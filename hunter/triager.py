"""
LLM triager: classify Semgrep candidates as real/likely_fp/needs_more_context
via structured Anthropic API calls with forced tool use.
"""
import asyncio
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import anthropic
import click

from hunter.db import get_conn

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_PROMPTS_DIR = Path(__file__).parent / "prompts"

# Cheap-first cascade: Haiku is the default, Sonnet is the escalation target.
# Escalation is triggered when:
#   - verdict == 'needs_more_context', OR
#   - verdict == 'real' AND confidence == 'low'
# Both paths re-run with Sonnet (carrying the Haiku reasoning forward as
# additional context) and the Sonnet verdict wins. Cost goes up only on the
# uncertain tail, which is where real CVEs hide anyway.
_MODEL_HAIKU  = "claude-haiku-4-5-20251001"
_MODEL_SONNET = "claude-sonnet-4-6"
_MODEL = _MODEL_HAIKU  # legacy alias for backward compat

# Pricing per million tokens, keyed by model id.
_PRICING: dict[str, tuple[float, float]] = {
    _MODEL_HAIKU:  (0.80,  4.00),   # $/Mtok (input, output)
    _MODEL_SONNET: (3.00, 15.00),
}
_INPUT_COST_PER_M  = _PRICING[_MODEL_HAIKU][0]  # legacy aliases — only Haiku
_OUTPUT_COST_PER_M = _PRICING[_MODEL_HAIKU][1]

_RULE_PROMPT: dict[str, str] = {
    "wp-sqli":                       "sqli",
    "wp-sqli-prepare-concat":        "sqli",
    "wp-reflected-xss":              "xss",
    "wp-reflected-xss-precise":      "xss",
    "wp-missing-nonce-check":        "csrf",
    "wp-nopriv-missing-nonce":       "csrf",
    "wp-missing-cap-check":          "cap-check",
    "wp-arbitrary-file-upload":      "file-upload",
    "wp-path-traversal":             "path-traversal",
    "wp-path-traversal-precise":     "path-traversal",
    "wp-php-object-injection":       "php-oi",
    "wp-php-object-injection-precise": "php-oi",
    "wp-ssrf":                       "ssrf",
    "wp-ssrf-precise":               "ssrf",
    "wp-stored-xss":                 "xss",
}

_TRIAGE_TOOL = {
    "name": "submit_triage",
    "description": (
        "Record your triage verdict for this specific Semgrep candidate. "
        "Call this tool exactly once after completing your analysis."
    ),
    "input_schema": {
        "type": "object",
        "required": ["verdict", "reachability", "reasoning", "suggested_poc_outline", "confidence"],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["real", "likely_fp", "needs_more_context", "real_but_not_cve_worthy"],
                "description": (
                    "'real': confirmed exploitable vulnerability that is CVE-eligible. "
                    "'likely_fp': false positive — not exploitable or not reachable. "
                    "'needs_more_context': cannot determine without seeing more code. "
                    "'real_but_not_cve_worthy': genuine vulnerability but entry point requires "
                    "admin/manage_options for a class (XSS, SQLi, RCE, file upload, SSRF) that "
                    "WordPress does not consider in-scope because admins already have those abilities. "
                    "Do NOT generate a PoC — log for human review only."
                ),
            },
            "reachability": {
                "type": "string",
                "enum": ["unauth", "subscriber", "admin", "unknown"],
                "description": (
                    "Minimum privilege needed to trigger the vulnerability. "
                    "'unauth': no authentication required. "
                    "'subscriber': any logged-in WordPress user. "
                    "'admin': requires administrator/manage_options capability. "
                    "'unknown': cannot determine from available context."
                ),
            },
            "reasoning": {
                "type": "string",
                "description": (
                    "Step-by-step analysis: taint source → propagation path → "
                    "sanitization present/absent → access control → verdict justification. "
                    "Be specific about line numbers and variable names."
                ),
            },
            "suggested_poc_outline": {
                "type": "string",
                "description": (
                    "For 'real' verdicts: concise exploit steps — HTTP method, endpoint, "
                    "required parameters/payloads, expected observable impact. "
                    "Empty string for 'likely_fp'."
                ),
            },
            "confidence": {
                "type": "string",
                "enum": ["high", "medium", "low"],
                "description": (
                    "Confidence in the verdict. 'high': clear evidence either way. "
                    "'medium': probable but some ambiguity. 'low': significant uncertainty."
                ),
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Prompt loading and rendering
# ---------------------------------------------------------------------------

def _load_prompt_template(rule_id: str) -> str:
    stem = _RULE_PROMPT.get(rule_id, "generic")
    path = _PROMPTS_DIR / f"{stem}.md"
    if not path.exists():
        path = _PROMPTS_DIR / "generic.md"
    return path.read_text(encoding="utf-8")


_CANDIDATE_MARKER = "\n\n## Flagged Candidate\n\n"


def _render(template: str, candidate: dict) -> tuple[str, str]:
    """
    Split template at '## Flagged Candidate' into (static_prefix, dynamic_block).

    The static_prefix (vuln explanation, reachability table, CVE eligibility) is
    marked with cache_control so the API caches it across candidates of the same
    rule type.  The dynamic_block contains the per-candidate code snippet and
    analysis instructions.

    When a taint_trace is available it is appended as a '## Taint Data Flow'
    section directly above the code snippet so the LLM sees source → sink
    before reading the full function body.
    """
    taint_trace = (candidate.get("taint_trace") or "").strip()
    taint_section = (
        f"\n\n### Semgrep Taint Data Flow\n\n"
        f"```\n{taint_trace}\n```\n"
        if taint_trace else ""
    )

    subs = {
        "__CODE_SNIPPET__": candidate.get("code_snippet") or "(snippet unavailable)",
        "__FILE_PATH__":    candidate.get("file_path") or "unknown",
        "__LINE_START__":   str(candidate.get("line_start") or "?"),
        "__LINE_END__":     str(candidate.get("line_end") or "?"),
        "__RULE_ID__":      candidate.get("rule_id") or "unknown",
        "__TAINT_TRACE__":  taint_section,
    }
    if _CANDIDATE_MARKER in template:
        static, tail = template.split(_CANDIDATE_MARKER, 1)
        for k, v in subs.items():
            tail = tail.replace(k, v)
        # Append taint section after the file/lines header if not already in template
        if taint_section and "__TAINT_TRACE__" not in template:
            # Insert before the code block
            tail = tail.replace("```php\n", taint_section + "```php\n", 1)
        return static.strip(), "## Flagged Candidate\n\n" + tail
    # Fallback for templates without the split marker — no caching
    full = template
    for k, v in subs.items():
        full = full.replace(k, v)
    return "", full


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------

def _compute_cost(input_tokens: int, output_tokens: int, model: str | None = None) -> float:
    """Cost in USD. *model* defaults to Haiku for backward compatibility."""
    in_rate, out_rate = _PRICING.get(model or _MODEL_HAIKU, _PRICING[_MODEL_HAIKU])
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000


def _spend_today(conn) -> float:
    today    = date.today().isoformat()
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    row = conn.execute(
        "SELECT COALESCE(SUM(cost_usd), 0) AS total FROM triage "
        "WHERE triaged_at >= ? AND triaged_at < ?",
        (today, tomorrow),
    ).fetchone()
    return float(row["total"])


def _daily_budget() -> float | None:
    val = os.environ.get("HUNTER_DAILY_BUDGET_USD")
    return float(val) if val else None


# ---------------------------------------------------------------------------
# API interaction
# ---------------------------------------------------------------------------

def _extract_tool_input(response) -> dict | None:
    for block in response.content:
        if (getattr(block, "type", None) == "tool_use"
                and getattr(block, "name", None) == "submit_triage"):
            return block.input
    return None


def _call_api(
    client,
    static: str,
    dynamic: str,
    model: str = _MODEL_HAIKU,
) -> tuple[dict | None, int, int]:
    """
    Call *model* with forced tool use. Returns (tool_input, input_tokens, output_tokens).
    Retries once if the response contains no valid submit_triage block.

    When *static* is non-empty it is sent as the first content block with
    cache_control so the API caches it across calls for the same rule type.
    """
    content: str | list
    if static:
        content = [
            {"type": "text", "text": static, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": dynamic},
        ]
    else:
        content = dynamic

    kwargs = dict(
        model=model,
        max_tokens=1024,
        tools=[_TRIAGE_TOOL],
        tool_choice={"type": "tool", "name": "submit_triage"},
        messages=[{"role": "user", "content": content}],
    )

    resp    = client.messages.create(**kwargs)
    in_tok  = resp.usage.input_tokens
    out_tok = resp.usage.output_tokens
    result  = _extract_tool_input(resp)

    if result is None:
        # One retry on malformed response
        resp    = client.messages.create(**kwargs)
        in_tok  += resp.usage.input_tokens
        out_tok += resp.usage.output_tokens
        result  = _extract_tool_input(resp)

    return result, in_tok, out_tok


def _should_escalate(verdict: str, confidence: str) -> bool:
    """Cheap-first cascade trigger. Escalate to Sonnet when:
      - the cheap model couldn't decide (needs_more_context), OR
      - it said 'real' with low confidence (the borderline tier where CVEs
        most often live and where false positives are most costly).

    `real` with high/medium confidence and `likely_fp` outcomes stay on Haiku.
    """
    if verdict == "needs_more_context":
        return True
    if verdict == "real" and confidence == "low":
        return True
    return False


def _dynamic_with_haiku_followup(dynamic: str, haiku_result: dict) -> str:
    """For an escalation triggered by 'needs_more_context', prepend Haiku's
    stated reasoning + information gap as a follow-up section so Sonnet can
    answer the specific question rather than re-deriving from scratch."""
    reasoning = (haiku_result.get("reasoning") or "").strip()
    if not reasoning:
        return dynamic
    section = (
        "### Cheap-tier triager (Haiku) output\n\n"
        "Haiku returned `needs_more_context` (or `real`/low-confidence) on this "
        "candidate. Its reasoning is reproduced verbatim below. Use it as a "
        "starting point — verify, refine, or correct it, but do not duplicate "
        "the same analysis.\n\n"
        f"```\n{reasoning[:4000]}\n```"
    )
    if _ANALYSIS_MARKER in dynamic:
        return dynamic.replace(_ANALYSIS_MARKER, f"\n\n{section}{_ANALYSIS_MARKER}", 1)
    return dynamic + f"\n\n{section}"


# ---------------------------------------------------------------------------
# Per-candidate triage
# ---------------------------------------------------------------------------

def _build_registration_context(candidate: dict, conn) -> str:
    """
    Return the AJAX/REST/admin-menu registration lines relevant to this candidate,
    or an empty string when the plugin source is unavailable.

    This gives the triager the hook registration needed to determine reachability
    (unauth / subscriber / admin) without reading the full plugin on every call.
    """
    from pathlib import Path
    from hunter.context import (
        _registrations_section,
        _read_lines,
        _enclosing_function_name,
    )

    slug = candidate.get("plugin_slug", "")
    row  = conn.execute(
        "SELECT source_path FROM plugins WHERE slug = ?", (slug,)
    ).fetchone()
    if not row or not row["source_path"]:
        return ""

    plugin_path = Path(row["source_path"])
    if not plugin_path.exists():
        return ""

    file_path  = candidate.get("file_path", "")
    line_start = int(candidate.get("line_start") or 1)
    cand_file  = plugin_path / file_path

    try:
        section = _registrations_section(plugin_path, cand_file, line_start)
    except Exception:
        return ""

    return section


_ANALYSIS_MARKER = "\n\n## Your Analysis\n"


def _insert_before_analysis(dynamic: str, section: str) -> str:
    """Insert *section* before the '## Your Analysis' marker, or append it."""
    if not section:
        return dynamic
    if _ANALYSIS_MARKER in dynamic:
        return dynamic.replace(_ANALYSIS_MARKER, f"\n\n{section}{_ANALYSIS_MARKER}", 1)
    return dynamic + f"\n\n{section}"


def _triage_one(candidate: dict, conn, client) -> str:
    """Triage a single candidate. Returns verdict string or 'error'."""
    from hunter.call_resolver import (
        build_callees_section_for_candidate,
        build_callers_section_for_candidate,
    )

    cid     = candidate["id"]
    rule_id = candidate.get("rule_id") or ""

    template        = _load_prompt_template(rule_id)
    static, dynamic = _render(template, candidate)

    # Insert registration context BEFORE the "## Your Analysis" instructions.
    dynamic = _insert_before_analysis(dynamic, _build_registration_context(candidate, conn))

    # Backward caller-following: who invokes the flagged function? Pulls in
    # callers' bodies so the triager can see whether tainted input flows into
    # the parameter that reaches the sink.
    dynamic = _insert_before_analysis(
        dynamic, build_callers_section_for_candidate(candidate, conn)
    )

    # Forward callee-following (multi-hop): user-defined functions called from
    # inside the flagged body, recursed up to max_depth so sanitizers behind
    # wrapper chains are visible.
    dynamic = _insert_before_analysis(
        dynamic, build_callees_section_for_candidate(candidate, conn)
    )

    now = datetime.now(timezone.utc).isoformat()

    # --- First pass: Haiku (cheap) ---
    try:
        haiku_result, h_in, h_out = _call_api(client, static, dynamic, model=_MODEL_HAIKU)
    except Exception as exc:
        click.echo(f"  [triage] #{cid}: API error — {exc}")
        conn.execute(
            """INSERT OR IGNORE INTO triage
                   (candidate_id, verdict, reachability, reasoning, poc_outline,
                    confidence, tokens_used, cost_usd, triaged_at, model_used)
               VALUES (?, 'error', 'unknown', ?, '', 'low', 0, 0.0, ?, ?)""",
            (cid, f"API error: {str(exc)[:200]}", now, _MODEL_HAIKU),
        )
        conn.commit()
        return "error"

    h_cost = _compute_cost(h_in, h_out, model=_MODEL_HAIKU)

    if haiku_result is None:
        click.echo(f"  [triage] #{cid}: malformed Haiku response after retry - skipping")
        # Intentionally do NOT write a triage row — the candidate stays
        # untriaged so a future run can retry it. (Pre-existing contract;
        # see test_both_malformed_responses_yield_error.)
        return "error"

    h_verdict    = haiku_result.get("verdict", "likely_fp")
    h_confidence = haiku_result.get("confidence", "low")

    # --- Cheap-first cascade: escalate to Sonnet on uncertainty ---
    final_result    = haiku_result
    final_in_tok    = h_in
    final_out_tok   = h_out
    final_cost      = h_cost
    final_model     = _MODEL_HAIKU
    escalated_from  = None

    if _should_escalate(h_verdict, h_confidence):
        # Carry Haiku's reasoning forward so Sonnet can build on (or correct) it
        # rather than re-deriving the analysis from scratch.
        sonnet_dynamic = _dynamic_with_haiku_followup(dynamic, haiku_result)
        try:
            sonnet_result, s_in, s_out = _call_api(
                client, static, sonnet_dynamic, model=_MODEL_SONNET
            )
        except Exception as exc:
            # Sonnet failure: keep Haiku's verdict, log the escalation attempt.
            click.echo(f"  [triage] #{cid}: Sonnet escalation failed ({exc}) — keeping Haiku verdict")
            sonnet_result = None
            s_in = s_out = 0

        if sonnet_result is not None:
            final_result   = sonnet_result
            final_in_tok   = h_in + s_in
            final_out_tok  = h_out + s_out
            final_cost     = h_cost + _compute_cost(s_in, s_out, model=_MODEL_SONNET)
            final_model    = _MODEL_SONNET
            escalated_from = _MODEL_HAIKU

    verdict      = final_result.get("verdict", "likely_fp")
    reachability = final_result.get("reachability", "unknown")
    reasoning    = final_result.get("reasoning", "")
    poc_outline  = final_result.get("suggested_poc_outline", "")
    confidence   = final_result.get("confidence", "low")

    conn.execute(
        """INSERT OR REPLACE INTO triage
               (candidate_id, verdict, reachability, reasoning, poc_outline,
                confidence, tokens_used, cost_usd, triaged_at,
                model_used, escalated_from)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (cid, verdict, reachability, reasoning, poc_outline,
         confidence, final_in_tok + final_out_tok, final_cost, now,
         final_model, escalated_from),
    )
    conn.commit()

    if verdict == "real":
        marker = "  *** REAL ***"
    elif verdict == "real_but_not_cve_worthy":
        marker = "  *** REAL (out-of-scope) — human review ***"
    else:
        marker = ""
    escal_tag = " (escalated->sonnet)" if escalated_from else ""
    click.echo(
        f"  [triage] #{cid} {rule_id} => {verdict} | "
        f"reach:{reachability} conf:{confidence} cost=${final_cost:.4f}{escal_tag}{marker}"
    )
    # Annotate the caller so they can bump the escalation counter
    if escalated_from:
        _ESCALATION_TRACKER.append(cid)
    return verdict


# Per-run tracker for escalation counts; reset by run_triage at start of each
# session. Kept as a module-level list (rather than a wrapped return value)
# so the _triage_one signature stays compatible with existing callers.
_ESCALATION_TRACKER: list[int] = []


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _check_spent(db_path: str | None) -> float:
    """Open a fresh conn, read today's spend, close. Designed to run inside
    asyncio.to_thread so the conn stays bound to the executor thread."""
    conn = get_conn(db_path)
    try:
        return _spend_today(conn)
    finally:
        conn.close()


def _default_concurrency() -> int:
    """Concurrency cap, from $HUNTER_TRIAGE_CONCURRENCY or 1 (serial)."""
    val = os.environ.get("HUNTER_TRIAGE_CONCURRENCY")
    try:
        n = int(val) if val else 1
    except ValueError:
        n = 1
    return max(1, min(20, n))


async def _run_triage_async(
    rows: list,
    db_path: str | None,
    client,
    concurrency: int,
    budget: float | None,
    spent_at_start: float,
) -> dict[str, int]:
    """Run _triage_one over *rows* with bounded concurrency.

    Each worker opens its OWN connection (WAL mode lets readers run in parallel
    and serializes writes safely). The Anthropic sync client is documented as
    thread-safe; asyncio.to_thread runs it on the default executor without
    blocking the event loop.

    Budget enforcement is best-effort across workers — a small overshoot is
    possible if many workers finish at once. Use HUNTER_DAILY_BUDGET_USD as a
    soft cap; tightening that to a hard cap would require a writer task.
    """
    sem    = asyncio.Semaphore(concurrency)
    counts = {"real": 0, "likely_fp": 0, "needs_more_context": 0,
              "real_but_not_cve_worthy": 0, "errors": 0}
    cancelled = asyncio.Event()

    def _triage_in_thread(row_dict: dict) -> str:
        """Run inside the executor thread: open conn IN this thread, run
        triage, close. SQLite connections are bound to the thread that
        created them — passing one in from the coroutine would raise
        sqlite3.ProgrammingError: 'objects created in a thread can only be
        used in that same thread'."""
        local_conn = get_conn(db_path)
        try:
            return _triage_one(row_dict, local_conn, client)
        finally:
            local_conn.close()

    async def worker(row) -> str:
        if cancelled.is_set():
            return "errors"
        async with sem:
            # Budget check happens before each worker grabs the semaphore —
            # so once we're spending past budget, queued workers bail out.
            if budget is not None:
                spent_now = await asyncio.to_thread(_check_spent, db_path)
                if spent_now >= budget:
                    cancelled.set()
                    return "errors"

            return await asyncio.to_thread(_triage_in_thread, dict(row))

    results = await asyncio.gather(*(worker(r) for r in rows), return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            counts["errors"] += 1
        else:
            counts[r if r in counts else "errors"] += 1
    if cancelled.is_set():
        click.echo("[triage] daily budget hit mid-run — remaining workers skipped")
    return counts


def run_triage(
    plugin_slug: str,
    db_path: str | None = None,
    client=None,
    concurrency: int | None = None,
) -> dict:
    """
    Triage all untriaged Semgrep candidates for *plugin_slug*.

    Returns summary dict: {total, real, likely_fp, needs_more_context, errors, cost_usd}.

    Parameters
    ----------
    concurrency : workers running in parallel. Defaults to
                  $HUNTER_TRIAGE_CONCURRENCY (1 = serial). With WAL journaling
                  and the thread-safe Anthropic sync client, values of 5-10
                  give large wall-clock wins on big scans.
    """
    conn   = get_conn(db_path)
    budget = _daily_budget()
    spent  = _spend_today(conn)

    if budget is not None:
        remaining = budget - spent
        click.echo(
            f"[triage] budget=${budget:.2f} | spent today=${spent:.4f} | "
            f"remaining=${remaining:.4f}"
        )
        if remaining <= 0:
            click.echo("[triage] daily budget exhausted — halting")
            return {"total": 0, "real": 0, "likely_fp": 0,
                    "needs_more_context": 0, "real_but_not_cve_worthy": 0,
                    "errors": 0, "cost_usd": 0.0}
    else:
        click.echo("[triage] no daily budget cap (set HUNTER_DAILY_BUDGET_USD to enable)")

    rows = conn.execute(
        """SELECT c.* FROM candidates c
           LEFT JOIN triage t ON t.candidate_id = c.id
           WHERE c.plugin_slug = ? AND t.candidate_id IS NULL
           ORDER BY c.semgrep_severity DESC, c.id ASC""",
        (plugin_slug,),
    ).fetchall()

    if not rows:
        click.echo(f"[triage] no untriaged candidates for {plugin_slug}")
        return {"total": 0, "real": 0, "likely_fp": 0,
                "needs_more_context": 0, "real_but_not_cve_worthy": 0,
                "errors": 0, "cost_usd": 0.0}

    click.echo(f"[triage] {len(rows)} untriaged candidates for {plugin_slug}")

    if client is None:
        client = anthropic.Anthropic()

    counts: dict[str, int] = {"real": 0, "likely_fp": 0, "needs_more_context": 0, "real_but_not_cve_worthy": 0, "errors": 0}

    conc = concurrency if concurrency is not None else _default_concurrency()
    if conc > 1:
        click.echo(f"[triage] running with concurrency={conc}")

    from hunter.runs import Run
    _ESCALATION_TRACKER.clear()
    with Run("triage", plugin_slug=plugin_slug, notes=f"concurrency={conc}",
             db_path=db_path) as triage_run:
        if conc > 1:
            counts = asyncio.run(
                _run_triage_async(rows, db_path, client, conc, budget, spent)
            )
        else:
            for row in rows:
                if budget is not None and _spend_today(conn) >= budget:
                    click.echo("[triage] daily budget hit mid-run — stopping")
                    break
                result = _triage_one(dict(row), conn, client)
                counts[result if result in counts else "errors"] += 1
        triage_run.bump("llm_real", counts["real"])
        triage_run.bump("llm_fp", counts["likely_fp"] + counts["real_but_not_cve_worthy"])
        triage_run.bump("llm_needs_context", counts["needs_more_context"])
        triage_run.bump("llm_escalated", len(_ESCALATION_TRACKER))
        triage_run.bump("cost_usd", _spend_today(conn) - spent)

    session_cost = _spend_today(conn) - spent
    summary = {"total": sum(counts.values()), **counts, "cost_usd": session_cost}
    click.echo(
        f"[triage] complete: {summary['total']} triaged | "
        f"real={summary['real']} oos={summary['real_but_not_cve_worthy']} "
        f"fp={summary['likely_fp']} unclear={summary['needs_more_context']} "
        f"err={summary['errors']} | session cost=${summary['cost_usd']:.4f}"
    )
    return summary
