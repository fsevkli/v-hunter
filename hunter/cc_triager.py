"""
Claude Code subprocess triager.

Same prompt-building logic as `hunter.triager`, but instead of calling the
Anthropic API directly (billed per-token), it shells out to the local
`claude` CLI in headless mode (`claude -p ... --output-format json`).

Trade-offs vs the Haiku-API triager:
+ Zero marginal API cost (billed against the user's Claude Code subscription).
+ Uses whatever model the Claude Code session is configured for (likely Opus
  or Sonnet) — so triage quality is typically higher than Haiku.
- Slower per-candidate: each invocation spins up a fresh Claude Code session
  with no prompt-cache reuse across candidates.
- No structured tool-use; relies on prompting Claude to emit a fenced JSON
  block, which is parsed back out of the response.

The output schema matches the API triager's `submit_triage` tool input so the
same `triage` table rows are written and downstream consumers (PoC generator,
reporter, review queue) do not need to know which engine produced the verdict.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

import click

from hunter.db import get_conn
from hunter.triager import (
    _build_registration_context,
    _insert_before_analysis,
    _load_prompt_template,
    _render,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Per-candidate ceiling — analyzing a single function should never need this
# long; if it does, something is wrong (hung session, model loop).
_CLAUDE_TIMEOUT_SEC = int(os.environ.get("HUNTER_CC_TIMEOUT_SEC", "240"))

# Permission mode for headless runs. The triager only reads files in the
# plugin source tree; bypass keeps the subprocess from hanging on an approval
# prompt that nothing will answer.
_CLAUDE_PERMISSION_MODE = os.environ.get("HUNTER_CC_PERMISSION_MODE", "bypassPermissions")

# Resolve `claude` once per process — Windows PATH lookups are not free.
_CLAUDE_BIN: str | None = None

_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)
_JSON_OBJECT_RE = re.compile(r"\{[\s\S]*\}")  # last-resort: any JSON-looking object

_VALID_VERDICTS = {
    "real", "likely_fp", "needs_more_context", "real_but_not_cve_worthy",
}
_VALID_REACHABILITY = {"unauth", "subscriber", "admin", "unknown"}
_VALID_CONFIDENCE = {"high", "medium", "low"}


_RESPONSE_INSTRUCTIONS = """

## Required Output Format

After your analysis, output a **single fenced JSON code block** matching this
exact schema. Do not output anything after the closing ```:

```json
{
  "verdict": "real | likely_fp | needs_more_context | real_but_not_cve_worthy",
  "reachability": "unauth | subscriber | admin | unknown",
  "reasoning": "step-by-step analysis with line numbers and variable names",
  "suggested_poc_outline": "exploit steps for 'real' verdicts only, empty string otherwise",
  "confidence": "high | medium | low"
}
```

Verdict guidance:
- `real`: confirmed exploitable, CVE-eligible (unauth / subscriber / contributor / editor).
- `real_but_not_cve_worthy`: genuine bug but entry point requires admin (manage_options) — out of scope.
- `likely_fp`: not exploitable or not reachable.
- `needs_more_context`: cannot determine without seeing additional code paths.
"""


# ---------------------------------------------------------------------------
# Subprocess invocation
# ---------------------------------------------------------------------------

def _find_claude() -> str:
    """Resolve the `claude` binary path, cached for the process lifetime."""
    global _CLAUDE_BIN
    if _CLAUDE_BIN:
        return _CLAUDE_BIN
    import shutil
    found = shutil.which("claude")
    if found:
        _CLAUDE_BIN = found
        return found
    override = os.environ.get("HUNTER_CC_BIN")
    if override:
        _CLAUDE_BIN = override
        return override
    _CLAUDE_BIN = "claude"  # last resort; subprocess will surface a clear error
    return _CLAUDE_BIN


def _invoke_claude(prompt: str) -> tuple[dict | None, str]:
    """Run claude -p and return (parsed_triage_payload, error_message).

    On success: (dict, "").  On failure: (None, "reason string").
    """
    bin_path = _find_claude()
    cmd = [
        bin_path, "-p",
        "--output-format", "json",
        "--permission-mode", _CLAUDE_PERMISSION_MODE,
    ]
    try:
        result = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_CLAUDE_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return None, f"claude-code timeout after {_CLAUDE_TIMEOUT_SEC}s"
    except FileNotFoundError:
        return None, f"claude binary not found (tried {bin_path!r})"
    except Exception as exc:
        return None, f"subprocess error: {exc}"

    if result.returncode != 0:
        tail = (result.stderr or "")[-400:].strip()
        return None, f"claude exited rc={result.returncode}: {tail}"

    stdout = result.stdout or ""
    # The JSON output format wraps the assistant's response in an envelope.
    # Common shape: {"type": "result", "result": "<assistant text>", ...}
    response_text = stdout
    try:
        envelope = json.loads(stdout)
        if isinstance(envelope, dict):
            response_text = (
                envelope.get("result")
                or envelope.get("response")
                or envelope.get("text")
                or stdout
            )
    except json.JSONDecodeError:
        pass  # not a JSON envelope; treat raw stdout as the response

    if not isinstance(response_text, str):
        response_text = str(response_text)

    # Find a fenced ```json block first; fall back to any JSON object.
    payload_str = None
    m = _JSON_BLOCK_RE.search(response_text)
    if m:
        payload_str = m.group(1).strip()
    else:
        m2 = _JSON_OBJECT_RE.search(response_text)
        if m2:
            payload_str = m2.group(0).strip()

    if not payload_str:
        return None, f"no JSON in response (first 300 chars): {response_text[:300]!r}"

    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError as exc:
        return None, f"malformed JSON ({exc}): {payload_str[:300]!r}"

    if not isinstance(payload, dict):
        return None, f"JSON not an object: {type(payload).__name__}"

    return payload, ""


def _normalize(payload: dict) -> dict:
    """Clamp values to the allowed enums; fall back to safe defaults."""
    verdict = payload.get("verdict") or "likely_fp"
    if verdict not in _VALID_VERDICTS:
        verdict = "likely_fp"

    reachability = payload.get("reachability") or "unknown"
    if reachability not in _VALID_REACHABILITY:
        reachability = "unknown"

    confidence = payload.get("confidence") or "low"
    if confidence not in _VALID_CONFIDENCE:
        confidence = "low"

    return {
        "verdict": verdict,
        "reachability": reachability,
        "reasoning": str(payload.get("reasoning") or "")[:8000],
        "poc_outline": str(payload.get("suggested_poc_outline") or "")[:4000],
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Prompt build
# ---------------------------------------------------------------------------

def _build_prompt(candidate: dict, conn) -> str:
    """Build the full prompt string sent to `claude -p` over stdin."""
    from hunter.call_resolver import (
        build_callees_section_for_candidate,
        build_callers_section_for_candidate,
    )

    rule_id = candidate.get("rule_id") or ""
    template = _load_prompt_template(rule_id)
    static, dynamic = _render(template, candidate)

    # Insertion order matters: each _insert_before_analysis call pushes the
    # previous insertion further up. To get top-to-bottom order
    #   registrations -> callers -> callees -> Analysis marker
    # we insert in that same order, so callees ends up adjacent to the marker.
    dynamic = _insert_before_analysis(
        dynamic, _build_registration_context(candidate, conn)
    )
    dynamic = _insert_before_analysis(
        dynamic, build_callers_section_for_candidate(candidate, conn)
    )
    dynamic = _insert_before_analysis(
        dynamic, build_callees_section_for_candidate(candidate, conn)
    )

    body = (static + "\n\n" + dynamic) if static else dynamic
    return body + _RESPONSE_INSTRUCTIONS


# ---------------------------------------------------------------------------
# Per-candidate triage
# ---------------------------------------------------------------------------

def _record_error(conn, cid: int, reason: str, now: str) -> None:
    conn.execute(
        """INSERT OR IGNORE INTO triage
               (candidate_id, verdict, reachability, reasoning, poc_outline,
                confidence, tokens_used, cost_usd, triaged_at)
           VALUES (?, 'error', 'unknown', ?, '', 'low', 0, 0.0, ?)""",
        (cid, f"cc-triage error: {reason[:300]}", now),
    )
    conn.commit()


def _triage_one_cc(candidate: dict, conn) -> str:
    cid = candidate["id"]
    rule_id = candidate.get("rule_id") or ""
    now = datetime.now(timezone.utc).isoformat()

    prompt = _build_prompt(candidate, conn)

    payload, err = _invoke_claude(prompt)
    if payload is None:
        click.echo(f"  [cc-triage] #{cid}: {err}")
        _record_error(conn, cid, err, now)
        return "error"

    norm = _normalize(payload)

    conn.execute(
        """INSERT OR REPLACE INTO triage
               (candidate_id, verdict, reachability, reasoning, poc_outline,
                confidence, tokens_used, cost_usd, triaged_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, 0.0, ?)""",
        (cid, norm["verdict"], norm["reachability"], norm["reasoning"],
         norm["poc_outline"], norm["confidence"], now),
    )
    conn.commit()

    if norm["verdict"] == "real":
        marker = "  *** REAL ***"
    elif norm["verdict"] == "real_but_not_cve_worthy":
        marker = "  *** REAL (out-of-scope) — human review ***"
    else:
        marker = ""
    click.echo(
        f"  [cc-triage] #{cid} {rule_id} => {norm['verdict']} | "
        f"reach:{norm['reachability']} conf:{norm['confidence']}{marker}"
    )
    return norm["verdict"]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def _run_triage_cc_async(
    rows: list,
    db_path: str | None,
    concurrency: int,
) -> dict[str, int]:
    """Concurrent variant of the cc-triage loop.

    Each worker spawns its own `claude -p` subprocess via asyncio (no thread
    needed — subprocess I/O is native async) and uses its own SQLite
    connection (WAL mode permits concurrent reads + serialized writes).

    The Claude Code CLI has its own session/queue management; concurrency
    higher than ~3-4 doesn't help (and can actually hurt due to local rate
    limiting). Default to 3 unless overridden.
    """
    import asyncio
    sem = asyncio.Semaphore(concurrency)
    counts = {"real": 0, "likely_fp": 0, "needs_more_context": 0,
              "real_but_not_cve_worthy": 0, "errors": 0}

    def _triage_in_thread(row_dict: dict) -> str:
        """Open conn IN the executor thread (SQLite connections are
        thread-bound), run cc-triage, close. See triager.py for the same
        pattern and rationale."""
        local_conn = get_conn(db_path)
        try:
            return _triage_one_cc(row_dict, local_conn)
        finally:
            local_conn.close()

    async def worker(row) -> str:
        async with sem:
            return await asyncio.to_thread(_triage_in_thread, dict(row))

    results = await asyncio.gather(*(worker(r) for r in rows), return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            counts["errors"] += 1
        else:
            counts[r if r in counts else "errors"] += 1
    return counts


def _default_cc_concurrency() -> int:
    """Concurrency for cc-triage, from $HUNTER_CC_TRIAGE_CONCURRENCY or 1."""
    val = os.environ.get("HUNTER_CC_TRIAGE_CONCURRENCY")
    try:
        n = int(val) if val else 1
    except ValueError:
        n = 1
    # claude-code is locally rate-limited; keep modest defaults.
    return max(1, min(5, n))


def run_triage_cc(
    plugin_slug: str,
    db_path: str | None = None,
    concurrency: int | None = None,
) -> dict:
    """Triage all untriaged candidates for *plugin_slug* via claude-code.

    Parameters
    ----------
    concurrency : parallel `claude -p` subprocesses. Defaults to
                  $HUNTER_CC_TRIAGE_CONCURRENCY (1 = serial). 2-3 is usually
                  the sweet spot — claude-code has its own session/queue.
    """
    conn = get_conn(db_path)

    rows = conn.execute(
        """SELECT c.* FROM candidates c
           LEFT JOIN triage t ON t.candidate_id = c.id
           WHERE c.plugin_slug = ? AND t.candidate_id IS NULL
           ORDER BY c.semgrep_severity DESC, c.id ASC""",
        (plugin_slug,),
    ).fetchall()

    if not rows:
        click.echo(f"[cc-triage] no untriaged candidates for {plugin_slug}")
        return {"total": 0, "real": 0, "likely_fp": 0,
                "needs_more_context": 0, "real_but_not_cve_worthy": 0,
                "errors": 0, "cost_usd": 0.0}

    click.echo(
        f"[cc-triage] {len(rows)} untriaged candidates for {plugin_slug} "
        f"(engine=claude-code, $0 marginal cost)"
    )

    counts = {"real": 0, "likely_fp": 0, "needs_more_context": 0,
              "real_but_not_cve_worthy": 0, "errors": 0}

    conc = concurrency if concurrency is not None else _default_cc_concurrency()
    if conc > 1:
        click.echo(f"[cc-triage] running with concurrency={conc}")

    import asyncio
    from hunter.runs import Run
    with Run("triage", plugin_slug=plugin_slug,
             notes=f"engine=claude-code concurrency={conc}",
             db_path=db_path) as triage_run:
        if conc > 1:
            counts = asyncio.run(_run_triage_cc_async(rows, db_path, conc))
        else:
            for row in rows:
                result = _triage_one_cc(dict(row), conn)
                counts[result if result in counts else "errors"] += 1
        triage_run.bump("llm_real", counts["real"])
        triage_run.bump("llm_fp", counts["likely_fp"] + counts["real_but_not_cve_worthy"])
        triage_run.bump("llm_needs_context", counts["needs_more_context"])

    summary = {"total": sum(counts.values()), **counts, "cost_usd": 0.0}
    click.echo(
        f"[cc-triage] complete: {summary['total']} triaged | "
        f"real={summary['real']} oos={summary['real_but_not_cve_worthy']} "
        f"fp={summary['likely_fp']} unclear={summary['needs_more_context']} "
        f"err={summary['errors']}"
    )
    return summary
