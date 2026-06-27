"""
PoC generator: for each candidate with verdict='real', produce a concrete
machine-executable HTTP request specification for the sandbox verifier.

Candidates with verdict='real_but_not_cve_worthy', 'likely_fp',
'needs_more_context', or any error state are never processed.
"""
import json
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
_MODEL = "claude-sonnet-4-6"

_INPUT_COST_PER_M  = 3.00
_OUTPUT_COST_PER_M = 15.00

_RULE_PROMPT: dict[str, str] = {
    "wp-sqli":                         "poc_sqli",
    "wp-sqli-prepare-concat":          "poc_sqli",
    "wp-reflected-xss":                "poc_xss",
    "wp-reflected-xss-precise":        "poc_xss",
    "wp-stored-xss":                   "poc_xss",
    "wp-missing-nonce-check":          "poc_csrf",
    "wp-nopriv-missing-nonce":         "poc_csrf",
    "wp-missing-cap-check":            "poc_cap_check",
    "wp-arbitrary-file-upload":        "poc_file_upload",
    "wp-path-traversal":               "poc_path_traversal",
    "wp-path-traversal-precise":       "poc_path_traversal",
    "wp-php-object-injection":         "poc_php_oi",
    "wp-php-object-injection-precise": "poc_php_oi",
    "wp-ssrf":                         "poc_ssrf",
    "wp-ssrf-precise":                 "poc_ssrf",
}

# ---------------------------------------------------------------------------
# Tool schema
# ---------------------------------------------------------------------------

_POC_TOOL = {
    "name": "submit_poc",
    "description": (
        "Record the concrete HTTP request specification that will trigger this vulnerability. "
        "Call this tool exactly once. When the entry point, parameter names, or required state "
        "cannot be determined from the provided code, set unverifiable_reason to a non-empty "
        "string and leave the request fields empty — do NOT guess."
    ),
    "input_schema": {
        "type": "object",
        "required": ["confidence", "unverifiable_reason"],
        "properties": {
            "confidence": {
                "type": "string",
                "enum": ["high", "medium", "low"],
                "description": (
                    "Confidence that this PoC will trigger the vulnerability in a default "
                    "WordPress installation. 'high': entry point, parameters, and payload are "
                    "all visible in the code. 'medium': entry point known but some values inferred. "
                    "'low': set unverifiable_reason instead of filling the other fields."
                ),
            },
            "unverifiable_reason": {
                "type": "string",
                "description": (
                    "Non-empty only when the PoC is structurally incomplete: the AJAX action name, "
                    "parameter name, page slug, or route is not present anywhere in the provided code. "
                    "Do NOT set this because a nonce or cookie is required — use {NONCE:action_string} "
                    "and {COOKIE:role} placeholders instead; the verifier resolves them at runtime. "
                    "An empty string means all other required fields are complete and accurate."
                ),
            },
            "http_method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "description": "HTTP method for the exploit request.",
            },
            "url_path": {
                "type": "string",
                "description": (
                    "URL path relative to WP root, including query string for GET requests. "
                    "E.g. /wp-admin/admin-ajax.php?action=bookingpress_form "
                    "or /wp-json/plugin/v1/endpoint."
                ),
            },
            "headers": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": (
                    "Required HTTP headers. Use runtime-resolved placeholders: "
                    "{COOKIE:subscriber}, {COOKIE:contributor}, {COOKIE:editor}, {COOKIE:admin} "
                    "for auth cookies; {REST_NONCE} for the X-WP-Nonce REST API header. "
                    "Example: {'Cookie': 'wordpress_logged_in={COOKIE:subscriber}', "
                    "'Content-Type': 'application/x-www-form-urlencoded'}."
                ),
            },
            "body_params": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": (
                    "POST body parameters with concrete exploit payloads. "
                    "Use {NONCE:action_string} for nonce fields when the action string is visible "
                    "(e.g. _wpnonce={NONCE:bpa_wp_nonce}). "
                    "For SQLi: real UNION SELECT payload. For XSS: real <script> tag. "
                    "For GET requests, put parameters in url_path instead."
                ),
            },
            "expected_signature": {
                "type": "string",
                "description": (
                    "Value confirming exploitation, interpreted according to signature_type. "
                    "string_in_body: substring that must appear in the response body — for SQLi credential "
                    "leak use '$P$B' (WP password hash prefix); for XSS use the exact reflected payload. "
                    "status_code: the expected HTTP status as a string, e.g. '302'. "
                    "elapsed_gt: the minimum elapsed time in seconds as a string, e.g. '3' — pair with "
                    "a SLEEP(N) payload where N matches this threshold. "
                    "Must be specific — 'success' alone is not acceptable."
                ),
            },
            "signature_type": {
                "type": "string",
                "enum": ["string_in_body", "status_code", "elapsed_gt", "db_row", "file_exists"],
                "description": (
                    "How the sandbox verifies exploitation: "
                    "'string_in_body' (substring in HTTP response body), "
                    "'status_code' (specific HTTP status code — expected_signature is the code as a string), "
                    "'elapsed_gt' (response took longer than N seconds — use for blind SQLi/SSRF with SLEEP payloads; "
                    "expected_signature is the threshold in seconds as a string, e.g. '3'), "
                    "'db_row' (row written to DB after request), "
                    "'file_exists' (file on disk)."
                ),
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Prompt loading
# ---------------------------------------------------------------------------

def _load_template(rule_id: str) -> str:
    stem = _RULE_PROMPT.get(rule_id, "poc_generic")
    path = _PROMPTS_DIR / f"{stem}.md"
    if not path.exists():
        path = _PROMPTS_DIR / "poc_generic.md"
    return path.read_text(encoding="utf-8")


def _build_dynamic(
    candidate: dict,
    triage_row: dict,
    expanded_context: str | None = None,
) -> str:
    if expanded_context:
        code_block = expanded_context
    else:
        snippet = candidate.get("code_snippet", "(snippet unavailable)")
        code_block = f"```php\n{snippet}\n```"

    return (
        f"## Candidate to Exploit\n\n"
        f"**File:** `{candidate.get('file_path', 'unknown')}`\n"
        f"**Lines:** {candidate.get('line_start', '?')}-{candidate.get('line_end', '?')}\n"
        f"**Rule:** `{candidate.get('rule_id', 'unknown')}`\n\n"
        f"{code_block}\n\n"
        f"## Triager Analysis\n\n"
        f"**Reachability:** {triage_row.get('reachability', 'unknown')}\n"
        f"**Reasoning:** {triage_row.get('reasoning', '')}\n"
        f"**Triager PoC outline:** {triage_row.get('poc_outline', '')}\n\n"
        f"Use the `submit_poc` tool to record the exact exploit request. "
        f"If the entry point, parameter names, or required state cannot be determined "
        f"from the code above, set unverifiable_reason — do NOT guess."
    )


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------

def _compute_cost(input_tokens: int, output_tokens: int) -> float:
    return (input_tokens * _INPUT_COST_PER_M + output_tokens * _OUTPUT_COST_PER_M) / 1_000_000


def _spend_today(conn) -> float:
    today    = date.today().isoformat()
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    row = conn.execute(
        "SELECT COALESCE(SUM(cost_usd), 0) AS total FROM pocs "
        "WHERE generated_at >= ? AND generated_at < ?",
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
                and getattr(block, "name", None) == "submit_poc"):
            return block.input
    return None


def _call_api(client, template: str, dynamic: str) -> tuple[dict | None, int, int]:
    """
    Call the API with forced tool use. Static template is the system message with
    cache_control so the API caches it across candidates of the same rule type;
    dynamic candidate data goes in the user message. Retries once on malformed response.
    """
    kwargs = dict(
        model=_MODEL,
        max_tokens=1024,
        system=[{"type": "text", "text": template, "cache_control": {"type": "ephemeral"}}],
        tools=[_POC_TOOL],
        tool_choice={"type": "tool", "name": "submit_poc"},
        messages=[{"role": "user", "content": dynamic}],
    )

    resp    = client.messages.create(**kwargs)
    in_tok  = resp.usage.input_tokens
    out_tok = resp.usage.output_tokens
    result  = _extract_tool_input(resp)

    if result is None:
        resp    = client.messages.create(**kwargs)
        in_tok  += resp.usage.input_tokens
        out_tok += resp.usage.output_tokens
        result  = _extract_tool_input(resp)

    return result, in_tok, out_tok


# ---------------------------------------------------------------------------
# Per-candidate PoC generation
# ---------------------------------------------------------------------------

def _poc_one(candidate: dict, triage_row: dict, conn, client) -> str:
    """Generate PoC for one candidate. Returns status string or 'error'."""
    cid       = candidate["id"]
    rule_id   = candidate.get("rule_id") or ""
    plugin_slug = candidate.get("plugin_slug") or ""

    # Build expanded context (enclosing function + registrations + nonce checks)
    expanded_context = None
    plugin_row = conn.execute(
        "SELECT source_path FROM plugins WHERE slug = ?", (plugin_slug,)
    ).fetchone()
    if plugin_row and plugin_row["source_path"]:
        try:
            from hunter.context import build_poc_context
            expanded_context = build_poc_context(plugin_row["source_path"], candidate)
        except Exception as exc:
            click.echo(f"  [poc] #{cid}: context expansion failed — {exc}")

    template = _load_template(rule_id)
    dynamic  = _build_dynamic(candidate, triage_row, expanded_context)

    try:
        tool_input, in_tok, out_tok = _call_api(client, template, dynamic)
    except Exception as exc:
        click.echo(f"  [poc] #{cid}: API error — {exc}")
        return "error"

    cost = _compute_cost(in_tok, out_tok)
    now  = datetime.now(timezone.utc).isoformat()

    if tool_input is None:
        click.echo(f"  [poc] #{cid}: malformed response after retry — skipping")
        return "error"

    confidence          = tool_input.get("confidence", "low")
    unverifiable_reason = tool_input.get("unverifiable_reason", "")

    if unverifiable_reason:
        status           = "unverifiable"
        http_method      = None
        url_path         = None
        headers_json     = None
        body_params_json = None
        expected_sig     = None
        sig_type         = None
    else:
        status           = "ready"
        http_method      = tool_input.get("http_method")
        url_path         = tool_input.get("url_path")
        headers_json     = json.dumps(tool_input.get("headers") or {})
        body_params_json = json.dumps(tool_input.get("body_params") or {})
        expected_sig     = tool_input.get("expected_signature")
        sig_type         = tool_input.get("signature_type")

    conn.execute(
        """INSERT OR REPLACE INTO pocs
               (candidate_id, status, http_method, url_path, headers, body_params,
                expected_signature, signature_type, confidence, unverifiable_reason,
                tokens_used, cost_usd, generated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (cid, status, http_method, url_path, headers_json, body_params_json,
         expected_sig, sig_type, confidence, unverifiable_reason,
         in_tok + out_tok, cost, now),
    )
    conn.commit()

    marker = " [UNVERIFIABLE]" if status == "unverifiable" else ""
    click.echo(
        f"  [poc] #{cid} {rule_id} => {status}{marker} | "
        f"conf:{confidence} cost=${cost:.4f}"
    )
    return status


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_poc(
    plugin_slug: str,
    db_path: str | None = None,
    client=None,
) -> dict:
    """
    Generate PoCs for all verdict='real' candidates for *plugin_slug* that do not
    already have a pocs entry.

    Candidates with any other verdict (real_but_not_cve_worthy, likely_fp,
    needs_more_context) are excluded by the query.

    Returns summary dict: {total, ready, unverifiable, errors, cost_usd}.
    """
    conn   = get_conn(db_path)
    budget = _daily_budget()
    spent  = _spend_today(conn)

    if budget is not None:
        remaining = budget - spent
        click.echo(
            f"[poc] budget=${budget:.2f} | spent today=${spent:.4f} | "
            f"remaining=${remaining:.4f}"
        )
        if remaining <= 0:
            click.echo("[poc] daily budget exhausted — halting")
            return {"total": 0, "ready": 0, "unverifiable": 0, "errors": 0, "cost_usd": 0.0}
    else:
        click.echo("[poc] no daily budget cap (set HUNTER_DAILY_BUDGET_USD to enable)")

    rows = conn.execute(
        """SELECT c.*, t.verdict, t.reachability, t.reasoning, t.poc_outline
           FROM candidates c
           JOIN triage t ON t.candidate_id = c.id
           LEFT JOIN pocs p ON p.candidate_id = c.id
           WHERE c.plugin_slug = ?
             AND t.verdict = 'real'
             AND p.candidate_id IS NULL
           ORDER BY c.semgrep_severity DESC, c.id ASC""",
        (plugin_slug,),
    ).fetchall()

    if not rows:
        click.echo(f"[poc] no candidates eligible for PoC generation for {plugin_slug}")
        return {"total": 0, "ready": 0, "unverifiable": 0, "errors": 0, "cost_usd": 0.0}

    click.echo(f"[poc] {len(rows)} candidate(s) for PoC generation ({plugin_slug})")

    if client is None:
        client = anthropic.Anthropic()

    counts: dict[str, int] = {"ready": 0, "unverifiable": 0, "errors": 0}

    for row in rows:
        if budget is not None and _spend_today(conn) >= budget:
            click.echo("[poc] daily budget hit mid-run — stopping")
            break

        candidate = dict(row)
        triage_row = {
            "verdict":     candidate.pop("verdict",     "real"),
            "reachability": candidate.pop("reachability", "unknown"),
            "reasoning":   candidate.pop("reasoning",   ""),
            "poc_outline": candidate.pop("poc_outline", ""),
        }

        result = _poc_one(candidate, triage_row, conn, client)
        counts[result if result in counts else "errors"] += 1

    session_cost = _spend_today(conn) - spent
    summary = {"total": sum(counts.values()), **counts, "cost_usd": session_cost}
    click.echo(
        f"[poc] complete: {summary['total']} processed | "
        f"ready={summary['ready']} unverifiable={summary['unverifiable']} "
        f"err={summary['errors']} | session cost=${summary['cost_usd']:.4f}"
    )
    return summary
