"""
Verify Anthropic prompt caching is active in poc_generator and triager.

Makes two API calls per module using real templates and two different
BookingPress SQLi snippets.  Inspects usage.cache_creation_input_tokens
(call 1) and usage.cache_read_input_tokens (call 2) to confirm caching.

Run from the project root:
    python scripts/verify_prompt_caching.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load .env so ANTHROPIC_API_KEY is available
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

import anthropic
from hunter.poc_generator import _POC_TOOL, _load_template as _poc_template
from hunter.triager import _TRIAGE_TOOL, _load_prompt_template, _render

# ---------------------------------------------------------------------------
# Candidate snippets from bookingpress-appointment-booking 1.0.10
# ---------------------------------------------------------------------------

BP_SNIPPET_1 = """\
$total_service = $wpdb->get_var(
    "SELECT count(*) FROM {$wpdb->prefix}bookingpress_servicesmeta "
    . "WHERE bookingpress_service_id IN (" . $_POST['service'] . ")"
);
"""

BP_SNIPPET_2 = """\
$results = $wpdb->get_results(
    "SELECT * FROM {$wpdb->prefix}bookingpress_appointment_bookings "
    . "WHERE bookingpress_service_id = " . $_REQUEST['step_id']
);
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_usage(usage) -> str:
    created = getattr(usage, "cache_creation_input_tokens", None)
    read    = getattr(usage, "cache_read_input_tokens", None)
    return (
        f"  input={usage.input_tokens} output={usage.output_tokens} "
        f"cache_created={created!r} cache_read={read!r}"
    )


def _check(label: str, call1_usage, call2_usage) -> bool:
    created = getattr(call1_usage, "cache_creation_input_tokens", None) or 0
    read    = getattr(call2_usage, "cache_read_input_tokens", None) or 0
    ok = created > 0 and read > 0
    status = "PASS" if ok else "FAIL"
    print(f"\n{status}  [{label}]")
    print(f"  call 1: {_fmt_usage(call1_usage)}")
    print(f"  call 2: {_fmt_usage(call2_usage)}")
    if not ok:
        if created == 0:
            print("  => cache_creation_input_tokens=0 on call 1: cache_control marker not reaching API")
        if read == 0:
            print("  => cache_read_input_tokens=0 on call 2: cache miss (TTL too short, or marker missing)")
    return ok


# ---------------------------------------------------------------------------
# poc_generator verification
# ---------------------------------------------------------------------------

def verify_poc_caching(client: anthropic.Anthropic) -> bool:
    print("\n=== poc_generator (system message with cache_control) ===")
    template = _poc_template("wp-sqli")

    def call(snippet: str, call_num: int):
        dynamic = (
            f"## Candidate to Exploit\n\n"
            f"**File:** `includes/class-bookingpress-appointment-booking.php`\n"
            f"**Lines:** {500 + call_num * 10}-{502 + call_num * 10}\n"
            f"**Rule:** `wp-sqli`\n\n"
            f"```php\n{snippet}\n```\n\n"
            f"## Triager Analysis\n\n"
            f"**Reachability:** unauth\n"
            f"**Reasoning:** nopriv AJAX handler, direct SQLi via _POST.\n"
            f"**Triager PoC outline:** POST admin-ajax.php with UNION SELECT.\n\n"
            f"Use the submit_poc tool."
        )
        print(f"  [poc call {call_num}] sending...", flush=True)
        return client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=256,
            system=[{"type": "text", "text": template,
                     "cache_control": {"type": "ephemeral"}}],
            tools=[_POC_TOOL],
            tool_choice={"type": "tool", "name": "submit_poc"},
            messages=[{"role": "user", "content": dynamic}],
        )

    r1 = call(BP_SNIPPET_1, 1)
    r2 = call(BP_SNIPPET_2, 2)
    return _check("poc_generator", r1.usage, r2.usage)


# ---------------------------------------------------------------------------
# triager verification
# ---------------------------------------------------------------------------

def verify_triager_caching(client: anthropic.Anthropic) -> bool:
    print("\n=== triager (multi-block user message with cache_control on static prefix) ===")
    template = _load_prompt_template("wp-sqli")

    def candidate(snippet: str, line_start: int) -> dict:
        return {
            "code_snippet": snippet,
            "file_path":   "includes/class-bookingpress-appointment-booking.php",
            "line_start":  line_start,
            "line_end":    line_start + 2,
            "rule_id":     "wp-sqli",
        }

    def call(cand: dict, call_num: int):
        static, dynamic = _render(template, cand)
        if not static:
            print("  WARN: no split marker found — static portion is empty, caching will not work")
        content: str | list
        if static:
            content = [
                {"type": "text", "text": static, "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": dynamic},
            ]
        else:
            content = dynamic
        print(f"  [triager call {call_num}] sending...", flush=True)
        return client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=256,
            tools=[_TRIAGE_TOOL],
            tool_choice={"type": "tool", "name": "submit_triage"},
            messages=[{"role": "user", "content": content}],
        )

    r1 = call(candidate(BP_SNIPPET_1, 514), 1)
    r2 = call(candidate(BP_SNIPPET_2, 892), 2)
    return _check("triager", r1.usage, r2.usage)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    client = anthropic.Anthropic()

    poc_ok     = verify_poc_caching(client)
    triager_ok = verify_triager_caching(client)

    print("\n" + "=" * 60)
    print(f"poc_generator caching: {'PASS' if poc_ok else 'FAIL'}")
    print(f"triager caching:       {'PASS' if triager_ok else 'FAIL'}")

    sys.exit(0 if (poc_ok and triager_ok) else 1)
