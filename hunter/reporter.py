"""
Reporter: generate a Patchstack-format vulnerability disclosure document
for a confirmed finding.
"""
import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import click

from hunter.db import get_conn

REPORTS_DIR = Path(__file__).parent.parent / "reports"

_RULE_TO_TYPE = {
    "wp-sqli":                       "SQL Injection",
    "wp-sqli-prepare-concat":        "SQL Injection",
    "wp-reflected-xss":              "Reflected Cross-Site Scripting (XSS)",
    "wp-reflected-xss-precise":      "Reflected Cross-Site Scripting (XSS)",
    "wp-stored-xss":                 "Stored Cross-Site Scripting (XSS)",
    "wp-missing-nonce-check":        "Cross-Site Request Forgery (CSRF)",
    "wp-nopriv-missing-nonce":       "Cross-Site Request Forgery (CSRF) / Missing Authentication",
    "wp-missing-cap-check":          "Broken Access Control",
    "wp-arbitrary-file-upload":      "Arbitrary File Upload",
    "wp-path-traversal":             "Path Traversal",
    "wp-path-traversal-precise":     "Path Traversal",
    "wp-php-object-injection":       "PHP Object Injection",
    "wp-php-object-injection-precise": "PHP Object Injection",
    "wp-ssrf":                       "Server-Side Request Forgery (SSRF)",
    "wp-ssrf-precise":               "Server-Side Request Forgery (SSRF)",
}

# CVSS per rule × reachability  (score, vector)
# Reachability keys: "unauth", "subscriber", "admin"
_CVSS_TABLE: dict[str, dict[str, tuple[str, str]]] = {
    "wp-sqli": {
        "unauth":     ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "subscriber": ("8.8", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
        "admin":      ("7.2", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),
    },
    "wp-reflected-xss": {
        "unauth":     ("6.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        "subscriber": ("5.4", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
        "admin":      ("4.8", "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N"),
    },
    "wp-stored-xss": {
        "unauth":     ("7.2", "CVSS:3.1/AV:N/AC:L/PR:N/UI:C/S:C/C:L/I:L/A:N"),
        "subscriber": ("5.4", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
        "admin":      ("4.8", "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N"),
    },
    "wp-missing-nonce-check": {
        "unauth":     ("6.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"),
        "subscriber": ("5.4", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L"),
        "admin":      ("4.3", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L"),
    },
    "wp-nopriv-missing-nonce": {
        "unauth":     ("6.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"),
        "subscriber": ("5.4", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L"),
        "admin":      ("4.3", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L"),
    },
    "wp-missing-cap-check": {
        "unauth":     ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "subscriber": ("6.5", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
        "admin":      ("4.9", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N"),
    },
    "wp-arbitrary-file-upload": {
        "unauth":     ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "subscriber": ("8.8", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
        "admin":      ("7.2", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),
    },
    "wp-path-traversal": {
        "unauth":     ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "subscriber": ("6.5", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
        "admin":      ("4.9", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N"),
    },
    "wp-php-object-injection": {
        "unauth":     ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "subscriber": ("8.8", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
        "admin":      ("7.2", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),
    },
    "wp-ssrf": {
        "unauth":     ("8.6", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
        "subscriber": ("6.5", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
        "admin":      ("4.9", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N"),
    },
}

# Aliases for "precise"-suffixed rule IDs
for _alias, _base in [
    ("wp-sqli-prepare-concat",        "wp-sqli"),
    ("wp-reflected-xss-precise",      "wp-reflected-xss"),
    ("wp-path-traversal-precise",     "wp-path-traversal"),
    ("wp-php-object-injection-precise", "wp-php-object-injection"),
    ("wp-ssrf-precise",               "wp-ssrf"),
]:
    _CVSS_TABLE[_alias] = _CVSS_TABLE[_base]


def _get_cvss(rule_id: str, reachability: str) -> tuple[str, str]:
    rule_table = _CVSS_TABLE.get(rule_id, {})
    reach = (reachability or "unknown").lower()
    if reach in ("unauth", "unauthenticated"):
        key = "unauth"
    elif reach in ("subscriber", "contributor", "editor"):
        key = "subscriber"
    elif reach == "admin":
        key = "admin"
    else:
        key = "subscriber"
    return rule_table.get(key, ("N/A", "N/A"))


_REACH_TO_ROLE = {
    "unauth":          "Unauthenticated",
    "unauthenticated": "Unauthenticated",
    "subscriber":      "Subscriber+",
    "contributor":     "Contributor+",
    "author":          "Author+",
    "editor":          "Editor+",
    "admin":           "Administrator",
    "unknown":         "Unknown (see analysis)",
}

_RULE_TO_REMEDIATION = {
    "wp-sqli": (
        "Use `$wpdb->prepare()` with `%s` / `%d` placeholders for all query parameters. "
        "Never concatenate user input directly into SQL strings. "
        "For integer inputs, cast with `intval()` or `absint()` before use."
    ),
    "wp-sqli-prepare-concat": (
        "Remove string concatenation from the first argument of `$wpdb->prepare()`. "
        "Use `%s` / `%d` / `%f` placeholders and pass user input as separate arguments. "
        "The format string must be a literal or a fully server-controlled string."
    ),
    "wp-reflected-xss": (
        "Escape all output using the correct context function: "
        "`esc_html()` for plain text, `esc_attr()` for HTML attributes, "
        "`esc_url()` for URLs, `esc_js()` for inline JavaScript. "
        "Never echo user input without escaping."
    ),
    "wp-stored-xss": (
        "Escape all database-retrieved values at the point of output using the correct "
        "context function: `esc_html()` for plain text, `esc_attr()` for HTML attributes, "
        "`esc_url()` for URLs. Sanitization at input time does not replace escaping at output time."
    ),
    "wp-missing-nonce-check": (
        "Add `check_ajax_referer('your-action', 'nonce_field')` or "
        "`wp_verify_nonce( $_POST['_wpnonce'], 'your-action' )` before processing "
        "any state-mutating operation. Verify the nonce is tied to a specific action string."
    ),
    "wp-nopriv-missing-nonce": (
        "For unauthenticated endpoints that must remain public, add rate limiting and "
        "validate all inputs strictly. If the endpoint mutates state, require a nonce "
        "issued to the session (`wp_create_nonce()`). If authentication is needed, "
        "use `is_user_logged_in()` to gate the handler."
    ),
    "wp-missing-cap-check": (
        "Add `if ( ! current_user_can( 'capability_name' ) ) { wp_die( -1 ); }` "
        "before any privileged operation. Choose the minimum capability required "
        "(e.g. `edit_posts` for contributor-level, `manage_options` for admin-only)."
    ),
    "wp-arbitrary-file-upload": (
        "Validate the uploaded file's MIME type using `wp_check_filetype_and_ext()` "
        "against a strict allowlist. Store uploaded files outside the web root or "
        "use `wp_handle_upload()` which enforces WordPress's built-in restrictions."
    ),
    "wp-path-traversal": (
        "Resolve the user-supplied path with `realpath()` and confirm it starts with "
        "the expected base directory. Use `validate_file()` to reject `..` sequences. "
        "Alternatively, use `basename()` to strip directory components and only allow "
        "filenames, not paths."
    ),
    "wp-php-object-injection": (
        "Never call `unserialize()` on user-controlled data. Use `json_decode()` "
        "instead for structured data. If deserialization is unavoidable, implement "
        "a strict allowlist of expected classes using the `allowed_classes` parameter "
        "of `unserialize()`."
    ),
    "wp-ssrf": (
        "Validate the user-supplied URL against an explicit allowlist of trusted "
        "hostnames before issuing the request. Do not rely on `filter_var(FILTER_VALIDATE_URL)` "
        "— it does not block internal IPs or cloud metadata endpoints (169.254.x.x). "
        "Use `wp_http_validate_url()` and additionally block link-local ranges."
    ),
}

# Aliases
for _alias, _base in [
    ("wp-reflected-xss-precise",      "wp-reflected-xss"),
    ("wp-path-traversal-precise",     "wp-path-traversal"),
    ("wp-php-object-injection-precise", "wp-php-object-injection"),
    ("wp-ssrf-precise",               "wp-ssrf"),
]:
    _RULE_TO_REMEDIATION[_alias] = _RULE_TO_REMEDIATION[_base]

_RULE_TO_IMPACT = {
    "wp-sqli": (
        "exfiltrate arbitrary data from the WordPress database (user credentials, "
        "private posts, payment records), modify or delete database records, and "
        "in some configurations execute OS commands via `INTO OUTFILE`"
    ),
    "wp-sqli-prepare-concat": (
        "exfiltrate arbitrary data from the WordPress database by injecting SQL into "
        "the format string of `$wpdb->prepare()`, bypassing its parameterisation"
    ),
    "wp-reflected-xss": (
        "inject arbitrary JavaScript that runs in the victim's browser session, "
        "steal authentication cookies or session tokens, redirect users to phishing "
        "pages, and perform actions on behalf of the victim including admin takeover"
    ),
    "wp-stored-xss": (
        "inject persistent JavaScript that executes in the browser of every user who "
        "views the affected content, enabling session hijacking, credential theft, "
        "and admin takeover without requiring ongoing attacker interaction"
    ),
    "wp-missing-nonce-check": (
        "perform state-mutating actions on behalf of any authenticated user who "
        "visits a malicious page, including modifying settings, deleting content, "
        "or escalating privileges"
    ),
    "wp-nopriv-missing-nonce": (
        "trigger server-side state changes without any authentication, including "
        "modifying plugin settings, injecting data, or abusing server resources"
    ),
    "wp-missing-cap-check": (
        "access or modify privileged data or functionality without holding the "
        "required WordPress capability, effectively bypassing the role-based "
        "access control model"
    ),
    "wp-arbitrary-file-upload": (
        "upload a PHP webshell disguised as an image or document, achieving "
        "Remote Code Execution (RCE) on the server with web-server-process privileges"
    ),
    "wp-path-traversal": (
        "read arbitrary files on the server (e.g. `/etc/passwd`, configuration files, "
        "private keys) or delete files outside the intended directory"
    ),
    "wp-php-object-injection": (
        "exploit PHP magic methods (`__destruct`, `__wakeup`) in loaded classes to "
        "achieve Remote Code Execution, arbitrary file write/delete, or SQL injection "
        "depending on available gadget chains in the application"
    ),
    "wp-ssrf": (
        "use the WordPress server as an HTTP proxy to reach internal services, "
        "cloud metadata endpoints (AWS IMDS at 169.254.169.254), or other hosts "
        "not directly accessible from the internet, potentially exfiltrating "
        "cloud credentials or internal API secrets"
    ),
}

for _alias, _base in [
    ("wp-reflected-xss-precise",      "wp-reflected-xss"),
    ("wp-path-traversal-precise",     "wp-path-traversal"),
    ("wp-php-object-injection-precise", "wp-php-object-injection"),
    ("wp-ssrf-precise",               "wp-ssrf"),
]:
    _RULE_TO_IMPACT[_alias] = _RULE_TO_IMPACT[_base]

_CWE_MAP = {
    "wp-sqli":                       "89",
    "wp-sqli-prepare-concat":        "89",
    "wp-reflected-xss":              "79",
    "wp-reflected-xss-precise":      "79",
    "wp-stored-xss":                 "79",
    "wp-missing-nonce-check":        "352",
    "wp-nopriv-missing-nonce":       "352",
    "wp-missing-cap-check":          "862",
    "wp-arbitrary-file-upload":      "434",
    "wp-path-traversal":             "22",
    "wp-path-traversal-precise":     "22",
    "wp-php-object-injection":       "502",
    "wp-php-object-injection-precise": "502",
    "wp-ssrf":                       "918",
    "wp-ssrf-precise":               "918",
}


def _slug_to_title(slug: str) -> str:
    return slug.replace("-", " ").title()


def _clean_html(s: str) -> str:
    return re.sub(r"&(?:amp|lt|gt|quot|#\d+);", lambda m: {
        "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"'
    }.get(m.group(0), m.group(0)), s)


def _format_body_params(body_json: str) -> str:
    try:
        params = json.loads(body_json)
        return "\n".join(f"    {k}={v}" for k, v in params.items())
    except Exception:
        return body_json or ""


def _first_sentences(text: str, n: int = 3) -> str:
    cleaned = re.sub(r"^#{1,6}\s+.*$", "", text, flags=re.MULTILINE)
    cleaned = re.sub(r"\*\*[^*]+\*\*\s*\n", "", cleaned)
    cleaned = re.sub(r"\n{2,}", " ", cleaned).strip()
    sentences = re.split(r"(?<=[.!?])\s+", cleaned)
    sentences = [s.strip() for s in sentences if s.strip()]
    return " ".join(sentences[:n])


def run_report(candidate_id: int, db_path: str | None = None) -> None:
    conn = get_conn(db_path)

    row = conn.execute("""
        SELECT c.id, c.plugin_slug, c.rule_id, c.file_path, c.line_start, c.line_end,
               c.code_snippet,
               t.verdict, t.reachability, t.reasoning, t.poc_outline, t.confidence AS t_conf,
               p.http_method, p.url_path, p.headers, p.body_params,
               p.expected_signature, p.signature_type, p.confidence AS p_conf, p.status,
               v.status AS v_status, v.side_effects, v.verified_at,
               pl.name, pl.version, pl.active_installs
        FROM candidates c
        JOIN triage t ON t.candidate_id = c.id
        LEFT JOIN pocs p ON p.candidate_id = c.id
        LEFT JOIN verifications v ON v.candidate_id = c.id
        JOIN plugins pl ON pl.slug = c.plugin_slug
        WHERE c.id = ?
    """, (candidate_id,)).fetchone()

    if not row:
        click.echo(f"[reporter] candidate {candidate_id} not found")
        return

    (cid, slug, rule_id, file_path, line_start, line_end, code_snippet,
     verdict, reachability, reasoning, poc_outline, t_conf,
     http_method, url_path, headers_json, body_json,
     expected_sig, sig_type, p_conf, poc_status,
     v_status, side_effects, verified_at,
     plugin_name, version, installs) = row

    plugin_name_clean = _clean_html(plugin_name or _slug_to_title(slug))
    vuln_type         = _RULE_TO_TYPE.get(rule_id, rule_id)
    cvss_score, cvss_vector = _get_cvss(rule_id, reachability)
    role              = _reach_label(reachability)
    cwe_id            = _CWE_MAP.get(rule_id, "???")
    cwe_url           = (f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                         if cwe_id != "???" else "https://cwe.mitre.org/")
    wp_url            = f"https://wordpress.org/plugins/{slug}/"
    today             = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    verified_str      = "Yes — sandbox-confirmed" if v_status == "confirmed" else "No"

    headers: dict = {}
    try:
        headers = json.loads(headers_json or "{}")
    except Exception:
        pass

    curl_parts = [f"curl -s -X {http_method or 'POST'} 'https://TARGET{url_path or '/wp-admin/admin-ajax.php'}'"]
    for k, v in headers.items():
        if "Cookie" not in k:
            curl_parts.append(f"  -H '{k}: {v}'")
    auth_header = "unauthenticated" if (reachability or "").lower() in ("unauth", "unauthenticated") else f"{role.lower()} session cookie"
    curl_parts.append(f"  -H 'Cookie: <{auth_header}>'")
    if body_json:
        try:
            params = json.loads(body_json)
            data_str = "&".join(f"{k}={v}" for k, v in params.items())
            curl_parts.append(f"  --data '{data_str}'")
        except Exception:
            curl_parts.append(f"  -d '{body_json}'")
    curl_cmd = " \\\n".join(curl_parts)

    if reasoning:
        summary_body = _first_sentences(reasoning, 4)
    else:
        summary_body = (
            f"The `{slug}` plugin (v{version}) contains a **{vuln_type}** vulnerability "
            f"at `{file_path}` (line {line_start}). "
            f"The minimum required access level to exploit this vulnerability is **{role}**."
        )

    technical_details = reasoning or "(See vulnerable code above.)"
    poc_steps = poc_outline or "(No automated PoC outline available — see curl command below.)"

    if v_status == "confirmed" and side_effects:
        sandbox_result = side_effects
    elif v_status == "confirmed":
        sandbox_result = "Vulnerability confirmed in sandbox environment."
    else:
        sandbox_result = "Not sandbox-verified — manual testing recommended."

    if code_snippet:
        snippet_lines = code_snippet.splitlines()
        if len(snippet_lines) > 60:
            snippet_lines = snippet_lines[:60] + ["    // ... [truncated]"]
        snippet_block = "\n".join(snippet_lines)
    else:
        snippet_block = "(snippet unavailable)"

    impact_action = _RULE_TO_IMPACT.get(rule_id, "perform unauthorized actions")
    remediation   = _RULE_TO_REMEDIATION.get(rule_id, "Apply input validation and access control as appropriate.")

    report = f"""# Vulnerability Report — {plugin_name_clean}

**Date:** {today}
**Plugin:** [{plugin_name_clean}]({wp_url})
**Slug:** `{slug}`
**Affected Version:** ≤ {version} (tested)
**Active Installations:** {installs:,}+
**Vulnerability Type:** {vuln_type}
**CVSSv3 Score:** {cvss_score}
**CVSSv3 Vector:** `{cvss_vector}`
**Required Authentication:** {role}
**Sandbox Verified:** {verified_str}

---

## Summary

{summary_body}

---

## Technical Details

**Vulnerable file:** `{file_path}`
**Flagged line:** {line_start}–{line_end}

### Vulnerable Code

```php
{snippet_block}
```

### Analysis

{technical_details}

---

## Proof of Concept

{poc_steps}

### Exploit Request

```bash
{curl_cmd}
```

### Expected Observable Impact

{expected_sig or "(see analysis above)"}

### Sandbox Verification

{sandbox_result}

---

## Impact

An attacker with **{role}** access can {impact_action}.

---

## Remediation

{remediation}

---

## Timeline

| Date | Event |
|---|---|
| {today} | Vulnerability discovered and reported |

---

## References

- [{plugin_name_clean} — WordPress.org]({wp_url})
- [CWE-{cwe_id}]({cwe_url})
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
"""

    REPORTS_DIR.mkdir(exist_ok=True)
    out_path = REPORTS_DIR / f"{slug}__{cid}__{rule_id}.md"
    out_path.write_text(report, encoding="utf-8")
    click.echo(f"[reporter] report written to {out_path}")
    click.echo(f"[reporter] {vuln_type} | {slug} v{version} | CVSS {cvss_score} | {role}")


def _reach_label(reachability: str | None) -> str:
    if not reachability:
        return "Unknown"
    key = (reachability or "").lower().strip()
    return _REACH_TO_ROLE.get(key, reachability.title())
