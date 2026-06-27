"""
Verifier: runs PoC HTTP requests in a Docker-sandboxed WordPress instance.

Phase 1: sandbox setup - start containers, install WordPress, create fixture
         users, resolve cookies via shim, list registered AJAX actions.
Phase 2: placeholder resolution, request execution, rejection detection,
         signature matching, verdict writing.
"""
import contextlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import click
import requests

from hunter.db import get_conn

_SANDBOX_DIR   = Path(__file__).parent.parent / "sandbox"
_COMPOSE_FILE  = _SANDBOX_DIR / "docker-compose.yml"
_SNAPSHOT_PATH = "/var/www/html/wp-content/wphunter_snapshot.sql"

_FIXTURE_ROLES     = ["subscriber", "contributor", "editor", "administrator"]
_WP_READY_TIMEOUT  = 120
_WP_READY_POLL     = 3
_REQUEST_TIMEOUT   = 15
_MAX_BODY          = 64 * 1024

_ALREADY_INSTALLED = ("already installed", "database already")
_USER_EXISTS       = ("already registered", "user_login_exists", "sorry, that username")

# Placeholder patterns
_COOKIE_RE     = re.compile(r'\{COOKIE:(\w+)\}')
_NONCE_RE      = re.compile(r'\{NONCE:([^}]+)\}')
_REST_NONCE_RE = re.compile(r'\{REST_NONCE\}')

# WP standard rejection patterns: (compiled_pattern, reason_label)
_REJECTION_CHECKS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'^\s*-1\s*$'),                                                "wp_auth_rejected"),
    (re.compile(r'^\s*0\s*$'),                                                  "wp_auth_rejected"),
    (re.compile(r'"success"\s*:\s*false.*?"data"\s*:\s*"-?\d+"', re.DOTALL),   "wp_auth_rejected"),
    (re.compile(r'You do not have sufficient permissions'),                      "wp_auth_rejected"),
    (re.compile(r'Are you sure you want to do this\?'),                          "wp_auth_rejected"),
    (re.compile(r'Sorry, you are not allowed to access this page'),              "wp_auth_rejected"),
]

_WP_CRITICAL_RE = re.compile(
    r'There has been a critical error on this (?:website|site)', re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Subprocess / Docker helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _compose_env(plugin_source: str, plugin_slug: str, secret: str, port: int) -> dict:
    return {
        "PLUGIN_SOURCE":        plugin_source.replace("\\", "/"),
        "PLUGIN_SLUG":          plugin_slug,
        "WPHUNTER_SHIM_SECRET": secret,
        "WP_PORT":              str(port),
    }


def _run_compose(
    args: list[str],
    env: dict,
    input_data: str | None = None,
) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-f", str(_COMPOSE_FILE)] + args
    return subprocess.run(
        cmd,
        env={**os.environ, **env},
        input=input_data,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )


def _compose_check(args: list[str], env: dict, label: str) -> None:
    r = _run_compose(args, env)
    if r.returncode != 0:
        raise RuntimeError(
            f"docker compose {label} failed (rc={r.returncode}):\n"
            + (r.stderr[-2000:] if r.stderr else "(no stderr)")
        )


def _wpcli(args: list[str], env: dict) -> str:
    r = _run_compose(["run", "--rm", "wpcli"] + args, env)
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if r.returncode != 0:
        raise RuntimeError(
            f"wp-cli {args!r} failed (rc={r.returncode}):\n{err[-1000:]}"
        )
    return out


def _wait_for_wp(base_url: str) -> None:
    click.echo(f"[verifier] waiting for WordPress at {base_url}", nl=False)
    deadline = time.time() + _WP_READY_TIMEOUT
    while time.time() < deadline:
        try:
            r = requests.get(
                base_url + "/wp-login.php",
                timeout=3,
                allow_redirects=False,
            )
            if r.status_code in (200, 302):
                click.echo(" ready")
                return
        except Exception:
            pass
        click.echo(".", nl=False)
        time.sleep(_WP_READY_POLL)
    click.echo(" TIMEOUT")
    raise RuntimeError(
        f"WordPress at {base_url} did not become ready within {_WP_READY_TIMEOUT}s"
    )


def _shim(base_url: str, secret: str, params: dict, cookie_header: str | None = None) -> dict | str:
    p = dict(params)
    p["_wphunter"] = secret
    hdrs = {"Cookie": cookie_header} if cookie_header else {}
    r = requests.get(base_url + "/", params=p, headers=hdrs, timeout=15)
    r.raise_for_status()
    ct = r.headers.get("Content-Type", "")
    return r.json() if "json" in ct else r.text.strip()


# ---------------------------------------------------------------------------
# Sandbox setup helpers
# ---------------------------------------------------------------------------

def _install_wp(env: dict, base_url: str, plugin_slug: str) -> None:
    click.echo("[verifier] installing WordPress core ...")
    try:
        out = _wpcli([
            "wp", "core", "install",
            f"--url={base_url}",
            "--title=WPHunter Sandbox",
            "--admin_user=wphunter_admin",
            "--admin_password=wphunter_admin_pass",
            "--admin_email=admin@wphunter.invalid",
            "--skip-email",
        ], env)
        click.echo(f"  {out or 'done'}")
    except RuntimeError as exc:
        if any(s in str(exc).lower() for s in _ALREADY_INSTALLED):
            click.echo("  already installed")
        else:
            raise

    click.echo(f"[verifier] activating plugin {plugin_slug} ...")
    try:
        out = _wpcli(["wp", "plugin", "activate", plugin_slug], env)
        click.echo(f"  {out or 'activated'}")
    except RuntimeError as exc:
        click.echo(f"  WARNING: plugin activation failed - {exc}")

    click.echo("[verifier] creating fixture users ...")
    for role in _FIXTURE_ROLES:
        login = f"wphunter_{role}"
        try:
            _wpcli([
                "wp", "user", "create", login,
                f"{login}@wphunter.invalid",
                f"--role={role}",
                "--user_pass=testpass123",
            ], env)
            click.echo(f"  created {login} ({role})")
        except RuntimeError as exc:
            if any(s in str(exc).lower() for s in _USER_EXISTS):
                click.echo(f"  {login} already exists")
            else:
                raise


def _collect_cookies(base_url: str, secret: str) -> dict[str, str]:
    click.echo("[verifier] resolving fixture cookies ...")
    cookies: dict[str, str] = {}
    for role in _FIXTURE_ROLES:
        data = _shim(base_url, secret, {"wphunter_cookie": role})
        hdr  = data["cookie_header"] if isinstance(data, dict) else str(data)
        cookies[role] = hdr
        click.echo(f"  [{role}] ok")
    return cookies


def _snapshot_db(env: dict) -> str:
    """Export WordPress DB via mysqldump in the db container. Returns SQL dump string."""
    click.echo("[verifier] snapshotting DB ...")
    r = _run_compose(
        ["exec", "-T", "db", "mysqldump", "-u", "wp", "-pwppass", "wordpress"],
        env,
    )
    if r.returncode != 0:
        raise RuntimeError(f"mysqldump failed: {r.stderr[-500:]}")
    return r.stdout


def _restore_db(env: dict, snapshot: str) -> None:
    """Restore WordPress DB from a SQL dump string."""
    r = _run_compose(
        ["exec", "-T", "db", "mysql", "-u", "wp", "-pwppass", "wordpress"],
        env,
        input_data=snapshot,
    )
    if r.returncode != 0:
        raise RuntimeError(f"mysql restore failed: {r.stderr[-500:]}")


def _extract_cookie_role(poc: dict) -> str | None:
    """Return the first {COOKIE:<role>} role found in the raw (pre-resolution) PoC fields."""
    raw = " ".join(filter(None, [
        poc.get("url_path") or "",
        poc.get("headers") or "",
        poc.get("body_params") or "",
    ]))
    m = _COOKIE_RE.search(raw)
    return m.group(1) if m else None


def _make_nonce_fn(base_url: str, secret: str, role: str | None = None, cookies: dict[str, str] | None = None):
    """
    Return a callable(action) -> str | None that fetches nonces via shim.
    Sends the role's auth cookies with the request so wp_get_session_token()
    returns the real session token — required for wp_verify_nonce() to match
    when the same cookies are sent on the actual verification request.
    """
    # Compatibility alias: PoCs may say role='admin' (legacy); WP uses 'administrator'.
    if role == "admin" and cookies and "administrator" in cookies:
        role = "administrator"
    cookie_header = (cookies or {}).get(role) if role else None

    def nonce_fn(action: str) -> str | None:
        try:
            params = {"wphunter_nonce": action}
            if role:
                params["role"] = role
            result = _shim(base_url, secret, params, cookie_header=cookie_header)
            v = str(result).strip() if result else ""
            return v or None
        except Exception:
            return None
    return nonce_fn


# ---------------------------------------------------------------------------
# Sandbox context manager (shared by phase 1 and phase 2)
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _sandbox(plugin_slug: str, plugin_source: str, keep_running: bool = False):
    """
    Context manager: start a fresh WordPress sandbox, yield
    (base_url, secret, cookies, env), tear down on exit.
    """
    plugin_source = str(Path(plugin_source).resolve())
    port     = _free_port()
    secret   = secrets.token_hex(16)
    base_url = f"http://localhost:{port}"
    env      = _compose_env(plugin_source, plugin_slug, secret, port)

    click.echo(f"[verifier] starting sandbox for {plugin_slug} on port {port} ...")
    try:
        _compose_check(["up", "-d", "db", "wordpress"], env, "up")
        _wait_for_wp(base_url)
        _install_wp(env, base_url, plugin_slug)
        cookies  = _collect_cookies(base_url, secret)
        snapshot = _snapshot_db(env)
        yield base_url, secret, cookies, env, snapshot
    finally:
        if keep_running:
            click.echo(
                f"[verifier] sandbox left running at {base_url}\n"
                "           docker compose -f sandbox/docker-compose.yml down -v"
            )
        else:
            click.echo("[verifier] tearing down sandbox ...")
            _run_compose(["down", "-v", "--remove-orphans"], env)
            click.echo("[verifier] teardown complete")


# ---------------------------------------------------------------------------
# Phase 1: setup only (public entry point)
# ---------------------------------------------------------------------------

def run_setup_only(
    plugin_slug: str,
    plugin_source: str | None = None,
    keep_running: bool = False,
    db_path: str | None = None,
) -> None:
    conn = get_conn(db_path)

    if plugin_source is None:
        row = conn.execute(
            "SELECT source_path FROM plugins WHERE slug = ?", (plugin_slug,)
        ).fetchone()
        if not row or not row["source_path"]:
            click.echo(
                f"[verifier] plugin '{plugin_slug}' not found in DB - pass --source"
            )
            sys.exit(1)
        plugin_source = row["source_path"]

    with _sandbox(plugin_slug, plugin_source, keep_running) as (base_url, secret, cookies, env, _snap):
        # List registered AJAX actions
        click.echo("[verifier] listing registered AJAX actions ...")
        data = _shim(base_url, secret, {"wphunter_actions": ""})
        if isinstance(data, dict):
            auth_actions   = sorted(data.get("actions", []))
            nopriv_actions = sorted(data.get("nopriv_actions", []))
        else:
            auth_actions = nopriv_actions = []

        click.echo(f"  Authenticated ({len(auth_actions)}):")
        for a in auth_actions:
            click.echo(f"    wp_ajax_{a}")
        click.echo(f"  Public/nopriv ({len(nopriv_actions)}):")
        for a in nopriv_actions:
            click.echo(f"    wp_ajax_nopriv_{a}")

        click.echo("\n[verifier] setup complete.")


# ---------------------------------------------------------------------------
# Phase 2: placeholder resolution
# ---------------------------------------------------------------------------

def _resolve_value(
    value: str,
    cookies: dict[str, str],
    nonce_fn,
) -> tuple[str, list[str]]:
    """
    Replace all placeholders in value.
    Returns (resolved_string, list_of_unresolved_placeholder_names).
    """
    unresolved: list[str] = []

    def sub_cookie(m: re.Match) -> str:
        role = m.group(1)
        # Alias 'admin' -> 'administrator' for compatibility with PoCs
        # generated before the role rename (WordPress uses the full name).
        if role == "admin" and "administrator" in cookies:
            role = "administrator"
        v = cookies.get(role)
        if v is None:
            unresolved.append(f"COOKIE:{role}")
            return m.group(0)
        return v

    def sub_nonce(m: re.Match) -> str:
        action = m.group(1)
        v = nonce_fn(action)
        if not v:
            unresolved.append(f"NONCE:{action}")
            return m.group(0)
        return v

    def sub_rest_nonce(_m: re.Match) -> str:
        v = nonce_fn("wp_rest")
        if not v:
            unresolved.append("REST_NONCE")
            return "{REST_NONCE}"
        return v

    result = _COOKIE_RE.sub(sub_cookie, value)
    result = _NONCE_RE.sub(sub_nonce, result)
    result = _REST_NONCE_RE.sub(sub_rest_nonce, result)
    return result, unresolved


def _resolve_poc(
    poc: dict,
    cookies: dict[str, str],
    nonce_fn,
) -> tuple[dict, list[str]]:
    """
    Resolve all placeholders in the PoC fields.
    Returns (resolved_poc_dict, all_unresolved).
    resolved_poc["headers"] and ["body_params"] are dicts (not JSON strings).
    """
    resolved    = dict(poc)
    all_unres:  list[str] = []

    if resolved.get("url_path"):
        v, u = _resolve_value(resolved["url_path"], cookies, nonce_fn)
        resolved["url_path"] = v
        all_unres.extend(u)

    headers = json.loads(resolved.get("headers") or "{}")
    new_headers: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() == "cookie" and _COOKIE_RE.search(str(v)):
            # Cookie header: the model may have written e.g. "wordpress_logged_in={COOKIE:sub}"
            # which is malformed after expansion (the placeholder already contains name=value).
            # Replace the entire Cookie header value with the raw cookie_header strings so
            # PHP receives properly named cookies and WordPress can authenticate the user.
            roles   = [m.group(1) for m in _COOKIE_RE.finditer(str(v))]
            # Alias 'admin' -> 'administrator' (WordPress's actual role slug).
            roles_normalized = [
                "administrator" if r == "admin" and "administrator" in cookies else r
                for r in roles
            ]
            missing = [r for r in roles_normalized if r not in cookies]
            valid   = [cookies[r] for r in roles_normalized if r in cookies]
            new_headers[k] = "; ".join(valid) if valid else str(v)
            all_unres.extend(f"COOKIE:{r}" for r in missing)
        else:
            rv, u = _resolve_value(str(v), cookies, nonce_fn)
            new_headers[k] = rv
            all_unres.extend(u)
    resolved["headers"] = new_headers

    body_params = json.loads(resolved.get("body_params") or "{}")
    new_body: dict[str, str] = {}
    for k, v in body_params.items():
        rv, u = _resolve_value(str(v), cookies, nonce_fn)
        new_body[k] = rv
        all_unres.extend(u)
    resolved["body_params"] = new_body

    return resolved, all_unres


# ---------------------------------------------------------------------------
# Phase 2: rejection detection
# ---------------------------------------------------------------------------

def _detect_rejection(body: str) -> str | None:
    """Return a reason string if body matches a WP standard auth-rejection pattern."""
    for pattern, reason in _REJECTION_CHECKS:
        if pattern.search(body):
            return reason
    return None


# ---------------------------------------------------------------------------
# Phase 2: signature matching
# ---------------------------------------------------------------------------

def _check_signature(
    sig_type: str,
    expected_sig: str,
    response: requests.Response,
) -> tuple[bool, str | None]:
    """
    Check whether the response satisfies the expected signature.
    Returns (matched, failure_reason).
    failure_reason is None on success or when not applicable.
    """
    body = (response.text or "")[:_MAX_BODY]

    if sig_type == "string_in_body":
        if not body:
            return False, "empty_response_body"
        return (expected_sig in body), None

    if sig_type == "status_code":
        try:
            return (response.status_code == int(expected_sig)), None
        except (ValueError, TypeError):
            return False, "invalid_expected_status_code"

    if sig_type == "elapsed_gt":
        try:
            threshold = float(expected_sig)
        except (ValueError, TypeError):
            return False, "invalid_elapsed_threshold"
        elapsed = response.elapsed.total_seconds() if response.elapsed else 0.0
        return (elapsed > threshold), None

    if sig_type == "db_row":
        return False, "db_row_not_implemented"

    if sig_type == "file_exists":
        return False, "file_exists_not_implemented"

    return False, f"unknown_signature_type:{sig_type}"


# ---------------------------------------------------------------------------
# Phase 2: verdict writing
# ---------------------------------------------------------------------------

def _write_verdict(
    conn,
    cid: int,
    status: str,
    reason: str | None,
    req_log: str | None,
    resp_log: str | None,
    side_effects: str | None,
    now: str,
) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO verifications
               (candidate_id, status, reason, request_log, response_log,
                side_effects, verified_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (cid, status, reason, req_log, resp_log, side_effects, now),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Phase 2: verification mode dispatch
# ---------------------------------------------------------------------------

# Modes the verifier knows how to run. `single_request` is the original
# verification flow (one request, signature match on the response). Other
# modes plug additional shapes into the pipeline without touching that flow.
_VERIFICATION_MODES = frozenset({
    "single_request",       # default — one request, signature in response
    "two_request_stored",   # write → read; signature in second response
    "timing_blind",         # N samples, median elapsed > threshold
    "file_create",          # filesystem diff via `docker exec`
    "unverifiable_oob",     # OOB SSRF / blind XXE — needs external collaborator
})


def _write_verdict_with_mode(
    conn,
    cid: int,
    status: str,
    reason: str | None,
    req_log: str | None,
    resp_log: str | None,
    side_effects: str | None,
    mode: str,
    evidence: str | None,
    now: str,
) -> None:
    """Extended verdict writer that records the verification mode + evidence.
    Use for new per-class modes; existing _write_verdict stays as-is so the
    legacy single-request path is untouched."""
    conn.execute(
        """INSERT OR REPLACE INTO verifications
               (candidate_id, status, reason, request_log, response_log,
                side_effects, mode, evidence, verified_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (cid, status, reason, req_log, resp_log, side_effects,
         mode, evidence, now),
    )
    conn.commit()


def _verify_one(
    cid: int,
    poc: dict,
    base_url: str,
    cookies: dict[str, str],
    nonce_fn,
    conn,
) -> str:
    """Dispatch a single PoC to the right verification mode.

    Mode is read from poc.verification_mode (set by the PoC generator) and
    defaults to 'single_request' for backward compatibility with existing
    DB rows that pre-date the column.
    """
    mode = (poc.get("verification_mode") or "single_request").strip()
    if mode not in _VERIFICATION_MODES:
        mode = "single_request"

    if mode == "two_request_stored":
        return _verify_two_request_stored(cid, poc, base_url, cookies, nonce_fn, conn)
    if mode == "timing_blind":
        return _verify_timing_blind(cid, poc, base_url, cookies, nonce_fn, conn)
    if mode == "file_create":
        return _verify_file_create(cid, poc, base_url, cookies, nonce_fn, conn)
    if mode == "unverifiable_oob":
        return _verify_unverifiable_oob(cid, poc, conn)

    return _verify_single_request(cid, poc, base_url, cookies, nonce_fn, conn)


def _verify_single_request(
    cid: int,
    poc: dict,
    base_url: str,
    cookies: dict[str, str],
    nonce_fn,
    conn,
) -> str:
    """
    Verify a single PoC. Returns one of: confirmed / failed / partial / error.
    Writes result to verifications table.
    """
    now = datetime.now(timezone.utc).isoformat()

    # ---- resolve placeholders ----
    try:
        resolved, unresolved = _resolve_poc(poc, cookies, nonce_fn)
    except Exception as exc:
        reason = f"placeholder_resolution_error:{exc}"
        _write_verdict(conn, cid, "error", reason, None, None, None, now)
        click.echo(f"  [#{cid}] error - {reason}")
        return "error"

    if unresolved:
        reason = "placeholder_unresolved:" + ",".join(unresolved)
        _write_verdict(conn, cid, "error", reason, None, None, None, now)
        click.echo(f"  [#{cid}] error - {reason}")
        return "error"

    # ---- build request ----
    method   = (poc.get("http_method") or "POST").upper()
    url_path = resolved.get("url_path") or "/wp-admin/admin-ajax.php"
    url      = (base_url + url_path) if url_path.startswith("/") else (base_url + "/" + url_path)
    headers  = resolved["headers"]
    body     = resolved["body_params"]

    req_log = json.dumps({"method": method, "url": url, "headers": headers, "body": body})

    # ---- execute request ----
    try:
        if method == "GET":
            resp = requests.get(
                url, headers=headers, params=body,
                timeout=_REQUEST_TIMEOUT, allow_redirects=True,
            )
        else:
            resp = requests.request(
                method, url, headers=headers,
                data=body or None,
                timeout=_REQUEST_TIMEOUT, allow_redirects=True,
            )
    except requests.Timeout:
        _write_verdict(conn, cid, "error", "request_timeout", req_log, None, None, now)
        click.echo(f"  [#{cid}] error - request_timeout")
        return "error"
    except Exception as exc:
        reason = f"request_error:{exc}"
        _write_verdict(conn, cid, "error", reason, req_log, None, None, now)
        click.echo(f"  [#{cid}] error - {reason}")
        return "error"

    body_text = (resp.text or "")[:_MAX_BODY]
    resp_log  = json.dumps({
        "status":  resp.status_code,
        "headers": dict(resp.headers),
        "body":    body_text,
        "elapsed": resp.elapsed.total_seconds() if resp.elapsed else None,
    })

    # ---- WP critical error ----
    if _WP_CRITICAL_RE.search(body_text):
        _write_verdict(conn, cid, "error", "wp_critical_error", req_log, resp_log, None, now)
        click.echo(f"  [#{cid}] error - wp_critical_error (HTTP {resp.status_code})")
        return "error"

    # ---- HTTP 500 defaults to error unless signature expects it ----
    sig_type = poc.get("signature_type") or ""
    expected = poc.get("expected_signature") or ""
    if resp.status_code == 500 and not (sig_type == "status_code" and expected == "500"):
        _write_verdict(conn, cid, "error", "http_500_response", req_log, resp_log, None, now)
        click.echo(f"  [#{cid}] error - http_500_response")
        return "error"

    # ---- rejection detection ----
    rejection = _detect_rejection(body_text)
    if rejection:
        _write_verdict(conn, cid, "failed", rejection, req_log, resp_log, None, now)
        click.echo(f"  [#{cid}] failed - {rejection} (HTTP {resp.status_code})")
        return "failed"

    # ---- signature matching ----
    matched, sig_reason = _check_signature(sig_type, expected, resp)

    if matched:
        anomaly = None
        if resp.status_code >= 500:
            anomaly = f"http_{resp.status_code}_with_match"
        elif len(resp.text or "") >= _MAX_BODY:
            anomaly = "response_truncated"
        verdict = "partial" if anomaly else "confirmed"
        _write_verdict(conn, cid, verdict, anomaly, req_log, resp_log, None, now)
        click.echo(f"  [#{cid}] {verdict} (HTTP {resp.status_code})")
        return verdict
    else:
        reason = sig_reason or "signature_not_found"
        _write_verdict(conn, cid, "failed", reason, req_log, resp_log, None, now)
        click.echo(f"  [#{cid}] failed - {reason} (HTTP {resp.status_code})")
        return "failed"


# ---------------------------------------------------------------------------
# Verification mode: two_request_stored (stored XSS / persisted injection)
# ---------------------------------------------------------------------------

def _send_one(method: str, url: str, headers: dict, body: dict | None):
    """Single HTTP call wrapper; returns (response, error_reason or None).
    Centralizes timeout / WP critical-error detection used by multi-request
    modes."""
    try:
        if method.upper() == "GET":
            resp = requests.get(
                url, headers=headers, params=body,
                timeout=_REQUEST_TIMEOUT, allow_redirects=True,
            )
        else:
            resp = requests.request(
                method.upper(), url, headers=headers,
                data=body or None,
                timeout=_REQUEST_TIMEOUT, allow_redirects=True,
            )
    except requests.Timeout:
        return None, "request_timeout"
    except Exception as exc:
        return None, f"request_error:{exc}"
    return resp, None


def _verify_two_request_stored(
    cid: int,
    poc: dict,
    base_url: str,
    cookies: dict[str, str],
    nonce_fn,
    conn,
) -> str:
    """Write-then-read verification for stored XSS and other persistent
    injection bugs.

    PoC must provide (in body_params / headers):
      - method / url_path / headers / body_params  (write step)
      - read_url_path                              (second-step URL)
      - read_method (default GET)
      - read_headers (default {})
      - read_body (default {})
      - expected_signature                         (string to find in read response)
      - signature_type                             (defaults to 'string_in_body')
    """
    now = datetime.now(timezone.utc).isoformat()
    mode = "two_request_stored"

    try:
        resolved, unresolved = _resolve_poc(poc, cookies, nonce_fn)
    except Exception as exc:
        _write_verdict_with_mode(conn, cid, "error",
            f"placeholder_resolution_error:{exc}", None, None, None,
            mode, None, now)
        click.echo(f"  [#{cid}] error - placeholder_resolution_error")
        return "error"
    if unresolved:
        _write_verdict_with_mode(conn, cid, "error",
            "placeholder_unresolved:" + ",".join(unresolved),
            None, None, None, mode, None, now)
        click.echo(f"  [#{cid}] error - placeholder_unresolved")
        return "error"

    write_url = base_url + (resolved.get("url_path") or "/wp-admin/admin-ajax.php")
    write_method = (poc.get("http_method") or "POST").upper()
    write_resp, err = _send_one(write_method, write_url,
                                resolved["headers"], resolved["body_params"])
    if err:
        _write_verdict_with_mode(conn, cid, "error", err,
            json.dumps({"step": "write", "url": write_url}), None, None,
            mode, None, now)
        click.echo(f"  [#{cid}] error - {err} (write step)")
        return "error"

    # The "read" parameters come from extra fields on the PoC row. If the
    # PoC generator didn't populate them, fall back to GET '/' which usually
    # renders comments/options where stored XSS lands.
    read_url    = base_url + (poc.get("read_url_path") or "/")
    read_method = (poc.get("read_method") or "GET").upper()
    read_headers = poc.get("read_headers") or {}
    read_body    = poc.get("read_body") or {}
    if isinstance(read_headers, str):
        try: read_headers = json.loads(read_headers)
        except Exception: read_headers = {}
    if isinstance(read_body, str):
        try: read_body = json.loads(read_body)
        except Exception: read_body = {}

    read_resp, err = _send_one(read_method, read_url, read_headers, read_body)
    if err:
        _write_verdict_with_mode(conn, cid, "error", err,
            json.dumps({"step": "read", "url": read_url}), None, None,
            mode, None, now)
        click.echo(f"  [#{cid}] error - {err} (read step)")
        return "error"

    body_text = (read_resp.text or "")[:_MAX_BODY]
    resp_log  = json.dumps({
        "write_status": write_resp.status_code,
        "read_status":  read_resp.status_code,
        "read_body":    body_text,
    })

    expected = poc.get("expected_signature") or ""
    matched  = bool(expected) and (expected in body_text)
    if matched:
        _write_verdict_with_mode(conn, cid, "confirmed", None,
            None, resp_log, None, mode,
            f"signature_in_read_response:{expected[:64]}", now)
        click.echo(f"  [#{cid}] confirmed (stored, two-request)")
        return "confirmed"

    _write_verdict_with_mode(conn, cid, "failed", "signature_not_in_read_response",
        None, resp_log, None, mode, None, now)
    click.echo(f"  [#{cid}] failed - signature_not_in_read_response")
    return "failed"


# ---------------------------------------------------------------------------
# Verification mode: timing_blind (time-based blind SQLi etc.)
# ---------------------------------------------------------------------------

def _verify_timing_blind(
    cid: int,
    poc: dict,
    base_url: str,
    cookies: dict[str, str],
    nonce_fn,
    conn,
) -> str:
    """Send the PoC request N times (default 5), take the median elapsed
    time, confirm if it exceeds the threshold from expected_signature.

    Single-sample timing is too noisy in CI; median of 5 with a 1-second
    threshold catches `SLEEP(2)` reliably while rejecting jitter.
    """
    now = datetime.now(timezone.utc).isoformat()
    mode = "timing_blind"

    try:
        resolved, unresolved = _resolve_poc(poc, cookies, nonce_fn)
    except Exception as exc:
        _write_verdict_with_mode(conn, cid, "error",
            f"placeholder_resolution_error:{exc}", None, None, None,
            mode, None, now)
        return "error"
    if unresolved:
        _write_verdict_with_mode(conn, cid, "error",
            "placeholder_unresolved:" + ",".join(unresolved),
            None, None, None, mode, None, now)
        return "error"

    try:
        threshold = float(poc.get("expected_signature") or "1.0")
    except (TypeError, ValueError):
        threshold = 1.0
    samples = int(poc.get("timing_samples") or 5)
    samples = max(3, min(15, samples))

    url    = base_url + (resolved.get("url_path") or "/wp-admin/admin-ajax.php")
    method = (poc.get("http_method") or "POST").upper()

    elapsed_list: list[float] = []
    for _ in range(samples):
        resp, err = _send_one(method, url, resolved["headers"], resolved["body_params"])
        if err:
            _write_verdict_with_mode(conn, cid, "error", err,
                json.dumps({"url": url, "method": method}),
                None, None, mode, None, now)
            return "error"
        elapsed_list.append(
            resp.elapsed.total_seconds() if resp.elapsed else 0.0
        )

    elapsed_list.sort()
    median = elapsed_list[len(elapsed_list) // 2]
    confirmed = median > threshold

    evidence = json.dumps({
        "threshold_s": threshold,
        "samples":     elapsed_list,
        "median":      median,
    })
    status = "confirmed" if confirmed else "failed"
    reason = None if confirmed else f"median_elapsed_below_threshold:{median:.2f}<{threshold:.2f}"
    _write_verdict_with_mode(conn, cid, status, reason,
        None, evidence, None, mode, evidence, now)
    click.echo(f"  [#{cid}] {status} (timing median={median:.2f}s, threshold={threshold:.2f}s)")
    return status


# ---------------------------------------------------------------------------
# Verification mode: file_create (arbitrary file write / upload)
# ---------------------------------------------------------------------------

def _sandbox_ls(container: str, path: str) -> set[str]:
    """List a directory inside the sandbox container. Returns a set of
    filenames; empty on any error so file_create still produces a verdict."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["docker", "exec", container, "ls", "-1", path],
            timeout=10, text=True, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return set()
    return {ln.strip() for ln in out.splitlines() if ln.strip()}


def _verify_file_create(
    cid: int,
    poc: dict,
    base_url: str,
    cookies: dict[str, str],
    nonce_fn,
    conn,
) -> str:
    """Filesystem diff: snapshot a target dir before+after the PoC, confirm
    if a file matching expected_signature appears.

    PoC fields used:
      - watch_path        : container dir to snapshot (e.g. /var/www/html/wp-content/uploads)
      - watch_container   : container name (default 'sandbox-wordpress')
      - expected_signature: filename substring or regex-like glob
    """
    import re as _re
    now = datetime.now(timezone.utc).isoformat()
    mode = "file_create"

    container = poc.get("watch_container") or "sandbox-wordpress"
    watch_path = poc.get("watch_path") or "/var/www/html/wp-content/uploads"
    expected = poc.get("expected_signature") or ""

    before = _sandbox_ls(container, watch_path)

    try:
        resolved, unresolved = _resolve_poc(poc, cookies, nonce_fn)
    except Exception as exc:
        _write_verdict_with_mode(conn, cid, "error",
            f"placeholder_resolution_error:{exc}", None, None, None,
            mode, None, now)
        return "error"
    if unresolved:
        _write_verdict_with_mode(conn, cid, "error",
            "placeholder_unresolved:" + ",".join(unresolved),
            None, None, None, mode, None, now)
        return "error"

    url    = base_url + (resolved.get("url_path") or "/wp-admin/admin-ajax.php")
    method = (poc.get("http_method") or "POST").upper()
    resp, err = _send_one(method, url, resolved["headers"], resolved["body_params"])
    if err:
        _write_verdict_with_mode(conn, cid, "error", err,
            json.dumps({"url": url}), None, None, mode, None, now)
        return "error"

    after  = _sandbox_ls(container, watch_path)
    new_files = sorted(after - before)

    # Match expected: literal substring OR glob-like pattern
    if expected:
        try:
            pat = _re.compile(expected.replace("*", ".*"))
            matches = [f for f in new_files if pat.search(f)]
        except _re.error:
            matches = [f for f in new_files if expected in f]
    else:
        matches = new_files  # any new file counts

    evidence = json.dumps({
        "watch_path": watch_path,
        "new_files":  new_files,
        "matched":    matches,
    })
    if matches:
        _write_verdict_with_mode(conn, cid, "confirmed", None,
            None, json.dumps({"status": resp.status_code}),
            ",".join(matches), mode, evidence, now)
        click.echo(f"  [#{cid}] confirmed - file created: {matches[0]}")
        return "confirmed"

    _write_verdict_with_mode(conn, cid, "failed", "no_matching_file_created",
        None, json.dumps({"status": resp.status_code, "new_files": new_files}),
        None, mode, evidence, now)
    click.echo(f"  [#{cid}] failed - no_matching_file_created (saw {len(new_files)} new files)")
    return "failed"


# ---------------------------------------------------------------------------
# Verification mode: unverifiable_oob (out-of-band — needs collaborator)
# ---------------------------------------------------------------------------

def _verify_unverifiable_oob(cid: int, poc: dict, conn) -> str:
    """Record the candidate as 'unverifiable' with manual-verification
    instructions. Does NOT send the request — for OOB SSRF / blind XXE
    where confirmation requires an external collaborator (interactsh,
    Burp Collaborator, an attacker-controlled server) that isn't part of
    the sandbox.

    The DB row is marked status='unverifiable' so the funnel counter
    distinguishes these from genuine FPs.
    """
    now = datetime.now(timezone.utc).isoformat()
    reason = poc.get("unverifiable_reason") or "needs_external_collaborator"
    evidence = json.dumps({
        "manual_repro": {
            "url_path":   poc.get("url_path"),
            "method":     poc.get("http_method"),
            "body":       poc.get("body_params"),
            "expected":   poc.get("expected_signature"),
            "instructions": (
                "Set up an external collaborator (interactsh, Burp Collaborator, "
                "or a controlled DNS / HTTP server) and replace COLLABORATOR_URL "
                "in body params with its address. Confirm a callback hits the "
                "collaborator within ~10 seconds of issuing the request."
            ),
        }
    })
    _write_verdict_with_mode(conn, cid, "unverifiable", reason,
        None, None, None, "unverifiable_oob", evidence, now)
    click.echo(f"  [#{cid}] unverifiable - {reason} (manual verification required)")
    return "unverifiable"


# ---------------------------------------------------------------------------
# Phase 2: public entry points
# ---------------------------------------------------------------------------

def _poc_rows_for_plugin(plugin_slug: str, conn) -> list:
    return conn.execute(
        """SELECT p.candidate_id, c.rule_id, c.file_path,
                  p.http_method, p.url_path, p.headers, p.body_params,
                  p.expected_signature, p.signature_type, p.status
           FROM pocs p
           JOIN candidates c ON c.id = p.candidate_id
           WHERE c.plugin_slug = ? AND p.status = 'ready'
           ORDER BY p.candidate_id""",
        (plugin_slug,),
    ).fetchall()


def _plugin_source(plugin_slug: str, conn) -> str | None:
    row = conn.execute(
        "SELECT source_path FROM plugins WHERE slug = ?", (plugin_slug,)
    ).fetchone()
    return row["source_path"] if row else None


def _run_candidates(rows, plugin_slug: str, plugin_source: str, keep_running: bool, conn) -> dict:
    """Shared core: start sandbox, verify each candidate with DB restore between each."""
    counts: dict[str, int] = {
        "confirmed":    0,
        "failed":       0,
        "partial":      0,
        "error":        0,
        "unverifiable": 0,  # new mode: OOB SSRF, blind XXE, etc.
    }

    # Pre-pass: unverifiable_oob mode doesn't need the sandbox at all (it
    # writes a manual-repro stub). Process those first so we don't pay the
    # docker-compose cost when every PoC is OOB.
    sandbox_rows = []
    for row in rows:
        poc = dict(row)
        if (poc.get("verification_mode") or "").strip() == "unverifiable_oob":
            cid = row["candidate_id"]
            click.echo(
                f"\n[verifier] candidate #{cid} "
                f"({row['rule_id'] or '?'} {row['file_path'] or ''}) [mode=unverifiable_oob]"
            )
            result = _verify_unverifiable_oob(cid, poc, conn)
            counts[result if result in counts else "error"] += 1
        else:
            sandbox_rows.append(row)

    if not sandbox_rows:
        return counts

    with _sandbox(plugin_slug, plugin_source, keep_running) as (base_url, secret, cookies, env, snapshot):
        for row in sandbox_rows:
            cid = row["candidate_id"]
            poc = dict(row)
            role     = _extract_cookie_role(poc)
            nonce_fn = _make_nonce_fn(base_url, secret, role=role, cookies=cookies)
            mode_tag = f" [mode={poc.get('verification_mode') or 'single_request'}]"
            click.echo(
                f"\n[verifier] candidate #{cid} "
                f"({row['rule_id'] or '?'} {row['file_path'] or ''})"
                + (f" [nonce-role={role}]" if role else "")
                + mode_tag
            )
            _restore_db(env, snapshot)
            result = _verify_one(cid, poc, base_url, cookies, nonce_fn, conn)
            counts[result if result in counts else "error"] += 1
    return counts


def run_verify(
    candidate_id: int,
    keep_running: bool = False,
    db_path: str | None = None,
) -> str:
    """Verify a single candidate. Returns verdict string."""
    conn = get_conn(db_path)

    poc_row = conn.execute(
        "SELECT * FROM pocs WHERE candidate_id = ?", (candidate_id,)
    ).fetchone()
    if not poc_row:
        click.echo(f"[verifier] no PoC found for candidate #{candidate_id}")
        return "error"
    if poc_row["status"] != "ready":
        click.echo(
            f"[verifier] candidate #{candidate_id} status={poc_row['status']} - skipping"
        )
        return "error"

    cand_row = conn.execute(
        """SELECT c.plugin_slug, p.source_path, c.rule_id, c.file_path
           FROM candidates c JOIN plugins p ON p.slug = c.plugin_slug
           WHERE c.id = ?""",
        (candidate_id,),
    ).fetchone()
    if not cand_row:
        click.echo(f"[verifier] candidate #{candidate_id} not found")
        return "error"

    plugin_slug   = cand_row["plugin_slug"]
    plugin_source = cand_row["source_path"]
    poc           = dict(poc_row)

    click.echo(f"[verifier] verifying #{candidate_id} ({cand_row['rule_id']} {cand_row['file_path']})")

    counts = _run_candidates(
        [{"candidate_id": candidate_id, "rule_id": cand_row["rule_id"],
          "file_path": cand_row["file_path"], **poc}],
        plugin_slug, plugin_source, keep_running, conn,
    )
    return next(k for k, v in counts.items() if v > 0) if any(counts.values()) else "error"


def run_verify_plugin(
    plugin_slug: str,
    keep_running: bool = False,
    db_path: str | None = None,
) -> dict:
    """Verify all ready PoCs for plugin_slug. Returns counts dict."""
    conn = get_conn(db_path)
    rows = _poc_rows_for_plugin(plugin_slug, conn)
    if not rows:
        click.echo(f"[verifier] no ready PoCs for {plugin_slug}")
        return {"confirmed": 0, "failed": 0, "partial": 0, "error": 0}

    src = _plugin_source(plugin_slug, conn)
    if not src:
        click.echo(f"[verifier] no source path for {plugin_slug}")
        return {"confirmed": 0, "failed": 0, "partial": 0, "error": 0}

    click.echo(f"[verifier] {len(rows)} ready PoC(s) for {plugin_slug}")
    from hunter.runs import Run
    with Run("verify", plugin_slug=plugin_slug, db_path=db_path) as v_run:
        counts = _run_candidates(rows, plugin_slug, src, keep_running, conn)
        v_run.bump("sandbox_confirmed", counts.get("confirmed", 0))
        # 'partial' = ran but signature didn't perfectly match.
        # 'unverifiable' = OOB / external-collaborator case — needs human review.
        v_run.bump("sandbox_unverifiable",
                   counts.get("partial", 0)
                   + counts.get("unverifiable", 0)
                   + counts.get("error", 0))
    unverif = counts.get("unverifiable", 0)
    click.echo(
        f"\n[verifier] {plugin_slug}: "
        f"confirmed={counts['confirmed']} failed={counts['failed']} "
        f"partial={counts['partial']} error={counts['error']}"
        + (f" unverifiable={unverif}" if unverif else "")
    )
    return counts


def run_verify_all_ready(
    keep_running: bool = False,
    db_path: str | None = None,
) -> dict:
    """Verify all ready PoCs across all plugins. Returns aggregated counts."""
    conn = get_conn(db_path)
    slugs = [
        r["plugin_slug"]
        for r in conn.execute(
            """SELECT DISTINCT c.plugin_slug
               FROM pocs p JOIN candidates c ON c.id = p.candidate_id
               WHERE p.status = 'ready'
               ORDER BY c.plugin_slug"""
        ).fetchall()
    ]
    if not slugs:
        click.echo("[verifier] no ready PoCs found")
        return {"confirmed": 0, "failed": 0, "partial": 0, "error": 0}

    total: dict[str, int] = {"confirmed": 0, "failed": 0, "partial": 0, "error": 0}
    for slug in slugs:
        counts = run_verify_plugin(slug, keep_running=False, db_path=db_path)
        for k in total:
            total[k] += counts.get(k, 0)

    click.echo(
        f"\n[verifier] all-ready totals: "
        f"confirmed={total['confirmed']} failed={total['failed']} "
        f"partial={total['partial']} error={total['error']}"
    )
    return total
