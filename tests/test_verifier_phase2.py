"""
Tests for verifier.py phase 2: placeholder resolution, rejection detection,
signature matching, verdict logic, and teardown behaviour.

No Docker is started — subprocess calls are mocked, HTTP via `responses`.
"""
import json
import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import responses as rsps

from hunter.verifier import (
    _check_signature,
    _detect_rejection,
    _resolve_poc,
    _resolve_value,
    _verify_one,
    _write_verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_conn():
    """In-memory SQLite with the verifications table."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE verifications (
            candidate_id INTEGER PRIMARY KEY,
            status TEXT,
            reason TEXT,
            request_log TEXT,
            response_log TEXT,
            side_effects TEXT,
            verified_at TEXT
        );
    """)
    return conn


def _make_poc(**overrides) -> dict:
    base = {
        "http_method":        "POST",
        "url_path":           "/wp-admin/admin-ajax.php",
        "headers":            json.dumps({"Content-Type": "application/x-www-form-urlencoded"}),
        "body_params":        json.dumps({"action": "test_action", "data": "payload"}),
        "expected_signature": "$P$B",
        "signature_type":     "string_in_body",
    }
    base.update(overrides)
    return base


def _fake_response(body: str, status: int = 200):
    r = MagicMock()
    r.text      = body
    r.status_code = status
    r.headers   = {"Content-Type": "text/html"}
    r.elapsed   = None
    return r


# ---------------------------------------------------------------------------
# Placeholder resolution
# ---------------------------------------------------------------------------

class TestResolveValue:
    def test_cookie_substituted(self):
        cookies = {"subscriber": "wp_auth_abc=token123"}
        result, unres = _resolve_value("{COOKIE:subscriber}", cookies, lambda a: None)
        assert result == "wp_auth_abc=token123"
        assert unres == []

    def test_nonce_substituted(self):
        result, unres = _resolve_value("{NONCE:my_action}", {}, lambda _: "abc123")
        assert result == "abc123"
        assert unres == []

    def test_rest_nonce_substituted(self):
        result, unres = _resolve_value("{REST_NONCE}", {}, lambda _: "restnonce99")
        assert result == "restnonce99"
        assert unres == []

    def test_unresolved_cookie_reported(self):
        result, unres = _resolve_value("{COOKIE:admin}", {}, lambda _: None)
        assert result == "{COOKIE:admin}"
        assert "COOKIE:admin" in unres

    def test_unresolved_nonce_reported(self):
        result, unres = _resolve_value("{NONCE:ghost_action}", {}, lambda _: None)
        assert "{NONCE:ghost_action}" in result
        assert "NONCE:ghost_action" in unres

    def test_unresolved_rest_nonce_reported(self):
        result, unres = _resolve_value("{REST_NONCE}", {}, lambda _: None)
        assert result == "{REST_NONCE}"
        assert "REST_NONCE" in unres

    def test_multiple_placeholders_in_one_string(self):
        cookies = {"editor": "wp_auth_ed=edval"}
        result, unres = _resolve_value(
            "Cookie: {COOKIE:editor}; nonce={NONCE:edit_post}",
            cookies,
            lambda _: "nonce42",
        )
        assert "wp_auth_ed=edval" in result
        assert "nonce42" in result
        assert unres == []

    def test_no_placeholders_unchanged(self):
        result, unres = _resolve_value("action=bookingpress_test", {}, lambda _: None)
        assert result == "action=bookingpress_test"
        assert unres == []


class TestExtractCookieRole:
    def test_finds_role_in_headers(self):
        from hunter.verifier import _extract_cookie_role
        poc = _make_poc(headers=json.dumps({"Cookie": "{COOKIE:subscriber}"}))
        assert _extract_cookie_role(poc) == "subscriber"

    def test_finds_role_in_body(self):
        from hunter.verifier import _extract_cookie_role
        poc = _make_poc(body_params=json.dumps({"cookie": "{COOKIE:admin}"}))
        assert _extract_cookie_role(poc) == "admin"

    def test_no_cookie_placeholder_returns_none(self):
        from hunter.verifier import _extract_cookie_role
        poc = _make_poc()
        assert _extract_cookie_role(poc) is None

    def test_prefers_first_match(self):
        from hunter.verifier import _extract_cookie_role
        poc = _make_poc(
            headers=json.dumps({"Cookie": "{COOKIE:editor}"}),
            body_params=json.dumps({"x": "{COOKIE:admin}"}),
        )
        assert _extract_cookie_role(poc) == "editor"


class TestResolvePoc:
    def test_resolves_headers_and_body(self):
        cookies = {"subscriber": "wp_auth=sub_token"}
        poc = _make_poc(
            headers=json.dumps({"Cookie": "{COOKIE:subscriber}"}),
            body_params=json.dumps({"_wpnonce": "{NONCE:save_action}", "x": "1"}),
        )
        resolved, unres = _resolve_poc(poc, cookies, lambda _: "testnonce")
        assert resolved["headers"]["Cookie"] == "wp_auth=sub_token"
        assert resolved["body_params"]["_wpnonce"] == "testnonce"
        assert unres == []

    def test_cookie_header_prefix_stripped(self):
        """Model sometimes writes 'wordpress_logged_in={COOKIE:sub}' — the prefix must be dropped."""
        cookies = {"subscriber": "wordpress_HASH=auth_val; wordpress_logged_in_HASH=li_val"}
        poc = _make_poc(
            headers=json.dumps({"Cookie": "wordpress_logged_in={COOKIE:subscriber}"}),
        )
        resolved, unres = _resolve_poc(poc, cookies, lambda _: "n")
        assert resolved["headers"]["Cookie"] == "wordpress_HASH=auth_val; wordpress_logged_in_HASH=li_val"
        assert unres == []

    def test_cookie_header_no_prefix_still_works(self):
        """Cookie header with just {COOKIE:sub} (correct form) also works."""
        cookies = {"admin": "wordpress_HASH=auth; wordpress_logged_in_HASH=li"}
        poc = _make_poc(headers=json.dumps({"Cookie": "{COOKIE:admin}"}))
        resolved, unres = _resolve_poc(poc, cookies, lambda _: "n")
        assert resolved["headers"]["Cookie"] == "wordpress_HASH=auth; wordpress_logged_in_HASH=li"
        assert unres == []

    def test_collects_all_unresolved(self):
        poc = _make_poc(
            headers=json.dumps({"Cookie": "{COOKIE:editor}"}),
            body_params=json.dumps({"nonce": "{NONCE:missing}"}),
        )
        _, unres = _resolve_poc(poc, {}, lambda _: None)
        assert "COOKIE:editor" in unres
        assert "NONCE:missing" in unres


# ---------------------------------------------------------------------------
# Rejection detection
# ---------------------------------------------------------------------------

class TestDetectRejection:
    def test_negative_one(self):
        assert _detect_rejection("-1") == "wp_auth_rejected"

    def test_negative_one_with_whitespace(self):
        assert _detect_rejection("  -1  \n") == "wp_auth_rejected"

    def test_zero(self):
        assert _detect_rejection("0") == "wp_auth_rejected"

    def test_json_nonce_rejection(self):
        assert _detect_rejection('{"success":false,"data":"-1"}') == "wp_auth_rejected"

    def test_json_rejection_with_spaces(self):
        body = '{"success": false, "data": "0"}'
        assert _detect_rejection(body) == "wp_auth_rejected"

    def test_insufficient_permissions(self):
        assert _detect_rejection("You do not have sufficient permissions") == "wp_auth_rejected"

    def test_nonce_confirm_prompt(self):
        assert _detect_rejection("Are you sure you want to do this?") == "wp_auth_rejected"

    def test_access_denied(self):
        assert _detect_rejection("Sorry, you are not allowed to access this page") == "wp_auth_rejected"

    def test_normal_response_not_rejected(self):
        assert _detect_rejection('{"success":true,"data":"ok"}') is None

    def test_partial_match_in_long_body(self):
        body = "Some HTML... You do not have sufficient permissions to edit this post..."
        assert _detect_rejection(body) == "wp_auth_rejected"

    def test_nonempty_not_rejected(self):
        assert _detect_rejection("1") is None
        assert _detect_rejection("Success") is None


# ---------------------------------------------------------------------------
# Signature matching
# ---------------------------------------------------------------------------

class TestCheckSignature:
    def test_string_in_body_confirmed(self):
        resp = _fake_response("admin hash: $P$Bhash123")
        matched, reason = _check_signature("string_in_body", "$P$B", resp)
        assert matched is True
        assert reason is None

    def test_string_in_body_not_found(self):
        resp = _fake_response("nothing useful here")
        matched, reason = _check_signature("string_in_body", "$P$B", resp)
        assert matched is False

    def test_string_in_body_empty_never_confirmed(self):
        resp = _fake_response("")
        matched, reason = _check_signature("string_in_body", "$P$B", resp)
        assert matched is False
        assert reason == "empty_response_body"

    def test_string_in_body_none_text(self):
        resp = _fake_response("")
        resp.text = None
        matched, reason = _check_signature("string_in_body", "$P$B", resp)
        assert matched is False

    def test_status_code_confirmed(self):
        resp = _fake_response("ok", status=200)
        matched, _ = _check_signature("status_code", "200", resp)
        assert matched is True

    def test_status_code_wrong(self):
        resp = _fake_response("ok", status=404)
        matched, _ = _check_signature("status_code", "200", resp)
        assert matched is False

    def test_status_code_bad_expected(self):
        resp = _fake_response("ok", status=200)
        matched, reason = _check_signature("status_code", "not_a_number", resp)
        assert matched is False
        assert "invalid" in reason

    def test_db_row_not_implemented(self):
        resp = _fake_response("ok")
        matched, reason = _check_signature("db_row", "something", resp)
        assert matched is False
        assert "not_implemented" in reason

    def test_file_exists_not_implemented(self):
        resp = _fake_response("ok")
        matched, reason = _check_signature("file_exists", "/uploads/shell.php", resp)
        assert matched is False
        assert "not_implemented" in reason

    def test_elapsed_gt_confirmed(self):
        resp = _fake_response("ok")
        resp.elapsed = MagicMock()
        resp.elapsed.total_seconds.return_value = 3.8
        matched, reason = _check_signature("elapsed_gt", "3", resp)
        assert matched is True
        assert reason is None

    def test_elapsed_gt_not_elapsed(self):
        resp = _fake_response("ok")
        resp.elapsed = MagicMock()
        resp.elapsed.total_seconds.return_value = 1.2
        matched, reason = _check_signature("elapsed_gt", "3", resp)
        assert matched is False

    def test_elapsed_gt_no_elapsed_attr(self):
        resp = _fake_response("ok")
        resp.elapsed = None
        matched, reason = _check_signature("elapsed_gt", "3", resp)
        assert matched is False

    def test_elapsed_gt_invalid_threshold(self):
        resp = _fake_response("ok")
        matched, reason = _check_signature("elapsed_gt", "not_a_number", resp)
        assert matched is False
        assert reason == "invalid_elapsed_threshold"

    def test_unknown_sig_type(self):
        resp = _fake_response("ok")
        matched, reason = _check_signature("magic_beans", "x", resp)
        assert matched is False
        assert "unknown_signature_type" in reason


# ---------------------------------------------------------------------------
# Verdict logic (_verify_one with mocked HTTP)
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:9999"
COOKIES  = {"subscriber": "wp_auth=sub", "admin": "wp_auth=adm",
             "editor": "wp_auth=ed", "contributor": "wp_auth=contrib"}


def noop_nonce(_action: str) -> str:
    return "testnonce123"


@rsps.activate
def test_verify_confirmed():
    rsps.add(rsps.POST, BASE_URL + "/wp-admin/admin-ajax.php",
             body="prefix $P$B hash suffix", status=200)
    conn = _make_conn()
    poc  = _make_poc()
    result = _verify_one(1, poc, BASE_URL, COOKIES, noop_nonce, conn)
    assert result == "confirmed"
    row = conn.execute("SELECT * FROM verifications WHERE candidate_id=1").fetchone()
    assert row["status"] == "confirmed"
    assert row["reason"] is None


@rsps.activate
def test_verify_failed_sig_not_found():
    rsps.add(rsps.POST, BASE_URL + "/wp-admin/admin-ajax.php",
             body="normal response no hash", status=200)
    conn = _make_conn()
    result = _verify_one(2, _make_poc(), BASE_URL, COOKIES, noop_nonce, conn)
    assert result == "failed"
    row = conn.execute("SELECT * FROM verifications WHERE candidate_id=2").fetchone()
    assert row["status"] == "failed"
    assert row["reason"] == "signature_not_found"


@rsps.activate
def test_verify_failed_wp_auth_rejected():
    rsps.add(rsps.POST, BASE_URL + "/wp-admin/admin-ajax.php",
             body="-1", status=200)
    conn = _make_conn()
    result = _verify_one(3, _make_poc(), BASE_URL, COOKIES, noop_nonce, conn)
    assert result == "failed"
    row = conn.execute("SELECT * FROM verifications WHERE candidate_id=3").fetchone()
    assert row["status"] == "failed"
    assert row["reason"] == "wp_auth_rejected"


@rsps.activate
def test_verify_error_on_500():
    rsps.add(rsps.POST, BASE_URL + "/wp-admin/admin-ajax.php",
             body="<html>Error</html>", status=500)
    conn = _make_conn()
    result = _verify_one(4, _make_poc(), BASE_URL, COOKIES, noop_nonce, conn)
    assert result == "error"
    row = conn.execute("SELECT * FROM verifications WHERE candidate_id=4").fetchone()
    assert row["status"] == "error"
    assert row["reason"] == "http_500_response"


@rsps.activate
def test_verify_error_wp_critical():
    rsps.add(rsps.POST, BASE_URL + "/wp-admin/admin-ajax.php",
             body="There has been a critical error on this website.", status=500)
    conn = _make_conn()
    result = _verify_one(5, _make_poc(), BASE_URL, COOKIES, noop_nonce, conn)
    assert result == "error"
    row = conn.execute("SELECT * FROM verifications WHERE candidate_id=5").fetchone()
    assert row["reason"] == "wp_critical_error"


@rsps.activate
def test_verify_error_timeout():
    rsps.add(rsps.POST, BASE_URL + "/wp-admin/admin-ajax.php",
             body=__import__("requests").Timeout("timed out"))
    conn = _make_conn()
    result = _verify_one(6, _make_poc(), BASE_URL, COOKIES, noop_nonce, conn)
    assert result == "error"
    row = conn.execute("SELECT * FROM verifications WHERE candidate_id=6").fetchone()
    assert row["reason"] == "request_timeout"


@rsps.activate
def test_verify_partial_5xx_with_sig():
    poc = _make_poc(
        signature_type="status_code",
        expected_signature="500",
    )
    rsps.add(rsps.POST, BASE_URL + "/wp-admin/admin-ajax.php",
             body="error trace with $P$B", status=500)
    conn = _make_conn()
    result = _verify_one(7, poc, BASE_URL, COOKIES, noop_nonce, conn)
    # status_code sig: expects 500, got 500 -> matched
    # but status >= 500 -> partial
    assert result == "partial"
    row = conn.execute("SELECT * FROM verifications WHERE candidate_id=7").fetchone()
    assert row["status"] == "partial"
    assert "500" in row["reason"]


def test_verify_error_unresolved_placeholder():
    """Unresolved placeholder -> error before any HTTP request."""
    poc = _make_poc(
        body_params=json.dumps({"_wpnonce": "{NONCE:missing_action}"}),
    )
    conn = _make_conn()
    result = _verify_one(8, poc, BASE_URL, {}, lambda _: None, conn)
    assert result == "error"
    row = conn.execute("SELECT * FROM verifications WHERE candidate_id=8").fetchone()
    assert row["status"] == "error"
    assert "placeholder_unresolved" in row["reason"]


@rsps.activate
def test_verify_get_request():
    """GET requests pass body_params as query string."""
    poc = _make_poc(
        http_method="GET",
        url_path="/wp-admin/admin-ajax.php?action=test",
        body_params=json.dumps({"q": "injection"}),
    )
    rsps.add(rsps.GET, BASE_URL + "/wp-admin/admin-ajax.php",
             body="result $P$B end", status=200)
    conn = _make_conn()
    result = _verify_one(9, poc, BASE_URL, COOKIES, noop_nonce, conn)
    assert result == "confirmed"


# ---------------------------------------------------------------------------
# Teardown isolation
# ---------------------------------------------------------------------------

class TestTeardown:
    def test_sandbox_teardown_called_on_success(self):
        """_sandbox context manager calls docker compose down on normal exit."""
        calls = []

        def fake_run_compose(args, env):
            calls.append(args)
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch("hunter.verifier._run_compose", side_effect=fake_run_compose), \
             patch("hunter.verifier._wait_for_wp"), \
             patch("hunter.verifier._install_wp"), \
             patch("hunter.verifier._collect_cookies", return_value={}), \
             patch("hunter.verifier._snapshot_db"):
            from hunter.verifier import _sandbox
            with _sandbox("test-plugin", "/fake/path"):
                pass

        teardown = [c for c in calls if "down" in c]
        assert any("-v" in c for c in teardown), "expected 'down -v' teardown call"

    def test_sandbox_teardown_called_on_exception(self):
        """_sandbox tears down even when the body raises."""
        calls = []

        def fake_run_compose(args, env):
            calls.append(args)
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch("hunter.verifier._run_compose", side_effect=fake_run_compose), \
             patch("hunter.verifier._wait_for_wp"), \
             patch("hunter.verifier._install_wp"), \
             patch("hunter.verifier._collect_cookies", return_value={}), \
             patch("hunter.verifier._snapshot_db"):
            from hunter.verifier import _sandbox
            with pytest.raises(RuntimeError):
                with _sandbox("test-plugin", "/fake/path"):
                    raise RuntimeError("intentional failure")

        teardown = [c for c in calls if "down" in c]
        assert any("-v" in c for c in teardown)

    def test_keep_running_skips_teardown(self):
        """With keep_running=True, down is NOT called."""
        calls = []

        def fake_run_compose(args, env):
            calls.append(args)
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch("hunter.verifier._run_compose", side_effect=fake_run_compose), \
             patch("hunter.verifier._wait_for_wp"), \
             patch("hunter.verifier._install_wp"), \
             patch("hunter.verifier._collect_cookies", return_value={}), \
             patch("hunter.verifier._snapshot_db"):
            from hunter.verifier import _sandbox
            with _sandbox("test-plugin", "/fake/path", keep_running=True):
                pass

        teardown = [c for c in calls if "down" in c]
        assert teardown == [], "expected no teardown when keep_running=True"
