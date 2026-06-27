"""
Tests for hunter.poc_generator.

All Anthropic API calls are mocked — no real network traffic.
"""
import json
from datetime import date
from unittest.mock import MagicMock

import pytest

from hunter.db import get_conn, migrate
from hunter.poc_generator import _compute_cost, run_poc


# ---------------------------------------------------------------------------
# Fake API response objects
# ---------------------------------------------------------------------------

class _FakeUsage:
    def __init__(self, input_tokens: int = 100, output_tokens: int = 50):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeToolBlock:
    type = "tool_use"
    name = "submit_poc"

    def __init__(self, tool_input: dict):
        self.input = tool_input


class _FakeResponse:
    def __init__(self, tool_input: dict, input_tokens: int = 100, output_tokens: int = 50):
        self.content = [_FakeToolBlock(tool_input)]
        self.usage = _FakeUsage(input_tokens, output_tokens)


class _EmptyResponse:
    """Malformed response: no tool_use block."""
    def __init__(self):
        self.content = []
        self.usage = _FakeUsage(10, 5)


def _ready_input(
    confidence: str = "high",
    http_method: str = "POST",
    url_path: str = "/wp-admin/admin-ajax.php?action=vuln_action",
    headers: dict | None = None,
    body_params: dict | None = None,
    expected_signature: str = "$P$B",
    signature_type: str = "string_in_body",
) -> dict:
    return {
        "confidence": confidence,
        "unverifiable_reason": "",
        "http_method": http_method,
        "url_path": url_path,
        "headers": headers or {"Content-Type": "application/x-www-form-urlencoded"},
        "body_params": body_params or {
            "action": "vuln_action",
            "id": "1 UNION SELECT user_login,user_pass,3 FROM wp_users-- -",
        },
        "expected_signature": expected_signature,
        "signature_type": signature_type,
    }


def _unverifiable_input(reason: str = "AJAX action name not visible in provided code") -> dict:
    return {"confidence": "low", "unverifiable_reason": reason}


def _mock_client(*responses) -> MagicMock:
    client = MagicMock()
    client.messages.create.side_effect = list(responses)
    return client


# ---------------------------------------------------------------------------
# DB fixtures and helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path):
    db_file = str(tmp_path / "hunter_test.db")
    migrate(db_file)
    return db_file


def _insert_plugin(conn, slug: str = "test-plugin") -> None:
    conn.execute(
        "INSERT OR IGNORE INTO plugins "
        "(slug, name, version, active_installs, last_updated, source_path, ingested_at) "
        "VALUES (?, ?, '1.0', 100, '', '/tmp', '2024-01-01')",
        (slug, slug),
    )


def _insert_candidate(
    conn,
    slug: str = "test-plugin",
    rule_id: str = "wp-sqli",
    file_path: str = "plugin.php",
    line_start: int = 10,
    line_end: int = 12,
    snippet: str = "$wpdb->query(\"SELECT * WHERE id=\" . $_GET['id']);",
) -> int:
    cur = conn.execute(
        "INSERT INTO candidates "
        "(plugin_slug, rule_id, file_path, line_start, line_end, code_snippet, "
        "semgrep_severity, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'ERROR', '2024-01-01')",
        (slug, rule_id, file_path, line_start, line_end, snippet),
    )
    return cur.lastrowid


def _insert_triage(
    conn,
    candidate_id: int,
    verdict: str = "real",
    reachability: str = "unauth",
    reasoning: str = "Direct SQLi via $_GET",
    poc_outline: str = "POST to admin-ajax.php with UNION SELECT",
) -> None:
    conn.execute(
        "INSERT INTO triage "
        "(candidate_id, verdict, reachability, reasoning, poc_outline, "
        "confidence, tokens_used, cost_usd, triaged_at) "
        "VALUES (?, ?, ?, ?, ?, 'high', 100, 0.001, '2024-01-01T00:00:00+00:00')",
        (candidate_id, verdict, reachability, reasoning, poc_outline),
    )


@pytest.fixture()
def seeded_db(tmp_db):
    """DB with one plugin, one real SQLi candidate, and its triage row."""
    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    cid = _insert_candidate(conn)
    _insert_triage(conn, cid, verdict="real")
    conn.commit()
    return tmp_db


# ---------------------------------------------------------------------------
# Verdict filtering — only 'real' proceeds
# ---------------------------------------------------------------------------

def test_real_verdict_gets_poc(seeded_db):
    client = _mock_client(_FakeResponse(_ready_input()))
    result = run_poc("test-plugin", db_path=seeded_db, client=client)

    assert result["ready"] == 1
    assert result["unverifiable"] == 0
    assert result["errors"] == 0
    assert result["total"] == 1

    row = get_conn(seeded_db).execute(
        "SELECT * FROM pocs WHERE candidate_id = 1"
    ).fetchone()
    assert row is not None
    assert row["status"] == "ready"
    assert row["http_method"] == "POST"
    assert row["confidence"] == "high"
    assert row["unverifiable_reason"] == ""
    assert row["url_path"] == "/wp-admin/admin-ajax.php?action=vuln_action"


def test_oos_verdict_not_in_pocs(tmp_db):
    """real_but_not_cve_worthy candidates must NOT get a pocs row."""
    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    cid = _insert_candidate(conn)
    _insert_triage(conn, cid, verdict="real_but_not_cve_worthy", reachability="admin")
    conn.commit()

    client = MagicMock()
    result = run_poc("test-plugin", db_path=tmp_db, client=client)

    assert client.messages.create.call_count == 0
    assert result["total"] == 0

    row = get_conn(tmp_db).execute(
        "SELECT * FROM pocs WHERE candidate_id = 1"
    ).fetchone()
    assert row is None


def test_fp_verdict_skipped(tmp_db):
    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    cid = _insert_candidate(conn)
    _insert_triage(conn, cid, verdict="likely_fp")
    conn.commit()

    client = MagicMock()
    result = run_poc("test-plugin", db_path=tmp_db, client=client)

    assert client.messages.create.call_count == 0
    assert result["total"] == 0
    assert get_conn(tmp_db).execute(
        "SELECT * FROM pocs WHERE candidate_id = 1"
    ).fetchone() is None


def test_needs_more_context_verdict_skipped(tmp_db):
    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    cid = _insert_candidate(conn)
    _insert_triage(conn, cid, verdict="needs_more_context")
    conn.commit()

    client = MagicMock()
    result = run_poc("test-plugin", db_path=tmp_db, client=client)

    assert client.messages.create.call_count == 0
    assert result["total"] == 0


# ---------------------------------------------------------------------------
# PoC status: ready vs unverifiable
# ---------------------------------------------------------------------------

def test_unverifiable_response_stored_without_request_fields(seeded_db):
    client = _mock_client(_FakeResponse(_unverifiable_input()))
    result = run_poc("test-plugin", db_path=seeded_db, client=client)

    assert result["unverifiable"] == 1
    assert result["ready"] == 0

    row = get_conn(seeded_db).execute(
        "SELECT * FROM pocs WHERE candidate_id = 1"
    ).fetchone()
    assert row is not None
    assert row["status"] == "unverifiable"
    assert "action name" in row["unverifiable_reason"]
    # All request fields must be NULL for unverifiable PoCs
    assert row["http_method"] is None
    assert row["url_path"] is None
    assert row["headers"] is None
    assert row["body_params"] is None
    assert row["expected_signature"] is None
    assert row["signature_type"] is None


def test_ready_poc_stores_all_request_fields(seeded_db):
    inp = _ready_input(
        http_method="POST",
        url_path="/wp-admin/admin-ajax.php?action=foo",
        headers={"Cookie": "wordpress_logged_in={SUBSCRIBER_COOKIE}"},
        body_params={"action": "foo", "id": "1 UNION SELECT 1,2,3-- -"},
        expected_signature="$P$B",
        signature_type="string_in_body",
    )
    client = _mock_client(_FakeResponse(inp))
    run_poc("test-plugin", db_path=seeded_db, client=client)

    row = get_conn(seeded_db).execute(
        "SELECT * FROM pocs WHERE candidate_id = 1"
    ).fetchone()
    assert row["http_method"] == "POST"
    assert row["url_path"] == "/wp-admin/admin-ajax.php?action=foo"
    assert json.loads(row["headers"]) == {"Cookie": "wordpress_logged_in={SUBSCRIBER_COOKIE}"}
    assert json.loads(row["body_params"]) == {"action": "foo", "id": "1 UNION SELECT 1,2,3-- -"}
    assert row["expected_signature"] == "$P$B"
    assert row["signature_type"] == "string_in_body"


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------

def test_malformed_response_triggers_retry(seeded_db):
    """First call returns no tool_use block; retry returns a valid PoC."""
    client = _mock_client(_EmptyResponse(), _FakeResponse(_ready_input()))
    result = run_poc("test-plugin", db_path=seeded_db, client=client)

    assert client.messages.create.call_count == 2
    assert result["ready"] == 1

    row = get_conn(seeded_db).execute(
        "SELECT * FROM pocs WHERE candidate_id = 1"
    ).fetchone()
    assert row["status"] == "ready"


def test_both_malformed_responses_yield_error(seeded_db):
    """Both attempts malformed → error, nothing written to pocs."""
    client = _mock_client(_EmptyResponse(), _EmptyResponse())
    result = run_poc("test-plugin", db_path=seeded_db, client=client)

    assert client.messages.create.call_count == 2
    assert result["errors"] == 1
    assert result["ready"] == 0

    row = get_conn(seeded_db).execute(
        "SELECT * FROM pocs WHERE candidate_id = 1"
    ).fetchone()
    assert row is None


# ---------------------------------------------------------------------------
# Skip already-processed candidates
# ---------------------------------------------------------------------------

def test_already_processed_candidate_skipped(seeded_db):
    conn = get_conn(seeded_db)
    today = date.today().isoformat()
    conn.execute(
        "INSERT INTO pocs (candidate_id, status, confidence, unverifiable_reason, "
        "tokens_used, cost_usd, generated_at) "
        "VALUES (1, 'ready', 'high', '', 100, 0.001, ?)",
        (f"{today}T00:00:00+00:00",),
    )
    conn.commit()

    client = MagicMock()
    result = run_poc("test-plugin", db_path=seeded_db, client=client)

    assert client.messages.create.call_count == 0
    assert result["total"] == 0


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------

def test_cost_logged_per_candidate(seeded_db):
    client = _mock_client(_FakeResponse(
        _ready_input(),
        input_tokens=1000,
        output_tokens=200,
    ))
    run_poc("test-plugin", db_path=seeded_db, client=client)

    row = get_conn(seeded_db).execute(
        "SELECT * FROM pocs WHERE candidate_id = 1"
    ).fetchone()
    expected = _compute_cost(1000, 200)
    assert abs(row["cost_usd"] - expected) < 1e-9
    assert row["tokens_used"] == 1200


# ---------------------------------------------------------------------------
# Budget cap
# ---------------------------------------------------------------------------

def test_budget_exhausted_halts_before_generation(seeded_db, monkeypatch):
    """Budget already exceeded → halt before querying candidates."""
    monkeypatch.setenv("HUNTER_DAILY_BUDGET_USD", "0.001")

    conn = get_conn(seeded_db)
    today = date.today().isoformat()
    # A pre-existing pocs row that consumes more than the budget
    cid2 = _insert_candidate(conn, file_path="plugin2.php", line_start=20, line_end=22)
    _insert_triage(conn, cid2, verdict="real")
    conn.execute(
        "INSERT INTO pocs (candidate_id, status, confidence, unverifiable_reason, "
        "tokens_used, cost_usd, generated_at) "
        "VALUES (?, 'ready', 'high', '', 500, 0.01, ?)",
        (cid2, f"{today}T00:00:00+00:00"),
    )
    conn.commit()

    client = MagicMock()
    result = run_poc("test-plugin", db_path=seeded_db, client=client)

    assert client.messages.create.call_count == 0
    assert result["total"] == 0


def test_budget_cap_halts_mid_run(seeded_db, monkeypatch):
    """First candidate is processed; second is stopped when its cost exceeds budget."""
    monkeypatch.setenv("HUNTER_DAILY_BUDGET_USD", "0.001")

    conn = get_conn(seeded_db)
    cid2 = _insert_candidate(conn, file_path="plugin2.php", line_start=20, line_end=22)
    _insert_triage(conn, cid2, verdict="real")
    conn.commit()

    # One response for the first candidate (high cost > budget). Second call
    # either never happens (mid-run halt) or raises StopIteration (also stops).
    client = _mock_client(_FakeResponse(
        _ready_input(),
        input_tokens=10_000,
        output_tokens=5_000,
    ))

    result = run_poc("test-plugin", db_path=seeded_db, client=client)

    # At least the first candidate was processed
    assert client.messages.create.call_count >= 1
    assert result["total"] >= 1


# ---------------------------------------------------------------------------
# Prompt routing — correct template per rule_id
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id,expected_stem", [
    ("wp-sqli",                  "poc_sqli"),
    ("wp-reflected-xss",         "poc_xss"),
    ("wp-missing-nonce-check",   "poc_csrf"),
    ("wp-missing-cap-check",     "poc_cap_check"),
    ("wp-arbitrary-file-upload", "poc_file_upload"),
    ("wp-path-traversal",        "poc_path_traversal"),
    ("wp-php-object-injection",  "poc_php_oi"),
    ("wp-ssrf",                  "poc_ssrf"),
    ("wp-unknown-rule",          "poc_generic"),
])
def test_prompt_routed_to_correct_template(tmp_db, monkeypatch, rule_id, expected_stem):
    from hunter import poc_generator as poc_mod

    loaded: list[str] = []
    original = poc_mod._load_template

    def _spy(rid: str) -> str:
        loaded.append(rid)
        return original(rid)

    monkeypatch.setattr(poc_mod, "_load_template", _spy)

    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    cid = _insert_candidate(conn, rule_id=rule_id)
    _insert_triage(conn, cid, verdict="real")
    conn.commit()

    client = _mock_client(_FakeResponse(_unverifiable_input()))
    run_poc("test-plugin", db_path=tmp_db, client=client)

    assert loaded == [rule_id]

    from hunter.poc_generator import _PROMPTS_DIR, _RULE_PROMPT
    stem = _RULE_PROMPT.get(rule_id, "poc_generic")
    assert stem == expected_stem
    assert (_PROMPTS_DIR / f"{stem}.md").exists()
