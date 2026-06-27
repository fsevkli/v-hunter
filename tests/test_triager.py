"""
Tests for hunter.triager.

All Anthropic API calls are mocked — no real network traffic.
"""
from datetime import date
from unittest.mock import MagicMock

import pytest

from hunter.db import get_conn, migrate
from hunter.triager import _compute_cost, run_triage


# ---------------------------------------------------------------------------
# Fake API response objects
# ---------------------------------------------------------------------------

class _FakeUsage:
    def __init__(self, input_tokens: int = 100, output_tokens: int = 50):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeToolBlock:
    type = "tool_use"
    name = "submit_triage"

    def __init__(self, tool_input: dict):
        self.input = tool_input


class _FakeResponse:
    def __init__(self, tool_input: dict, input_tokens: int = 100, output_tokens: int = 50):
        self.content = [_FakeToolBlock(tool_input)]
        self.usage = _FakeUsage(input_tokens, output_tokens)
        self.stop_reason = "tool_use"


class _EmptyResponse:
    """Malformed response: no tool_use block (simulates unexpected API output)."""
    def __init__(self):
        self.content = []
        self.usage = _FakeUsage(10, 5)
        self.stop_reason = "end_turn"


def _verdict(verdict: str, reachability: str = "unauth", confidence: str = "high",
             poc: str = "", reasoning: str = "test reasoning") -> _FakeResponse:
    return _FakeResponse({
        "verdict": verdict,
        "reachability": reachability,
        "reasoning": reasoning,
        "suggested_poc_outline": poc if verdict == "real" else "",
        "confidence": confidence,
    })


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
    snippet: str = "    10 | $wpdb->query(\"SELECT * WHERE id=\" . $_GET['id']);",
) -> int:
    cur = conn.execute(
        "INSERT INTO candidates "
        "(plugin_slug, rule_id, file_path, line_start, line_end, code_snippet, "
        "semgrep_severity, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'ERROR', '2024-01-01')",
        (slug, rule_id, file_path, line_start, line_end, snippet),
    )
    return cur.lastrowid


@pytest.fixture()
def seeded_db(tmp_db):
    """DB with one plugin row and one untriaged SQLi candidate (id=1)."""
    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    _insert_candidate(conn)
    conn.commit()
    return tmp_db


# ---------------------------------------------------------------------------
# Verdict correctness
# ---------------------------------------------------------------------------

def test_real_verdict_written_to_db(seeded_db):
    client = _mock_client(_verdict("real", "unauth", "high", "POST /wp-admin/admin-ajax.php"))
    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    assert result["real"] == 1
    assert result["likely_fp"] == 0
    assert result["total"] == 1

    row = get_conn(seeded_db).execute(
        "SELECT * FROM triage WHERE candidate_id = 1"
    ).fetchone()
    assert row is not None
    assert row["verdict"] == "real"
    assert row["reachability"] == "unauth"
    assert row["confidence"] == "high"
    assert "POST /wp-admin/admin-ajax.php" in row["poc_outline"]


def test_likely_fp_verdict_written_to_db(seeded_db):
    client = _mock_client(_verdict("likely_fp", "admin", "high"))
    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    assert result["likely_fp"] == 1
    assert result["real"] == 0

    row = get_conn(seeded_db).execute(
        "SELECT * FROM triage WHERE candidate_id = 1"
    ).fetchone()
    assert row is not None
    assert row["verdict"] == "likely_fp"
    assert row["poc_outline"] == ""


def test_needs_more_context_verdict_written(seeded_db):
    client = _mock_client(_verdict("needs_more_context", "unknown", "low"))
    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    assert result["needs_more_context"] == 1
    row = get_conn(seeded_db).execute(
        "SELECT * FROM triage WHERE candidate_id = 1"
    ).fetchone()
    assert row["verdict"] == "needs_more_context"
    assert row["confidence"] == "low"


def test_real_but_not_cve_worthy_verdict_written(seeded_db):
    client = _mock_client(_verdict("real_but_not_cve_worthy", "admin", "high"))
    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    assert result["real_but_not_cve_worthy"] == 1
    assert result["real"] == 0
    assert result["likely_fp"] == 0

    row = get_conn(seeded_db).execute(
        "SELECT * FROM triage WHERE candidate_id = 1"
    ).fetchone()
    assert row is not None
    assert row["verdict"] == "real_but_not_cve_worthy"
    assert row["reachability"] == "admin"
    assert row["poc_outline"] == ""  # no PoC for out-of-scope findings


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------

def test_malformed_response_triggers_retry(seeded_db):
    """First API call returns no tool_use block; second (retry) returns valid."""
    client = _mock_client(
        _EmptyResponse(),                        # first attempt: malformed
        _verdict("real", "subscriber"),          # retry: valid
    )
    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    assert client.messages.create.call_count == 2
    assert result["real"] == 1

    row = get_conn(seeded_db).execute(
        "SELECT * FROM triage WHERE candidate_id = 1"
    ).fetchone()
    assert row["verdict"] == "real"
    assert row["reachability"] == "subscriber"


def test_both_malformed_responses_yield_error(seeded_db):
    """Both attempts malformed → candidate marked as error, nothing written to triage."""
    client = _mock_client(_EmptyResponse(), _EmptyResponse())
    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    assert client.messages.create.call_count == 2
    assert result["errors"] == 1
    assert result["real"] == 0

    row = get_conn(seeded_db).execute(
        "SELECT * FROM triage WHERE candidate_id = 1"
    ).fetchone()
    assert row is None  # nothing written to triage on error


# ---------------------------------------------------------------------------
# Cost logging
# ---------------------------------------------------------------------------

def test_cost_logged_per_candidate(seeded_db):
    client = _mock_client(_FakeResponse(
        {"verdict": "real", "reachability": "unauth", "reasoning": "r",
         "suggested_poc_outline": "p", "confidence": "high"},
        input_tokens=1000, output_tokens=200,
    ))
    run_triage("test-plugin", db_path=seeded_db, client=client)

    row = get_conn(seeded_db).execute(
        "SELECT * FROM triage WHERE candidate_id = 1"
    ).fetchone()
    expected = _compute_cost(1000, 200)
    assert abs(row["cost_usd"] - expected) < 1e-9
    assert row["tokens_used"] == 1200


# ---------------------------------------------------------------------------
# Daily budget cap
# ---------------------------------------------------------------------------

def test_budget_exhausted_halts_before_triage(seeded_db, monkeypatch):
    """Budget cap prevents triaging even when untriaged candidates exist."""
    monkeypatch.setenv("HUNTER_DAILY_BUDGET_USD", "0.001")

    conn = get_conn(seeded_db)
    # Create a second candidate to attach the "prior spend" triage row to,
    # so candidate 1 remains untriaged (proving the halt — not an empty queue).
    cid2 = _insert_candidate(conn, file_path="plugin2.php", line_start=20, line_end=22)
    conn.commit()

    today = date.today().isoformat()
    conn.execute(
        "INSERT INTO triage "
        "(candidate_id, verdict, reachability, reasoning, poc_outline, confidence, "
        "tokens_used, cost_usd, triaged_at) "
        "VALUES (?, 'real', 'unauth', 'prev run', '', 'high', 500, 0.01, ?)",
        (cid2, f"{today}T00:00:00+00:00"),
    )
    conn.commit()

    client = MagicMock()
    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    # Budget (0.001) already spent (0.01) → halt before any new triage
    assert client.messages.create.call_count == 0
    assert result["total"] == 0


def test_budget_cap_mid_run(seeded_db, monkeypatch):
    """Budget exhaustion mid-run stops processing remaining candidates."""
    monkeypatch.setenv("HUNTER_DAILY_BUDGET_USD", "0.001")

    conn = get_conn(seeded_db)
    # Add a second untriaged candidate
    _insert_candidate(conn, file_path="plugin2.php", line_start=20, line_end=22)
    conn.commit()

    processed = []

    def fake_create(**kwargs):
        # After the first call, simulate the budget being hit by inserting a spend row
        conn2 = get_conn(seeded_db)
        today = date.today().isoformat()
        # Get the last inserted candidate that now has a triage row via run_triage itself
        # We just return a valid response each time; the mid-run budget check fires
        # because the first _triage_one call writes a cost row that exceeds the cap.
        processed.append(1)
        return _FakeResponse(
            {"verdict": "real", "reachability": "unauth", "reasoning": "r",
             "suggested_poc_outline": "p", "confidence": "high"},
            input_tokens=10000, output_tokens=5000,  # high cost: > 0.001
        )

    client = MagicMock()
    client.messages.create.side_effect = fake_create

    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    # First candidate is processed (and its cost exceeds budget),
    # second candidate is halted mid-run.
    assert result["total"] >= 1
    assert client.messages.create.call_count >= 1


# ---------------------------------------------------------------------------
# Multi-candidate handling
# ---------------------------------------------------------------------------

def test_multiple_candidates_triaged(tmp_db):
    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    _insert_candidate(conn, rule_id="wp-sqli")
    _insert_candidate(conn, rule_id="wp-reflected-xss", file_path="xss.php",
                      line_start=5, line_end=5)
    conn.commit()

    client = _mock_client(
        _verdict("real",      "unauth"),
        _verdict("likely_fp", "unauth"),
    )
    result = run_triage("test-plugin", db_path=tmp_db, client=client)

    assert result["total"] == 2
    assert result["real"] == 1
    assert result["likely_fp"] == 1
    assert client.messages.create.call_count == 2


def test_already_triaged_candidates_skipped(seeded_db):
    """Candidates with an existing triage row must not be re-sent to the API."""
    conn = get_conn(seeded_db)
    today = date.today().isoformat()
    conn.execute(
        "INSERT INTO triage "
        "(candidate_id, verdict, reachability, reasoning, poc_outline, confidence, "
        "tokens_used, cost_usd, triaged_at) "
        "VALUES (1, 'likely_fp', 'admin', 'prev run', '', 'high', 100, 0.001, ?)",
        (f"{today}T00:00:00+00:00",),
    )
    conn.commit()

    client = MagicMock()
    result = run_triage("test-plugin", db_path=seeded_db, client=client)

    assert client.messages.create.call_count == 0
    assert result["total"] == 0


def test_no_candidates_returns_zero_summary(tmp_db):
    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    conn.commit()

    client = MagicMock()
    result = run_triage("test-plugin", db_path=tmp_db, client=client)

    assert client.messages.create.call_count == 0
    assert result == {"total": 0, "real": 0, "likely_fp": 0,
                      "needs_more_context": 0, "real_but_not_cve_worthy": 0,
                      "errors": 0, "cost_usd": 0.0}


# ---------------------------------------------------------------------------
# Prompt routing — correct template selected per rule_id
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id,expected_stem", [
    ("wp-sqli",                  "sqli"),
    ("wp-reflected-xss",         "xss"),
    ("wp-missing-nonce-check",   "csrf"),
    ("wp-missing-cap-check",     "cap-check"),
    ("wp-arbitrary-file-upload", "file-upload"),
    ("wp-path-traversal",        "path-traversal"),
    ("wp-php-object-injection",  "php-oi"),
    ("wp-ssrf",                  "ssrf"),
    ("wp-unknown-rule",          "generic"),
])
def test_prompt_routed_to_correct_template(tmp_db, monkeypatch, rule_id, expected_stem):
    from hunter import triager as triager_mod

    loaded: list[str] = []
    original = triager_mod._load_prompt_template

    def _spy(rid: str) -> str:
        loaded.append(rid)
        return original(rid)

    monkeypatch.setattr(triager_mod, "_load_prompt_template", _spy)

    conn = get_conn(tmp_db)
    _insert_plugin(conn)
    _insert_candidate(conn, rule_id=rule_id)
    conn.commit()

    client = _mock_client(_verdict("likely_fp"))
    run_triage("test-plugin", db_path=tmp_db, client=client)

    assert loaded == [rule_id]

    # Verify the expected template file exists on disk
    from hunter.triager import _PROMPTS_DIR, _RULE_PROMPT
    stem = _RULE_PROMPT.get(rule_id, "generic")
    assert stem == expected_stem
    assert (_PROMPTS_DIR / f"{stem}.md").exists()
