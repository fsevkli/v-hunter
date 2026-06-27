import os
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Base schema. New tables added here ship as part of the next migration step
# (see _MIGRATIONS) so existing databases get them via the version table,
# not via re-execution of the whole SCHEMA on every connect.
SCHEMA = """
CREATE TABLE IF NOT EXISTS plugins (
    slug TEXT PRIMARY KEY,
    name TEXT,
    version TEXT,
    active_installs INTEGER,
    last_updated TEXT,
    source_path TEXT,
    ingested_at TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_slug TEXT NOT NULL,
    rule_id TEXT,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT,
    semgrep_severity TEXT,
    created_at TEXT,
    FOREIGN KEY (plugin_slug) REFERENCES plugins(slug)
);

CREATE TABLE IF NOT EXISTS triage (
    candidate_id INTEGER PRIMARY KEY,
    verdict TEXT,
    reachability TEXT,
    reasoning TEXT,
    poc_outline TEXT,
    confidence TEXT,
    tokens_used INTEGER,
    cost_usd REAL,
    triaged_at TEXT,
    FOREIGN KEY (candidate_id) REFERENCES candidates(id)
);

CREATE TABLE IF NOT EXISTS pocs (
    candidate_id INTEGER PRIMARY KEY,
    poc_script TEXT,
    expected_impact TEXT,
    generated_at TEXT
);

CREATE TABLE IF NOT EXISTS verifications (
    candidate_id INTEGER PRIMARY KEY,
    status TEXT,
    request_log TEXT,
    response_log TEXT,
    side_effects TEXT,
    verified_at TEXT
);

CREATE TABLE IF NOT EXISTS reviews (
    candidate_id INTEGER PRIMARY KEY,
    decision TEXT,
    reviewer_notes TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);
"""


# ---------------------------------------------------------------------------
# Migrations
#
# Each entry: (version, description, sql_or_callable).
# - SQL strings run as conn.executescript().
# - Callables receive the connection and may run arbitrary logic.
# Versions MUST be monotonically increasing. Already-applied versions are
# skipped — this is recorded in schema_version, so the same database can be
# re-opened safely from any point.
#
# DO NOT edit a published migration. Add a new one instead.
# ---------------------------------------------------------------------------
_MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "Initial additive columns (formerly try/except ALTER TABLE block)",
        """
        ALTER TABLE triage ADD COLUMN confidence TEXT;
        ALTER TABLE candidates ADD COLUMN taint_trace TEXT;
        ALTER TABLE pocs ADD COLUMN http_method TEXT;
        ALTER TABLE pocs ADD COLUMN url_path TEXT;
        ALTER TABLE pocs ADD COLUMN headers TEXT;
        ALTER TABLE pocs ADD COLUMN body_params TEXT;
        ALTER TABLE pocs ADD COLUMN expected_signature TEXT;
        ALTER TABLE pocs ADD COLUMN signature_type TEXT;
        ALTER TABLE pocs ADD COLUMN confidence TEXT;
        ALTER TABLE pocs ADD COLUMN unverifiable_reason TEXT;
        ALTER TABLE pocs ADD COLUMN status TEXT;
        ALTER TABLE pocs ADD COLUMN tokens_used INTEGER;
        ALTER TABLE pocs ADD COLUMN cost_usd REAL;
        ALTER TABLE verifications ADD COLUMN reason TEXT;
        """,
    ),
    (
        2,
        "Triager escalation: record which model produced the final verdict",
        """
        ALTER TABLE triage ADD COLUMN model_used TEXT;
        ALTER TABLE triage ADD COLUMN escalated_from TEXT;
        """,
    ),
    (
        3,
        "Verifier: per-class verification modes",
        """
        ALTER TABLE pocs ADD COLUMN verification_mode TEXT;
        ALTER TABLE verifications ADD COLUMN mode TEXT;
        ALTER TABLE verifications ADD COLUMN evidence TEXT;
        """,
    ),
    (
        4,
        "Coverage tracking: per-run funnel counters",
        """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            stage TEXT NOT NULL,
            plugin_slug TEXT,
            raw_findings INTEGER DEFAULT 0,
            inserted_candidates INTEGER DEFAULT 0,
            pre_filter_killed INTEGER DEFAULT 0,
            llm_real INTEGER DEFAULT 0,
            llm_fp INTEGER DEFAULT 0,
            llm_needs_context INTEGER DEFAULT 0,
            llm_escalated INTEGER DEFAULT 0,
            pocs_generated INTEGER DEFAULT 0,
            sandbox_confirmed INTEGER DEFAULT 0,
            sandbox_unverifiable INTEGER DEFAULT 0,
            cost_usd REAL DEFAULT 0.0,
            notes TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_runs_stage_plugin
            ON runs(stage, plugin_slug, started_at);
        """,
    ),
    (
        5,
        "Manual-review pipeline: targeted discovery + per-plugin review log",
        """
        CREATE TABLE IF NOT EXISTS manual_reviews (
            plugin_slug TEXT PRIMARY KEY,
            version_reviewed TEXT,
            reviewed_at TEXT,
            promise_score INTEGER,
            verdict TEXT,
            reachable_role TEXT,
            vuln_class TEXT,
            file_line TEXT,
            notes TEXT,
            source_deleted_at TEXT,
            FOREIGN KEY (plugin_slug) REFERENCES plugins(slug)
        );
        CREATE INDEX IF NOT EXISTS idx_manual_reviews_verdict
            ON manual_reviews(verdict);
        """,
    ),
]


def _db_path() -> str:
    return os.environ.get("HUNTER_DB_PATH", str(PROJECT_ROOT / "hunter.db"))


def get_conn(db_path: str | None = None) -> sqlite3.Connection:
    """Open a connection with WAL journaling and foreign-key enforcement.

    WAL allows concurrent readers + one writer, so the sandbox worker writing
    verification rows while the triager reads candidates is safe (previously
    a `database is locked` waiting to happen on rollback journal mode).
    """
    conn = sqlite3.connect(db_path or _db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL: enables concurrent readers + one writer; survives crashes via the
    # -wal/-shm sidecar files. Idempotent — re-setting on every open is fine.
    conn.execute("PRAGMA journal_mode = WAL")
    # synchronous=NORMAL is the recommended pairing with WAL: safe across
    # process crashes (FULL would survive OS crashes too, at a perf cost).
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def _applied_versions(conn: sqlite3.Connection) -> set[int]:
    try:
        rows = conn.execute("SELECT version FROM schema_version").fetchall()
    except sqlite3.OperationalError:
        return set()
    return {r[0] for r in rows}


def _split_sql_statements(sql: str) -> list[str]:
    """Split a SQL script into individual statements on top-level `;`.

    Naive split is sufficient for our migrations — they're plain DDL with no
    string literals containing semicolons. Multi-statement CREATE TABLE blocks
    are kept intact because their inner `;`-less commas don't appear here.
    """
    parts = [s.strip() for s in sql.split(";")]
    return [p for p in parts if p]


def migrate(db_path: str | None = None) -> None:
    """Apply all pending migrations.

    The base SCHEMA is executed on every call (CREATE TABLE IF NOT EXISTS is
    idempotent). Versioned migrations from _MIGRATIONS run once each, recorded
    in schema_version so the same DB can be re-opened safely from any point.

    Each migration is split into individual statements and run with per-
    statement error handling — so a `duplicate column` on one ALTER doesn't
    abort the remaining ALTERs in the same migration block.
    """
    with get_conn(db_path) as conn:
        conn.executescript(SCHEMA)

        applied = _applied_versions(conn)
        for version, description, sql in _MIGRATIONS:
            if version in applied:
                continue
            for stmt in _split_sql_statements(sql):
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError as e:
                    # 'duplicate column name' / 'table already exists' are
                    # idempotency hits — keep going. Anything else is real.
                    msg = str(e).lower()
                    if ("duplicate column name" in msg
                            or "already exists" in msg):
                        continue
                    raise
            conn.execute(
                "INSERT INTO schema_version (version, description) VALUES (?, ?)",
                (version, description),
            )
        conn.commit()


def current_schema_version(db_path: str | None = None) -> int:
    """Return the highest migration version applied to the DB (0 if none)."""
    with get_conn(db_path) as conn:
        try:
            row = conn.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            return int(row[0]) if row and row[0] is not None else 0
        except sqlite3.OperationalError:
            return 0
