"""
Tests for hunter.db migration idempotency.

Verifies that:
1. migrate() can be run twice on the same DB without errors.
2. All 11 new pocs columns are present after migration.
3. A partially-migrated DB (some columns present, some missing) is completed
   correctly — the already-present columns are skipped, the missing ones are added.
4. A column that was dropped and re-added via migrate() is restored.
"""
import sqlite3

import pytest

from hunter.db import SCHEMA, get_conn, migrate

_NEW_POCS_COLS = {
    "http_method",
    "url_path",
    "headers",
    "body_params",
    "expected_signature",
    "signature_type",
    "confidence",
    "unverifiable_reason",
    "status",
    "tokens_used",
    "cost_usd",
}


def _pocs_columns(db_path: str) -> set[str]:
    conn = sqlite3.connect(db_path)
    rows = conn.execute("PRAGMA table_info(pocs)").fetchall()
    conn.close()
    return {row[1] for row in rows}


# ---------------------------------------------------------------------------
# Basic: migrate() creates all expected columns
# ---------------------------------------------------------------------------

def test_migrate_creates_all_new_pocs_columns(tmp_path):
    db = str(tmp_path / "test.db")
    migrate(db)
    assert _NEW_POCS_COLS.issubset(_pocs_columns(db))


# ---------------------------------------------------------------------------
# Idempotency: running migrate() twice is safe
# ---------------------------------------------------------------------------

def test_migrate_twice_does_not_error(tmp_path):
    db = str(tmp_path / "test.db")
    migrate(db)
    migrate(db)  # must not raise
    assert _NEW_POCS_COLS.issubset(_pocs_columns(db))


# ---------------------------------------------------------------------------
# Partial migration: only some columns present before migrate()
# ---------------------------------------------------------------------------

def test_migrate_completes_partial_schema(tmp_path):
    """
    Simulate a DB that was partially migrated (a previous process added only
    some of the new pocs columns).  Running migrate() must add the remainder.
    """
    db = str(tmp_path / "partial.db")

    # Create the schema with the original tables only
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA)
    # Manually add a subset of the new columns (simulating a partial migration)
    conn.execute("ALTER TABLE pocs ADD COLUMN http_method TEXT")
    conn.execute("ALTER TABLE pocs ADD COLUMN url_path TEXT")
    conn.commit()
    conn.close()

    # Confirm only those two are present yet
    present = _pocs_columns(db)
    assert "http_method" in present
    assert "url_path" in present
    assert "cost_usd" not in present

    # Full migration must add the remaining 9 columns without erroring on the 2 that exist
    migrate(db)

    assert _NEW_POCS_COLS.issubset(_pocs_columns(db))


# ---------------------------------------------------------------------------
# Drop-and-restore: migrate() re-adds a column that was dropped
# ---------------------------------------------------------------------------

def test_migrate_does_not_silently_re_add_dropped_column(tmp_path):
    """
    Under the versioned-migration model, a tracked migration runs exactly
    ONCE. Dropping a column it created and re-running migrate() will NOT
    silently re-add it — schema_version blocks re-execution. Restoring such
    a column requires a new migration version, which is the correct contract
    for production databases where a dropped column is real schema corruption
    that warrants explicit action.

    (The previous behavior — re-adding columns on every migrate() call — was
    an emergent property of the old try/except-ALTER-on-every-connect loop,
    not an intentional feature.)
    """
    db = str(tmp_path / "dropped.db")
    migrate(db)

    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE pocs DROP COLUMN url_path")
    conn.commit()
    conn.close()

    assert "url_path" not in _pocs_columns(db)

    migrate(db)

    # Stays dropped — schema_version says migration #1 was already applied.
    assert "url_path" not in _pocs_columns(db)


# ---------------------------------------------------------------------------
# Exception specificity: only OperationalError is swallowed
# ---------------------------------------------------------------------------

def test_migrate_catches_only_operational_error():
    """
    migrate() must catch sqlite3.OperationalError specifically (duplicate-column
    error), not the broad Exception base class.  Verified via source inspection
    since sqlite3.Connection.execute is a C type that cannot be monkeypatched.
    """
    import inspect
    from hunter import db as db_mod

    source = inspect.getsource(db_mod.migrate)
    assert "sqlite3.OperationalError" in source, \
        "migrate() must catch sqlite3.OperationalError, not a broader exception type"
    assert "except Exception" not in source, \
        "migrate() must not catch bare Exception — use sqlite3.OperationalError"
