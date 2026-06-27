"""
Per-run funnel tracking.

Each pipeline stage (scan, triage, verify) opens a Run context manager. The
manager allocates a `runs` table row at __enter__, accumulates counters in
memory while the stage executes, and flushes them all in a single UPDATE at
__exit__. Counter buffering keeps the SQL write rate low — a triage of 200
candidates costs one UPDATE, not 200.

Columns are restricted to a hard-coded allowlist (_VALID_COLS) so a typo or a
hostile caller can't inject SQL into the UPDATE statement.

The `hunter stats --funnel` CLI reads these rows to show the
    raw_findings → pre_filter_killed → inserted → llm_real → confirmed
funnel across runs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from hunter.db import get_conn

# Columns the Run context manager will UPDATE. Anything not in this set is
# silently ignored — protects against typos and SQL injection.
_VALID_COLS: frozenset[str] = frozenset({
    "raw_findings",
    "inserted_candidates",
    "pre_filter_killed",
    "llm_real",
    "llm_fp",
    "llm_needs_context",
    "llm_escalated",
    "pocs_generated",
    "sandbox_confirmed",
    "sandbox_unverifiable",
    "cost_usd",
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Run:
    """Context manager that records a single pipeline-stage execution.

    Usage:
        with Run("scan", plugin_slug="bookingpress") as run:
            run.bump("raw_findings", len(findings))
            for f in findings:
                if pre_filter_hit:
                    run.bump("pre_filter_killed")
                else:
                    run.bump("inserted_candidates")
            run.bump("cost_usd", 0.0)  # scan stage is free

    `stage` is one of: scan, triage, poc, verify (free-form — the schema
    doesn't enforce it, but the CLI filters by these names).
    """

    def __init__(
        self,
        stage: str,
        plugin_slug: str | None = None,
        notes: str = "",
        db_path: str | None = None,
    ) -> None:
        self.stage = stage
        self.plugin_slug = plugin_slug
        self.notes = notes
        self.db_path = db_path  # None = use $HUNTER_DB_PATH default
        self._counters: dict[str, float] = {}
        self.run_id: int | None = None
        # If the runs table doesn't exist (e.g. legacy DB outside the
        # migration path), become a no-op rather than crashing the caller.
        self._disabled = False

    def bump(self, key: str, n: float = 1.0) -> None:
        """Increment the named counter by *n* (default 1). Unknown keys are
        silently dropped so a typo doesn't crash the pipeline mid-scan."""
        if key not in _VALID_COLS:
            return
        self._counters[key] = self._counters.get(key, 0.0) + n

    def __enter__(self) -> "Run":
        import sqlite3
        try:
            with get_conn(self.db_path) as conn:
                cur = conn.execute(
                    "INSERT INTO runs (started_at, stage, plugin_slug, notes) "
                    "VALUES (?, ?, ?, ?)",
                    (_now(), self.stage, self.plugin_slug, self.notes),
                )
                self.run_id = cur.lastrowid
                conn.commit()
        except sqlite3.OperationalError:
            # Legacy DB without the runs table — fall back to no-op so
            # pre-migration code paths and old test fixtures keep working.
            self._disabled = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._disabled:
            return
        # Always flush, even on exceptions — partial counts are useful for
        # debugging a crash mid-scan.
        set_clauses: list[str] = ["ended_at = ?"]
        values: list[object] = [_now()]
        for col, val in self._counters.items():
            if col not in _VALID_COLS:
                continue
            set_clauses.append(f"{col} = ?")
            values.append(val)
        values.append(self.run_id)
        sql = f"UPDATE runs SET {', '.join(set_clauses)} WHERE id = ?"
        with get_conn(self.db_path) as conn:
            conn.execute(sql, values)
            conn.commit()


# ---------------------------------------------------------------------------
# Read-side: aggregate counters for the funnel view
# ---------------------------------------------------------------------------

_FUNNEL_COLS = (
    "raw_findings",
    "inserted_candidates",
    "pre_filter_killed",
    "llm_real",
    "llm_fp",
    "llm_needs_context",
    "llm_escalated",
    "pocs_generated",
    "sandbox_confirmed",
    "sandbox_unverifiable",
)


def funnel_totals(plugin_slug: str | None = None) -> dict[str, float]:
    """Sum all funnel counters across runs.

    If *plugin_slug* is given, restricts to runs for that plugin.
    """
    sql = (
        "SELECT "
        + ", ".join(f"COALESCE(SUM({c}), 0) AS {c}" for c in _FUNNEL_COLS)
        + ", COALESCE(SUM(cost_usd), 0) AS cost_usd "
        "FROM runs "
        + ("WHERE plugin_slug = ?" if plugin_slug else "")
    )
    args: tuple = (plugin_slug,) if plugin_slug else ()
    with get_conn() as conn:
        row = conn.execute(sql, args).fetchone()
    return {k: row[k] for k in (*_FUNNEL_COLS, "cost_usd")}


def recent_runs(limit: int = 20) -> Iterable[dict]:
    """Yield the N most-recent run rows as dicts."""
    sql = (
        "SELECT id, started_at, ended_at, stage, plugin_slug, "
        + ", ".join(_FUNNEL_COLS)
        + ", cost_usd "
        "FROM runs ORDER BY id DESC LIMIT ?"
    )
    with get_conn() as conn:
        for row in conn.execute(sql, (limit,)).fetchall():
            yield dict(row)


def compare_to_ground_truth(ground_truth_path: str) -> dict:
    """Compare confirmed verifications to a ground-truth JSON file.

    Ground-truth shape:
        {
          "plugin-slug": [
              {"rule_id": "wp-sqli", "file": "x.php", "line": 42},
              ...
          ]
        }

    Returns precision / recall / matched / missed / extra counts.
    """
    import json

    with open(ground_truth_path, encoding="utf-8") as f:
        truth = json.load(f)

    flat_truth: set[tuple[str, str, str, int]] = set()
    for slug, items in truth.items():
        for item in items:
            flat_truth.add((slug, item["rule_id"], item["file"], int(item["line"])))

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT c.plugin_slug, c.rule_id, c.file_path, c.line_start "
            "FROM verifications v JOIN candidates c ON c.id = v.candidate_id "
            "WHERE v.status = 'confirmed'"
        ).fetchall()
    confirmed = {
        (r["plugin_slug"], r["rule_id"], r["file_path"], int(r["line_start"]))
        for r in rows
    }

    # Match by (plugin, file, line) — rule_id may differ between the
    # ground-truth label and the rule that actually fired.
    truth_pfl = {(s, f, l) for s, _, f, l in flat_truth}
    conf_pfl  = {(s, f, l) for s, _, f, l in confirmed}

    matched = truth_pfl & conf_pfl
    missed  = truth_pfl - conf_pfl
    extra   = conf_pfl  - truth_pfl

    precision = len(matched) / len(conf_pfl) if conf_pfl else 0.0
    recall    = len(matched) / len(truth_pfl) if truth_pfl else 0.0
    return {
        "matched":   len(matched),
        "missed":    len(missed),
        "extra":     len(extra),
        "precision": precision,
        "recall":    recall,
        "missed_items": sorted(missed),
        "extra_items":  sorted(extra),
    }
