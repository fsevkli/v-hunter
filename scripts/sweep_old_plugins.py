"""
One-shot: clean up plugins/ directories from prior pipeline runs.

For every plugin in the `plugins` table that does NOT already have a
manual_reviews row:
  - Classify the verdict by what the LLM pipeline produced:
      'pipelined_real_unconfirmed' if any triage row says verdict='real'
      'submitted_or_closed'        if slug is in HARD_OFFLIMITS
      'pipelined_no_finding'       otherwise
  - INSERT a manual_reviews row (preserves the slug so discover_targets skips it)
  - rm -rf plugins/<slug> (free disk)
  - Set source_deleted_at = now

The 25 new plugins from the most recent discover_targets run already have
manual_reviews rows (with verdict NULL) and are NOT touched.
"""
import shutil
from datetime import datetime, timezone
from pathlib import Path

from hunter.db import get_conn

HARD_OFFLIMITS = {
    "bookingpress-appointment-booking",
    "multiple-page-generator-plugin-mpg",
    "timetics",
    "storegrowth-sales-booster",
    "ai-copilot-content-generator",
    "legal-texts-connector-it-recht-kanzlei",
    "wp-statistics",
}


def main() -> None:
    now = datetime.now(timezone.utc).isoformat()

    with get_conn() as conn:
        # Plugins already tracked in manual_reviews (the new batch, plus any
        # prior reviews) — never sweep these.
        protected = {
            r["plugin_slug"]
            for r in conn.execute("SELECT plugin_slug FROM manual_reviews").fetchall()
        }

        # All ingested plugins
        rows = conn.execute(
            "SELECT slug, version, source_path FROM plugins ORDER BY slug"
        ).fetchall()

        # Slugs that ever produced a `real` triage verdict
        real_slugs = {
            r["plugin_slug"]
            for r in conn.execute("""
                SELECT DISTINCT c.plugin_slug
                FROM candidates c
                JOIN triage t ON t.candidate_id = c.id
                WHERE t.verdict = 'real'
            """).fetchall()
        }

        to_sweep = [r for r in rows if r["slug"] not in protected]
        print(f"plugins total:     {len(rows)}")
        print(f"protected (in manual_reviews): {len(protected)}")
        print(f"to sweep:          {len(to_sweep)}")
        print()

        deleted = kept = 0
        verdict_counts: dict[str, int] = {}

        for row in to_sweep:
            slug = row["slug"]
            version = row["version"] or "unknown"
            src = Path(row["source_path"]) if row["source_path"] else None

            # Classify
            if slug in HARD_OFFLIMITS:
                verdict = "submitted_or_closed"
            elif slug in real_slugs:
                verdict = "pipelined_real_unconfirmed"
            else:
                verdict = "pipelined_no_finding"

            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

            # Delete source if present
            src_deleted_at = None
            if src and src.exists():
                try:
                    shutil.rmtree(src)
                    src_deleted_at = now
                    deleted += 1
                except OSError as e:
                    print(f"  ! could not delete {src}: {e}")

            # Record in manual_reviews so future discovery skips it
            conn.execute(
                """INSERT OR REPLACE INTO manual_reviews
                       (plugin_slug, version_reviewed, reviewed_at,
                        promise_score, verdict, notes, source_deleted_at)
                   VALUES (?, ?, ?, NULL, ?, ?, ?)""",
                (
                    slug, version, now, verdict,
                    "Bulk-archived from prior LLM pipeline runs. "
                    "Source deleted to free disk; slug retained to prevent "
                    "re-ingestion. If a Patchstack-worthy finding turns up "
                    "elsewhere, re-fetch source manually.",
                    src_deleted_at,
                ),
            )

        conn.commit()

    print(f"swept:   {len(to_sweep)}")
    print(f"deleted: {deleted} source directories")
    print()
    print("verdict breakdown:")
    for v, n in sorted(verdict_counts.items()):
        print(f"  {v:30} {n}")


if __name__ == "__main__":
    main()
