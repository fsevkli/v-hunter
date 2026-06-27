"""
batch_pipeline_v2.py

Run the full pipeline (ingest -> scan -> triage -> poc) on the fresh
plugin slugs discovered by discover_clean_plugins.py.

Reads slugs from scripts/clean_plugin_slugs.json (populated by the
discovery script); falls back to the SLUGS list if the file is absent.

Usage:
    python scripts/batch_pipeline_v2.py
"""
import json
import sys
import time
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

from hunter.ingestor import run_ingest
from hunter.static_filter import run_scan
from hunter.triager import run_triage
from hunter.poc_generator import run_poc
from hunter.db import get_conn

# Load slugs from discovery output when available
_slugs_file = Path(__file__).parent.parent / "scripts" / "clean_plugin_slugs.json"
if _slugs_file.exists():
    SLUGS = json.loads(_slugs_file.read_text())
    print(f"[batch] loaded {len(SLUGS)} slugs from {_slugs_file.name}")
else:
    print(f"[batch] WARNING: {_slugs_file} not found – using hardcoded fallback")
    SLUGS = []   # filled in below if discovery ran


def pipeline_one(slug: str) -> dict:
    t0 = time.time()
    print(f"\n{'='*60}")
    print(f"[batch] {slug}")
    print(f"{'='*60}")

    print(f"[batch] {slug} -> ingest")
    run_ingest(slugs=slug)

    print(f"[batch] {slug} -> scan")
    run_scan(plugin_slug=slug)

    print(f"[batch] {slug} -> triage")
    run_triage(plugin_slug=slug)

    print(f"[batch] {slug} -> poc")
    run_poc(plugin_slug=slug)

    conn = get_conn()
    candidates = conn.execute(
        "SELECT COUNT(*) FROM candidates WHERE plugin_slug=?", (slug,)
    ).fetchone()[0]
    real = conn.execute(
        """SELECT COUNT(*) FROM triage t
           JOIN candidates c ON c.id=t.candidate_id
           WHERE c.plugin_slug=? AND t.verdict='real'""",
        (slug,),
    ).fetchone()[0]
    ready_pocs = conn.execute(
        """SELECT COUNT(*) FROM pocs p
           JOIN candidates c ON c.id=p.candidate_id
           WHERE c.plugin_slug=? AND p.status='ready'""",
        (slug,),
    ).fetchone()[0]
    elapsed = time.time() - t0
    print(
        f"[batch] {slug} done in {elapsed:.0f}s - "
        f"candidates={candidates} real={real} ready_pocs={ready_pocs}"
    )
    return {"slug": slug, "candidates": candidates, "real": real, "ready_pocs": ready_pocs}


def main():
    if not SLUGS:
        print("[batch] No slugs to process. Run discover_clean_plugins.py first.")
        sys.exit(1)

    results = []
    failed  = []

    for slug in SLUGS:
        try:
            r = pipeline_one(slug)
            results.append(r)
        except Exception as exc:
            print(f"[batch] ERROR {slug}: {exc}")
            failed.append(slug)

    print(f"\n{'='*60}")
    print("BATCH SUMMARY")
    print(f"{'='*60}")
    total_real = sum(r["real"] for r in results)
    total_pocs = sum(r["ready_pocs"] for r in results)
    for r in results:
        flag = " *** FINDINGS ***" if r["ready_pocs"] > 0 else ""
        print(
            f"  {r['slug']:<50} cands={r['candidates']:>3} "
            f"real={r['real']:>2} pocs={r['ready_pocs']:>2}{flag}"
        )
    if failed:
        print(f"\nFailed: {failed}")
    print(f"\nTotal real findings: {total_real}")
    print(f"Total ready PoCs:    {total_pocs}")
    print("\nRun verify with: python -c \"from hunter.cli import cli; cli()\" -- verify --all-ready")


if __name__ == "__main__":
    main()
