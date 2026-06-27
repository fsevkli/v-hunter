"""
Auto-hunt v3: discover + ingest + semgrep-scan via the existing hunter
pipeline (all 14 rules: SQLi, XSS, SSRF, IDOR, path-traversal, php-object-
injection, file-upload, missing-cap, missing-nonce, meta-key, ssti, etc.).

For each plugin we:
  1. discover via scripts.discover_targets (>=1K installs floor)
  2. ingest
  3. run_scan
  4. read back HIGH/ERROR candidates -> append to FLAGS file
  5. mark in manual_reviews
  6. delete the source dir

20 iterations x 5 plugins/iter = 100 plugins.

Usage: python scripts/auto_hunt_v3.py [iterations]
"""
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

from hunter.db import get_conn, migrate
from hunter.static_filter import run_scan

LOG = ROOT / "scripts" / "auto_hunt_v3_log.txt"
FLAGS = ROOT / "scripts" / "auto_hunt_v3_flags.txt"
ITERATIONS = int(sys.argv[1]) if len(sys.argv) > 1 else 20
PER_ITER = 5

LOG.write_text(f"=== auto-hunt v3 start {datetime.now().isoformat()} ===\n", encoding="utf-8")
FLAGS.write_text("", encoding="utf-8")

def log(msg: str) -> None:
    print(msg, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def flag(msg: str) -> None:
    with open(FLAGS, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

migrate()

for it in range(1, ITERATIONS + 1):
    log(f"\n===== iteration {it}/{ITERATIONS} =====")
    t0 = time.time()

    # Discover (writes downloaded plugins to plugins/)
    try:
        subprocess.run(
            ["python", "scripts/discover_targets.py", "--limit", str(PER_ITER)],
            check=False, timeout=600,
        )
    except Exception as e:
        log(f"  [discover] exception: {e}")
        continue

    plugins_dir = ROOT / "plugins"
    if not plugins_dir.exists():
        log("  [discover] no plugins/ dir, skipping")
        continue

    slugs = [p.name for p in plugins_dir.iterdir() if p.is_dir()]
    log(f"  discovered: {slugs}")

    for slug in slugs:
        ppath = plugins_dir / slug
        try:
            log(f"  -> scanning {slug}")
            inserted = run_scan(plugin_slug=slug, plugin_path=ppath)
            log(f"     inserted {inserted} candidates")
        except Exception as e:
            log(f"     [scan] {slug} exception: {e}")

        # Pull HIGH/ERROR severity findings for this plugin
        conn = get_conn()
        rows = conn.execute(
            """SELECT rule_id, file_path, line_start, semgrep_severity
               FROM candidates
               WHERE plugin_slug=? AND semgrep_severity IN ('ERROR','WARNING')
               ORDER BY semgrep_severity DESC, rule_id""",
            (slug,),
        ).fetchall()

        # Look up installs via WP.org
        installs = "?"
        try:
            import json, urllib.request
            with urllib.request.urlopen(
                f"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug={slug}",
                timeout=10,
            ) as r:
                installs = json.load(r).get("active_installs", "?")
        except Exception:
            pass

        if rows:
            flag(f"\n[FLAG][iter={it}][installs={installs}] {slug}")
            for r in rows:
                flag(f"  {r['semgrep_severity']:<7} {r['rule_id']:<40} {r['file_path']}:{r['line_start']}")
            flag("---")
            log(f"     FLAGGED ({len(rows)} hits, installs={installs})")
        else:
            log(f"     clean (installs={installs})")

        # Record review + delete dir
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT OR IGNORE INTO plugins (slug) VALUES (?)", (slug,))
        conn.execute(
            """INSERT OR REPLACE INTO manual_reviews
                   (plugin_slug, reviewed_at, verdict, notes, source_deleted_at)
               VALUES (?,?,?,?,?)""",
            (slug, now, f"auto_v3_iter_{it}",
             f"v3 semgrep: hits={len(rows)} installs={installs}", now),
        )
        conn.commit()
        shutil.rmtree(ppath, ignore_errors=True)

    log(f"  iter {it} took {time.time()-t0:.0f}s")

log(f"\n=== done {datetime.now().isoformat()} ===")
