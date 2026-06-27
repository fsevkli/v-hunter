"""
Recall benchmark — run all 8 WP-Hunter rules against the CVE plugin set and
compare finding counts against a stored baseline.

Usage
-----
  python benchmarks/recall_benchmark.py           # compare vs baseline
  python benchmarks/recall_benchmark.py --update  # regenerate baseline file

Exit codes
----------
  0  all counts within threshold (or --update succeeded)
  1  one or more counts dropped > THRESHOLD_PCT vs baseline
  2  no plugins found under validation/plugins/
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

ROOT        = Path(__file__).parent.parent
RULES_DIR   = ROOT / "rules"
PLUGINS_DIR = ROOT / "validation" / "plugins"
BASELINE    = Path(__file__).parent / "recall.json"

THRESHOLD_PCT = 33   # regression if count drops more than this %

RULE_IDS = [
    "wp-missing-nonce-check",
    "wp-missing-cap-check",
    "wp-sqli",
    "wp-reflected-xss",
    "wp-arbitrary-file-upload",
    "wp-path-traversal",
    "wp-php-object-injection",
    "wp-ssrf",
]

SHORT = {
    "wp-missing-nonce-check":      "NONCE",
    "wp-missing-cap-check":        "CAP",
    "wp-sqli":                     "SQLI",
    "wp-reflected-xss":            "XSS",
    "wp-arbitrary-file-upload":    "UPLOAD",
    "wp-path-traversal":           "PATH",
    "wp-php-object-injection":     "POI",
    "wp-ssrf":                     "SSRF",
}

# ANSI colours (disabled on Windows without ANSI support or when not a tty)
_USE_COLOR = sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR")
_RED    = "\033[91m" if _USE_COLOR else ""
_GREEN  = "\033[92m" if _USE_COLOR else ""
_YELLOW = "\033[93m" if _USE_COLOR else ""
_RESET  = "\033[0m"  if _USE_COLOR else ""

# ---------------------------------------------------------------------------
# Semgrep helpers (same rglob+batching pattern as static_filter.py)
# ---------------------------------------------------------------------------

def _find_semgrep() -> str:
    via_path = shutil.which("semgrep")
    if via_path:
        return via_path
    fallbacks = [
        os.environ.get("SEMGREP_BIN", ""),
        "/usr/local/bin/semgrep",
        "/usr/bin/semgrep",
    ]
    for f in fallbacks:
        if f and Path(f).exists():
            return f
    return "semgrep"


def _semgrep_env() -> dict:
    env    = os.environ.copy()
    bindir = str(Path(_find_semgrep()).parent)
    if bindir and bindir not in env.get("PATH", ""):
        env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    return env


def _scan_once(plugin_path: Path) -> dict[str, int]:
    """Single semgrep pass. Returns {rule_id: count}."""
    php_files = [str(p) for p in plugin_path.rglob("*.php")]
    if not php_files:
        return {rid: 0 for rid in RULE_IDS}

    cmd_prefix = [
        _find_semgrep(),
        "--config", str(RULES_DIR),
        "--json",
        "--no-rewrite-rule-ids",
        "--quiet",
    ]
    prefix_chars  = sum(len(a) + 1 for a in cmd_prefix)
    max_file_chars = 28_000 - prefix_chars

    all_results: list[dict] = []
    batch:       list[str]  = []
    batch_chars = 0

    def _flush() -> None:
        if not batch:
            return
        result = subprocess.run(
            cmd_prefix + batch,
            capture_output=True, timeout=300, env=_semgrep_env(),
        )
        try:
            data = json.loads(result.stdout.decode("utf-8", errors="replace"))
            all_results.extend(data.get("results", []))
        except Exception:
            pass

    for fpath in php_files:
        flen = len(fpath) + 1
        if batch and batch_chars + flen > max_file_chars:
            _flush()
            batch, batch_chars = [], 0
        batch.append(fpath)
        batch_chars += flen
    _flush()

    counts = {rid: 0 for rid in RULE_IDS}
    for f in all_results:
        rid = f.get("check_id", "")
        if rid in counts:
            counts[rid] += 1
    return counts


def _scan(plugin_path: Path, runs: int = 3) -> dict[str, int]:
    """Run semgrep *runs* times and return the per-rule maximum.

    Semgrep's taint engine is non-deterministic: the same plugin can yield
    different finding counts across runs.  Taking the maximum stabilises the
    baseline against that variance so a single unlucky low run doesn't flag a
    false regression.
    """
    maxima: dict[str, int] = {rid: 0 for rid in RULE_IDS}
    for _ in range(runs):
        counts = _scan_once(plugin_path)
        for rid, n in counts.items():
            if n > maxima[rid]:
                maxima[rid] = n
    return maxima


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------

def _discover_plugins() -> list[tuple[str, str, Path]]:
    """
    Return [(slug, version, path), ...] sorted by slug/version,
    discovering all slug/version subdirectories under PLUGINS_DIR.
    """
    entries = []
    if not PLUGINS_DIR.exists():
        return entries
    for slug_dir in sorted(PLUGINS_DIR.iterdir()):
        if not slug_dir.is_dir():
            continue
        for ver_dir in sorted(slug_dir.iterdir()):
            if ver_dir.is_dir() and any(ver_dir.rglob("*.php")):
                entries.append((slug_dir.name, ver_dir.name, ver_dir))
    return entries


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------

def _load_baseline() -> dict:
    if not BASELINE.exists():
        return {}
    with BASELINE.open(encoding="utf-8") as fh:
        return json.load(fh)


def _save_baseline(data: dict) -> None:
    with BASELINE.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"Baseline written -> {BASELINE}")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _fmt_count(current: int, baseline: int | None) -> str:
    """Format one cell, colouring regressions."""
    cell = str(current) if current else "."
    if baseline is None:
        return f"{_YELLOW}{cell}{_RESET}"   # new (no baseline)
    drop_pct = (baseline - current) / baseline * 100 if baseline > 0 else 0
    if drop_pct > THRESHOLD_PCT:
        return f"{_RED}{cell}v{_RESET}"    # regression
    if current > baseline:
        return f"{_GREEN}{cell}^{_RESET}"  # improvement
    return cell


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def run(update: bool) -> int:
    plugins = _discover_plugins()
    if not plugins:
        print(f"No plugins found under {PLUGINS_DIR}")
        return 2

    print(f"Found {len(plugins)} plugin version(s) under {PLUGINS_DIR}\n")

    # Scan all (3 runs each, take max per rule to stabilise against taint non-determinism)
    results: dict[str, dict[str, int]] = {}   # key = "slug/ver"
    for slug, ver, path in plugins:
        key = f"{slug}/{ver}"
        print(f"  scanning {key} (3 runs, taking max) ...", flush=True)
        results[key] = _scan(path, runs=3)

    if update:
        baseline_data = {
            "_meta": {
                "generated":     str(date.today()),
                "threshold_pct": THRESHOLD_PCT,
                "scan_runs":     3,
                "notes": (
                    "Counts are the per-rule MAXIMUM across 3 semgrep runs "
                    "(rglob+batching, no git-ls-files). Using max-of-3 stabilises "
                    "against taint-engine non-determinism. The 33% drop threshold "
                    "absorbs remaining run-to-run variance."
                ),
            },
        }
        baseline_data.update(results)
        _save_baseline(baseline_data)
        return 0

    # Compare
    baseline = _load_baseline()
    header_cols = " ".join(f"{SHORT[r]:7s}" for r in RULE_IDS)
    header = f"{'Plugin/Ver':48s} {header_cols}"
    print("\n" + header)
    print("-" * len(header))

    any_regression = False
    for slug, ver, _ in plugins:
        key       = f"{slug}/{ver}"
        current   = results[key]
        base_row  = baseline.get(key)  # None if not in baseline

        # Skip rows that are all zeros and no baseline (new/clean plugins with no hits)
        if all(v == 0 for v in current.values()) and (
            base_row is None or all(v == 0 for v in base_row.values())
        ):
            cells = " ".join(f"{'.':<7s}" for _ in RULE_IDS)
        else:
            cells_list = []
            for rid in RULE_IDS:
                c = current[rid]
                b = base_row[rid] if isinstance(base_row, dict) else None
                cells_list.append(f"{_fmt_count(c, b):<7s}")
                if isinstance(b, int) and b > 0:
                    drop_pct = (b - c) / b * 100
                    if drop_pct > THRESHOLD_PCT:
                        any_regression = True
            cells = " ".join(cells_list)

        print(f"{key[:48]:48s} {cells}")

    # Summary
    print()
    if any_regression:
        print(f"{_RED}REGRESSION: one or more counts dropped >{THRESHOLD_PCT}% vs baseline.{_RESET}")
        return 1
    print(f"{_GREEN}OK — all counts within {THRESHOLD_PCT}% of baseline.{_RESET}")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true",
                        help="Regenerate recall.json from current scan results.")
    args = parser.parse_args()
    sys.exit(run(args.update))
