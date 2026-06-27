"""
Download plugins and run all 8 WP-Hunter rules against them.
Prints a structured results table.
"""
import io, json, os, shutil, subprocess, sys, time, zipfile
from pathlib import Path
import requests

ROOT     = Path(__file__).parent.parent
RULES    = ROOT / "rules"
BASE     = Path(__file__).parent / "plugins"
SEMGREP  = os.environ.get("SEMGREP_BIN") or shutil.which("semgrep") or "semgrep"
UA       = "wp-hunter-validation/0.1"

# Ensure pysemgrep (a sibling of the semgrep launcher) is findable in subprocess
_ENV = os.environ.copy()
_bindir = os.path.dirname(SEMGREP)
if _bindir:
    _ENV["PATH"] = _bindir + os.pathsep + _ENV.get("PATH", "")

RULE_FILES = [
    "missing-nonce-check.yml",
    "missing-cap-check.yml",
    "sql-injection.yml",
    "reflected-xss.yml",
    "arbitrary-file-upload.yml",
    "path-traversal.yml",
    "php-object-injection.yml",
    "ssrf.yml",
]

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


def fetch(slug: str, version: str) -> Path:
    dest = BASE / slug / version
    if dest.exists() and any(dest.rglob("*.php")):
        return dest
    url = f"https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
    print(f"    downloading {slug} {version} ...", end=" ", flush=True)
    r = requests.get(url, timeout=60, headers={"User-Agent": UA})
    if r.status_code != 200:
        print(f"HTTP {r.status_code}")
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        for m in zf.infolist():
            parts = Path(m.filename).parts
            if len(parts) < 2:
                continue
            rel = Path(*parts[1:])
            tgt = dest / rel
            if m.is_dir():
                tgt.mkdir(parents=True, exist_ok=True)
            else:
                tgt.parent.mkdir(parents=True, exist_ok=True)
                tgt.write_bytes(zf.read(m.filename))
    php = list(dest.rglob("*.php"))
    print(f"ok ({len(php)} PHP files)")
    time.sleep(1)
    return dest


def scan(path: Path) -> dict[str, list[dict]]:
    """Run all rules and return {rule_id: [finding, ...]}.

    PHP files are collected via rglob and passed explicitly to bypass semgrep's
    git-tracking mode (which silently skips untracked plugin directories).
    Files are batched to stay under the Windows CreateProcess argument limit.
    """
    php_files = [str(p) for p in path.rglob("*.php")]
    if not php_files:
        return {rid: [] for rid in RULE_IDS}

    cmd_prefix = [SEMGREP, "--config", str(RULES),
                  "--json", "--no-rewrite-rule-ids", "--quiet"]
    prefix_chars = sum(len(a) + 1 for a in cmd_prefix)
    max_file_chars = 28_000 - prefix_chars

    all_findings: list[dict] = []
    batch: list[str] = []
    batch_chars = 0

    def _flush() -> None:
        if not batch:
            return
        result = subprocess.run(
            cmd_prefix + batch,
            capture_output=True, timeout=180, env=_ENV,
        )
        try:
            data = json.loads(result.stdout.decode("utf-8", errors="replace"))
            all_findings.extend(data.get("results", []))
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

    by_rule: dict[str, list[dict]] = {rid: [] for rid in RULE_IDS}
    for f in all_findings:
        rid = f.get("check_id", "")
        if rid in by_rule:
            by_rule[rid].append({
                "file": str(Path(f["path"]).relative_to(path)),
                "line": f["start"]["line"],
                "snippet": f["extra"].get("lines", "").strip()[:80],
            })
    return by_rule


def count(by_rule: dict) -> dict[str, int]:
    return {rid: len(findings) for rid, findings in by_rule.items()}


if __name__ == "__main__":
    # ------------------------------------------------------------------ #
    # Download plan                                                        #
    # ------------------------------------------------------------------ #
    print("=== Downloading plugins ===")

    cve_plugins = [
        # (slug, vuln_ver, patch_ver, rule_id, notes)
        ("bookingpress-appointment-booking",  "1.0.10", "1.0.11", "wp-sqli",                 "CVE-2022-0739"),
        ("download-manager",                  "3.1.24", "3.1.25", "wp-path-traversal",        "CVE-2021-24239"),
        ("wp-fastest-cache",                  "0.9.4",  None,     "wp-ssrf",                  "ssrf-pattern"),
        ("popup-builder",                     "3.62",   "3.63",   "wp-php-object-injection",  "CVE-2020-10196"),
        ("perfect-survey",                    "1.5.1",  "1.5.2",  "wp-sqli",                  "CVE-2021-24762"),
        ("wp-statistics",                     "13.0.7", "13.0.8", "wp-reflected-xss",         "CVE-2021-24340"),
        ("contact-form-to-db",               "1.5.7",  None,     "wp-arbitrary-file-upload", "upload-pattern"),
    ]

    clean_plugins = [
        ("hello-dolly",    "1.7.2"),
        ("wp-pagenavi",    "2.94.5"),
        ("classic-editor", "1.6.3"),
    ]

    for slug, vuln, patch, _, _ in cve_plugins:
        print(f"  {slug}:")
        fetch(slug, vuln)
        if patch:
            fetch(slug, patch)

    for slug, ver in clean_plugins:
        print(f"  {slug}:")
        fetch(slug, ver)

    # ------------------------------------------------------------------ #
    # Scan CVE plugins                                                     #
    # ------------------------------------------------------------------ #
    print("\n=== Scanning CVE plugins ===")

    short = {
        "wp-missing-nonce-check":      "NONCE",
        "wp-missing-cap-check":        "CAP",
        "wp-sqli":                     "SQLI",
        "wp-reflected-xss":            "XSS",
        "wp-arbitrary-file-upload":    "UPLOAD",
        "wp-path-traversal":           "PATH",
        "wp-php-object-injection":     "POI",
        "wp-ssrf":                     "SSRF",
    }
    header = f"{'Plugin':44s} {'Ver':8s} " + " ".join(f"{short[r]:6s}" for r in RULE_IDS)
    print(header)
    print("-" * len(header))

    cve_results = {}   # (slug, ver) -> by_rule
    for slug, vuln, patch, _, label in cve_plugins:
        for ver in ([vuln] + ([patch] if patch else [])):
            path = BASE / slug / ver
            if not path.exists():
                print(f"  SKIP {slug} {ver}")
                continue
            by_rule = scan(path)
            cve_results[(slug, ver)] = by_rule
            counts = [str(len(by_rule[r])) if len(by_rule[r]) else "." for r in RULE_IDS]
            print(f"{slug[:44]:44s} {ver:8s} " + " ".join(f"{c:6s}" for c in counts))

    # ------------------------------------------------------------------ #
    # Scan clean plugins                                                   #
    # ------------------------------------------------------------------ #
    print("\n=== Scanning clean plugins (false-positive check) ===")
    print(header)
    print("-" * len(header))

    fp_by_rule: dict[str, int] = {r: 0 for r in RULE_IDS}
    for slug, ver in clean_plugins:
        path = BASE / slug / ver
        if not path.exists():
            print(f"  SKIP {slug} {ver}")
            continue
        by_rule = scan(path)
        counts = [str(len(by_rule[r])) if len(by_rule[r]) else "." for r in RULE_IDS]
        print(f"{slug[:44]:44s} {ver:8s} " + " ".join(f"{c:6s}" for c in counts))
        for r in RULE_IDS:
            fp_by_rule[r] += len(by_rule[r])

    print("\nFalse-positive totals across 3 clean plugins:")
    for r in RULE_IDS:
        print(f"  {short[r]:8s} {fp_by_rule[r]}")

    # ------------------------------------------------------------------ #
    # Detail: print first finding per rule for the VULN version           #
    # ------------------------------------------------------------------ #
    print("\n=== First finding per CVE plugin (vulnerable version) ===")
    for slug, vuln, patch, target_rule, label in cve_plugins:
        by_rule = cve_results.get((slug, vuln), {})
        findings = by_rule.get(target_rule, [])
        if findings:
            f = findings[0]
            print(f"  {label} {slug} {vuln}")
            print(f"    rule : {target_rule}")
            print(f"    file : {f['file']}:{f['line']}")
            print(f"    code : {f['snippet']}")
        else:
            print(f"  {label} {slug} {vuln} => {target_rule}: NO MATCH")
            any_hit = [(r, by_rule[r]) for r in RULE_IDS if by_rule.get(r)]
            if any_hit:
                for r, fs in any_hit[:2]:
                    print(f"    (fired: {r} x {len(fs)})")

    # ------------------------------------------------------------------ #
    # Patch regression: confirm patched version no longer fires           #
    # ------------------------------------------------------------------ #
    print("\n=== Patch regression (target rule only) ===")
    for slug, vuln, patch, target_rule, label in cve_plugins:
        if not patch:
            continue
        vuln_hits = len(cve_results.get((slug, vuln), {}).get(target_rule, []))
        patch_hits = len(cve_results.get((slug, patch), {}).get(target_rule, []))
        status = "FIXED" if patch_hits < vuln_hits else ("SAME" if patch_hits == vuln_hits else "MORE?")
        print(f"  {label:20s} {target_rule:28s} vuln={vuln_hits} patch={patch_hits}  {status}")
