"""
discover_rce_targets.py — find and download plugins with RCE / DB-takeover surface
                          reachable without admin privileges.

LESSON FROM BATCH-1 REVIEW (26 plugins, 0 findings):
  Admin tools (backup, file-manager, database, code-snippets, migration) are
  ALWAYS admin-gated by design. eval/exec/shell_exec inside manage_options is not
  a vulnerability. Every single plugin in that batch was out of scope.

NEW STRATEGY — target FRONTEND-FACING plugins where nopriv AJAX or open REST routes
  handle dangerous operations:
  - Forms / file upload: nopriv handler + move_uploaded_file → webshell
  - WooCommerce extensions: subscriber/nopriv AJAX + $wpdb manipulation
  - Booking / events: nopriv submission + DB write without cap check
  - REST API plugins: permission_callback => '__return_true' + dangerous sink
  - User/membership: nopriv registration + wp_insert_user / role assignment
  - Media / gallery: open REST upload endpoint → arbitrary file write
  - Webhook receivers: unauthenticated POST → eval / include / SQL

Scoring uses TWO signal classes — a plugin needs BOTH to rank high:
  [A] Auth surface  : nopriv_ajax, rest_open, logged_in_only, weak cap check
  [B] Dangerous sink: file upload, eval, unserialize, raw SQL, LFI, exec

A plugin with only [A] or only [B] keeps a low score.
A plugin with both [A]+[B] gets a 2× multiplier and is flagged as priority.

Plugins are downloaded to plugins_rce/<slug>/ for MANUAL code review.
No automated triage — you read the source yourself.

Usage:
    python scripts/discover_rce_targets.py [--limit 20] [--dry-run]
"""
from __future__ import annotations

import argparse
import io
import re
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

from hunter.db import get_conn, migrate

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

WP_API       = "https://api.wordpress.org/plugins/info/1.2/"
DOWNLOADS    = "https://downloads.wordpress.org/plugin"
RATE_LIMIT_S = 0.8

MIN_INSTALLS = 10_000
MAX_INSTALLS = 500_000   # wider band — more popular = more impact
MAX_AGE_DAYS = 730       # skip plugins untouched for 2+ years

OUT_DIR = ROOT / "plugins_rce"   # separate from the automated-pipeline plugins/

# ---------------------------------------------------------------------------
# Tags — frontend-facing categories where unauthenticated/subscriber surface
#         meets dangerous operations (file write, DB manipulation, unserialize).
#
# REMOVED (batch-1 lesson): backup, database, file-manager, code-snippets,
#   migration, clone, phpmyadmin, ssh, ftp — these are admin tools, always
#   gated behind manage_options / install_plugins. Zero exploitable surface.
# ---------------------------------------------------------------------------

RCE_TAGS = [
    # ── Frontend forms & file upload ────────────────────────────────────────
    # CF7/Ninja/WPForms add-ons often register nopriv handlers for submission +
    # file attachment processing. Classic path: nopriv AJAX + move_uploaded_file.
    "contact-form", "forms", "form-builder", "form-addon",
    "quiz", "survey", "poll",
    "file-upload", "document", "attachment",

    # ── WooCommerce / e-commerce ─────────────────────────────────────────────
    # Checkout, cart, and order hooks run as subscriber/nopriv.
    # Extensions frequently mis-check caps or use nopriv nonces on the frontend.
    "woocommerce", "woo", "checkout", "cart", "payment",
    "product", "order", "pricing", "discount", "coupon",
    "shipping", "invoice",

    # ── Booking / appointment / events ───────────────────────────────────────
    # Visitors submit bookings without logging in (nopriv AJAX).
    # Proven class from batch of accepted/dupe findings (truebooker, timetics).
    "booking", "appointment", "reservation", "events",
    "calendar", "scheduling", "availability",

    # ── User registration / membership / login ──────────────────────────────
    # Custom registration flows run as nopriv; profile pages run as subscriber.
    # wp_insert_user / add_cap without proper checks = priv-esc.
    "user-registration", "membership", "registration", "login",
    "social-login", "oauth", "sso", "user-role",

    # ── REST API / webhook / integration ─────────────────────────────────────
    # Plugins that expose REST endpoints or receive external webhooks
    # frequently set permission_callback => '__return_true'.
    "rest-api", "api", "webhook", "integration", "sync",
    "feed", "push-notification", "notification",

    # ── Import / export (subscriber-triggered) ───────────────────────────────
    # Unlike admin import tools, plugins that let subscribers/contributors
    # import their own content (portfolio, product, post) can expose file-upload
    # + unserialize paths to lower roles.
    "import", "export", "csv", "xml",

    # ── Page builder / shortcode / dynamic rendering ─────────────────────────
    # Frontend rendering hooks + variable include / eval for dynamic content.
    "shortcode", "elementor", "page-builder",
    "block", "widget", "dynamic-content",

    # ── Media / gallery / portfolio (frontend upload) ─────────────────────────
    # REST-exposed upload endpoints (e.g. /wp-json/plugin/v1/upload) for
    # gallery/portfolio plugins often accept files without role checks.
    "gallery", "media", "photo", "portfolio",
    "slider", "video", "lightbox",

    # ── Subscription / LMS / course ──────────────────────────────────────────
    # Enrolled students (subscriber) trigger AJAX that manipulates course state,
    # grades, or certificate generation — DB writes at subscriber level.
    "subscription", "lms", "course", "elearning",
    "certificate", "quiz",
]

# ---------------------------------------------------------------------------
# Surface patterns — only RCE and DB-takeover signals
# ---------------------------------------------------------------------------

_RCE_PATTERNS: dict[str, re.Pattern] = {
    # ════════════════════════════════════════════════════════════════════════
    # CLASS A — AUTH SURFACE
    # These signal that dangerous operations may be reachable without admin.
    # Score them high; require at least one to rank a plugin as priority.
    # ════════════════════════════════════════════════════════════════════════

    # Unauthenticated AJAX handler registration
    "nopriv_ajax":        re.compile(r"\bwp_ajax_nopriv_\w+"),

    # Open REST endpoint (no auth)
    "rest_open":          re.compile(r"permission_callback\s*[=:>]+\s*['\"]?__return_true"),
    # REST with inline anonymous function that just returns true
    "rest_no_auth_fn":    re.compile(r"permission_callback[^;]{0,80}function\s*\([^)]*\)\s*\{[^}]{0,40}return\s+true"),

    # Only checks login (not capability) — subscriber-accessible
    "logged_in_only":     re.compile(r"\bis_user_logged_in\s*\(\s*\)"),

    # Subscriber-level capability check (weakest non-nopriv gate)
    "cap_read":           re.compile(r"current_user_can\s*\(\s*['\"]read['\"]"),

    # ════════════════════════════════════════════════════════════════════════
    # CLASS B — DANGEROUS SINKS
    # These are the operations that turn a weak auth check into an RCE or
    # DB-takeover. Require at least one for a plugin to be worth reviewing.
    # ════════════════════════════════════════════════════════════════════════

    # ── Direct code execution ──────────────────────────────────────────────
    "eval":               re.compile(r"\beval\s*\("),
    "exec":               re.compile(r"\bexec\s*\("),
    "shell_exec":         re.compile(r"\bshell_exec\s*\("),
    "system":             re.compile(r"\bsystem\s*\("),
    "passthru":           re.compile(r"\bpassthru\s*\("),
    "popen":              re.compile(r"\bpopen\s*\("),
    "proc_open":          re.compile(r"\bproc_open\s*\("),
    "pcntl_exec":         re.compile(r"\bpcntl_exec\s*\("),
    "assert_str":         re.compile(r"\bassert\s*\(\s*\$"),
    "create_function":    re.compile(r"\bcreate_function\s*\("),
    "preg_replace_e":     re.compile(r"preg_replace\s*\(\s*['\"][^'\"]*\/e['\"]"),

    # ── Dynamic dispatch ──────────────────────────────────────────────────
    "call_user_func":     re.compile(r"\bcall_user_func(?:_array)?\s*\(\s*\$"),
    "variable_function":  re.compile(r"\$\w+\s*\([^)]*\$"),

    # ── File write / upload → webshell ────────────────────────────────────
    "file_put_contents":  re.compile(r"\bfile_put_contents\s*\(\s*\$"),
    "move_uploaded_file": re.compile(r"\bmove_uploaded_file\s*\("),
    "file_upload":        re.compile(r"\$_FILES\s*\["),
    "fwrite":             re.compile(r"\bfwrite\s*\("),
    "copy_file":          re.compile(r"\bcopy\s*\(\s*\$"),

    # ── LFI / RFI ─────────────────────────────────────────────────────────
    "include_var":        re.compile(r"\b(?:include|require)(?:_once)?\s+\$"),
    "include_get_post":   re.compile(r"\b(?:include|require)(?:_once)?\s+.*\$_(?:GET|POST|REQUEST|COOKIE)"),

    # ── PHP object injection ───────────────────────────────────────────────
    "unserialize":        re.compile(r"\bunserialize\s*\("),

    # ── ZIP extraction (arbitrary path write) ─────────────────────────────
    "zip_extract":        re.compile(r"\b(?:ZipArchive|PclZip|zip_open)\b"),
    "zip_extractto":      re.compile(r"->extractTo\s*\("),

    # ── Privilege escalation ──────────────────────────────────────────────
    # User creation or capability grant reached from a low-privilege hook
    # is the signature of a priv-esc (easy-elements class from prev batch).
    "user_create":        re.compile(r"\b(?:wp_insert_user|wp_create_user|wp_update_user)\s*\("),
    "add_cap":            re.compile(r"->add_cap\s*\("),
    "update_wp_caps":     re.compile(r"update_user_meta\s*\([^,]+,\s*['\"]wp_capabilities['\"]"),

    # ── Full DB takeover ──────────────────────────────────────────────────
    "wpdb_raw_query":     re.compile(r"\$wpdb->\s*query\s*\(\s*(?!\s*\$wpdb->prepare)"),
    "wpdb_get_results":   re.compile(r"\$wpdb->get_results\s*\(\s*[\"']?\s*(?:SELECT|select)"),
    "mysqli_query":       re.compile(r"\bmysqli_query\s*\("),
    "mysql_query":        re.compile(r"\bmysql_query\s*\("),
    "raw_sql_concat":     re.compile(r"\$(?:sql|query|SQL|Query)\s*[\.=]+.*\$_(?:GET|POST|REQUEST|COOKIE)"),
}

# CLASS A — auth surface signals (unauthenticated / low-priv access)
_AUTH_SURFACE = {
    "nopriv_ajax", "rest_open", "rest_no_auth_fn",
    "logged_in_only", "cap_read",
}

# CLASS B — dangerous sink patterns (operations that cause RCE / DB-takeover)
_DANGEROUS_SINKS = {
    "eval", "exec", "shell_exec", "system", "passthru", "popen",
    "proc_open", "pcntl_exec", "assert_str", "create_function", "preg_replace_e",
    "call_user_func", "variable_function",
    "file_put_contents", "move_uploaded_file", "file_upload", "fwrite", "copy_file",
    "include_var", "include_get_post",
    "unserialize", "zip_extract", "zip_extractto",
    "user_create", "add_cap", "update_wp_caps",
    "wpdb_raw_query", "wpdb_get_results", "mysqli_query", "mysql_query", "raw_sql_concat",
}

# Base scores (per hit, capped at 5 hits/pattern)
_SCORES: dict[str, int] = {
    # Auth surface
    "nopriv_ajax":        20,   # unauthenticated handler
    "rest_open":          20,   # open REST route
    "rest_no_auth_fn":    15,
    "logged_in_only":     8,
    "cap_read":           6,

    # Direct code execution (high value but useless without auth surface)
    "eval":               20,
    "exec":               18,
    "shell_exec":         18,
    "system":             15,
    "passthru":           15,
    "popen":              12,
    "proc_open":          18,
    "pcntl_exec":         18,
    "assert_str":         12,
    "create_function":    15,
    "preg_replace_e":     18,
    "call_user_func":     10,
    "variable_function":  6,

    # File write / upload
    "file_put_contents":  15,
    "move_uploaded_file": 15,
    "file_upload":        12,   # bumped — file upload is prime RCE path from frontend
    "fwrite":             8,
    "copy_file":          5,

    # LFI
    "include_var":        12,
    "include_get_post":   18,

    # Object injection
    "unserialize":        10,

    # ZIP extraction
    "zip_extract":        8,
    "zip_extractto":      10,

    # Privilege escalation
    "user_create":        18,   # creating users = priv-esc if nopriv-reachable
    "add_cap":            15,
    "update_wp_caps":     15,

    # DB takeover
    "wpdb_raw_query":     12,
    "wpdb_get_results":   8,
    "mysqli_query":       12,
    "mysql_query":        10,
    "raw_sql_concat":     18,
}

# Always keep a plugin if it has ANY of these (regardless of score)
_HIGH_CONFIDENCE = {
    # Auth surface alone justifies keeping — we look for sinks ourselves
    "nopriv_ajax", "rest_open",
    # Sinks that are almost always dangerous when reachable
    "eval", "exec", "shell_exec", "system", "passthru",
    "proc_open", "pcntl_exec", "preg_replace_e", "create_function",
    "include_get_post", "raw_sql_concat",
    # Priv-esc
    "user_create", "add_cap", "update_wp_caps",
}

# ---------------------------------------------------------------------------
# Already-seen guard — skip slugs we've already downloaded or reviewed
# ---------------------------------------------------------------------------

def _already_seen() -> set[str]:
    seen: set[str] = set()
    try:
        with get_conn() as conn:
            for r in conn.execute("SELECT slug FROM plugins"):
                seen.add(r["slug"])
            for r in conn.execute("SELECT plugin_slug FROM manual_reviews"):
                seen.add(r["plugin_slug"])
    except Exception:
        pass
    # Also skip anything already downloaded in plugins_rce/
    if OUT_DIR.exists():
        for d in OUT_DIR.iterdir():
            if d.is_dir():
                seen.add(d.name)
    return seen

# ---------------------------------------------------------------------------
# WP.org tag query
# ---------------------------------------------------------------------------

def _query_tag(
    session: requests.Session,
    tag: str,
    excluded: set[str],
    want: int,
    max_pages: int = 8,
) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    found: list[dict] = []
    page = 1
    while len(found) < want and page <= max_pages:
        params = {
            "action":                            "query_plugins",
            "request[tag]":                      tag,
            "request[page]":                     page,
            "request[per_page]":                 100,
            "request[fields][active_installs]":  1,
            "request[fields][last_updated]":     1,
            "request[fields][short_description]": 1,
        }
        try:
            r = session.get(WP_API, params=params, timeout=20)
        except requests.RequestException:
            break
        time.sleep(RATE_LIMIT_S)
        if r.status_code != 200:
            break
        plugins = r.json().get("plugins", [])
        if not plugins:
            break
        for p in plugins:
            slug = p.get("slug", "")
            if not slug or slug in excluded:
                continue
            installs = p.get("active_installs", 0)
            if not (MIN_INSTALLS <= installs <= MAX_INSTALLS):
                continue
            try:
                updated = datetime.strptime(
                    p.get("last_updated", ""), "%Y-%m-%d %I:%M%p GMT"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if updated < cutoff:
                continue
            found.append(p)
            if len(found) >= want:
                break
        page += 1
    return found

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def _download(slug: str, session: requests.Session) -> Path | None:
    dest = OUT_DIR / slug
    if dest.exists():
        return dest  # already there

    url = f"{DOWNLOADS}/{slug}.latest-stable.zip"
    try:
        r = session.get(url, timeout=60)
    except requests.RequestException as e:
        print(f"    [download] {slug}: {e}")
        return None
    if r.status_code != 200:
        print(f"    [download] {slug}: HTTP {r.status_code}")
        return None

    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            for member in zf.infolist():
                parts = Path(member.filename).parts
                if len(parts) < 2:
                    continue
                rel = Path(*parts[1:])
                target = dest / rel
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(zf.read(member.filename))
    except Exception as e:
        print(f"    [download] {slug}: zip error: {e}")
        import shutil; shutil.rmtree(dest, ignore_errors=True)
        return None

    return dest

# ---------------------------------------------------------------------------
# Source scan
# ---------------------------------------------------------------------------

_SKIP_DIRS = {"vendor", "vendor-prefixed", "node_modules", "test", "tests", "spec", "specs"}


def _scan(plugin_dir: Path) -> dict[str, int]:
    """Count pattern hits across all .php files, skipping vendor/test dirs."""
    counts: dict[str, int] = {k: 0 for k in _RCE_PATTERNS}
    for php in plugin_dir.rglob("*.php"):
        if any(seg in _SKIP_DIRS for seg in php.parts):
            continue
        try:
            text = php.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, pat in _RCE_PATTERNS.items():
            counts[name] += len(pat.findall(text))
    return counts


def _score(counts: dict[str, int]) -> int:
    """
    Score = sum of (hits × weight) for each pattern, capped at 5 hits/pattern.
    Bonus: if plugin has BOTH auth-surface AND dangerous-sink signals, apply 2× multiplier.
    This makes nopriv_ajax + move_uploaded_file rank far above either alone.
    """
    has_auth    = any(counts.get(p, 0) > 0 for p in _AUTH_SURFACE)
    has_sink    = any(counts.get(p, 0) > 0 for p in _DANGEROUS_SINKS)
    multiplier  = 2 if (has_auth and has_sink) else 1

    total = 0
    for name, hits in counts.items():
        if hits:
            total += _SCORES.get(name, 0) * min(hits, 5)
    return total * multiplier


def _high_confidence_hit(counts: dict[str, int]) -> bool:
    return any(counts.get(p, 0) > 0 for p in _HIGH_CONFIDENCE)


def _dual_signal(counts: dict[str, int]) -> bool:
    """True when the plugin has BOTH an auth-surface pattern AND a dangerous sink."""
    return (
        any(counts.get(p, 0) > 0 for p in _AUTH_SURFACE) and
        any(counts.get(p, 0) > 0 for p in _DANGEROUS_SINKS)
    )

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=20,
                        help="Number of plugins to download (default 20)")
    parser.add_argument("--dry-run", action="store_true",
                        help="List candidates without downloading")
    args = parser.parse_args()

    migrate()
    OUT_DIR.mkdir(exist_ok=True)

    excluded = _already_seen()
    print(f"[rce-discover] skipping {len(excluded)} already-seen slugs")
    print(f"[rce-discover] install band: {MIN_INSTALLS:,}–{MAX_INSTALLS:,}")
    print(f"[rce-discover] output dir:   {OUT_DIR}")
    print(f"[rce-discover] target count: {args.limit}\n")

    session = requests.Session()
    session.headers["User-Agent"] = "wp-hunter/0.1 (security research; responsible disclosure)"

    results: list[dict] = []   # {slug, score, counts, installs}

    for tag in RCE_TAGS:
        if len(results) >= args.limit:
            break

        need = (args.limit - len(results)) * 4   # over-fetch to account for low-score drops
        print(f"[rce-discover] tag='{tag}' — querying...")
        candidates = _query_tag(session, tag, excluded, want=need)
        if not candidates:
            print(f"  (no results)")
            continue

        print(f"  {len(candidates)} candidates from WP.org")

        for p in candidates:
            if len(results) >= args.limit:
                break

            slug     = p["slug"]
            installs = p.get("active_installs", 0)
            excluded.add(slug)

            if args.dry_run:
                print(f"  [dry-run] would download: {slug}  ({installs:,} installs)")
                results.append({"slug": slug, "installs": installs, "score": 0, "counts": {}})
                continue

            print(f"  -> {slug}  ({installs:,} installs) … ", end="", flush=True)

            plugin_dir = _download(slug, session)
            time.sleep(RATE_LIMIT_S)

            if not plugin_dir:
                print("download failed")
                continue

            counts = _scan(plugin_dir)
            score  = _score(counts)
            hc     = _high_confidence_hit(counts)
            dual   = _dual_signal(counts)

            # Keep only plugins with at least some signal
            fired = [k for k, v in counts.items() if v > 0]
            if not fired:
                print(f"no surface — removed (score=0)")
                import shutil; shutil.rmtree(plugin_dir, ignore_errors=True)
                continue

            # Auth-surface-only plugins with no dangerous sink are low value;
            # still keep but don't count toward --limit (they inflate the list).
            has_sink = any(counts.get(p, 0) > 0 for p in _DANGEROUS_SINKS)
            if not has_sink and not hc:
                print(f"auth surface only, no dangerous sink — removed (score={score})")
                import shutil; shutil.rmtree(plugin_dir, ignore_errors=True)
                continue

            tag_dual = "  *** DUAL-SIGNAL ***" if dual else ""
            tag_hc   = "  [HIGH-CONF]" if hc and not dual else ""
            print(f"score={score}{tag_dual}{tag_hc}")

            # Show auth-surface patterns first, then sinks
            auth_fired = [k for k in fired if k in _AUTH_SURFACE]
            sink_fired = [k for k in fired if k in _DANGEROUS_SINKS]
            if auth_fired:
                print(f"     auth : {', '.join(f'{k}×{counts[k]}' for k in auth_fired)}")
            if sink_fired:
                print(f"     sinks: {', '.join(f'{k}×{counts[k]}' for k in sink_fired)}")

            results.append({
                "slug":     slug,
                "installs": installs,
                "score":    score,
                "counts":   counts,
                "hc":       hc,
                "dual":     dual,
            })

    # ── Final report ────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print(f"  RCE DISCOVERY RESULTS  —  {len(results)} plugins downloaded")
    print("=" * 70)

    # Sort: dual-signal first, then high-confidence, then by score
    results.sort(key=lambda x: (
        -int(x.get("dual", False)),
        -int(x.get("hc",   False)),
        -x["score"],
    ))

    for r in results:
        counts     = r.get("counts", {})
        auth_fired = [k for k, v in counts.items() if v > 0 and k in _AUTH_SURFACE]
        sink_fired = [k for k, v in counts.items() if v > 0 and k in _DANGEROUS_SINKS]

        tag = ""
        if r.get("dual"):
            tag = "  *** DUAL-SIGNAL ***"
        elif r.get("hc"):
            tag = "  [HIGH-CONF]"

        print(f"\n  [{r['score']:>5}]  {r['slug']}  ({r['installs']:,} installs){tag}")
        if auth_fired:
            print(f"           auth : " + "  ".join(f"{k}×{counts[k]}" for k in auth_fired))
        if sink_fired:
            print(f"           sinks: " + "  ".join(f"{k}×{counts[k]}" for k in sink_fired))

    print()
    dual_count = sum(1 for r in results if r.get("dual"))
    print(f"Dual-signal (auth+sink): {dual_count} / {len(results)}")
    print(f"Plugins saved to:        {OUT_DIR}/")
    print(f"Manual review:           read the source in plugins_rce/<slug>/")
    print()
    print("REVIEW PRIORITY ORDER:")
    print("  1. DUAL-SIGNAL — nopriv/open-REST + dangerous sink")
    print("  2. HIGH-CONF   — preg_replace_e / include_get_post / raw_sql_concat")
    print("  3. Others      — check auth gate before diving deep")
    return 0


if __name__ == "__main__":
    sys.exit(main())
