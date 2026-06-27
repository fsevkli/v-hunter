"""
discover_targets.py — find and download N plugins for manual review.

Strategy (revised 2026-05-21):
  - Browse WP.org by HIGH_VALUE_TAGS (payment, booking, form, import, …)
    instead of generic browse=updated — avoids the "everyone scans the same
    recently-updated queue" duplicate problem.
  - Use WPScan API (WPSCAN_API_KEY in .env) to score each candidate by its
    CVE history:
      · zero historical CVEs  → PRIORITY 1  (truly untouched)
      · old CVEs only (>60d)  → PRIORITY 2  (sloppy developer, more bugs likely)
      · recent CVE (<60d)     → SKIP        (hot, other researchers active)
  - Install range tightened to 1K–15K — below the radar of top researchers
    who target 10K+, still meets Patchstack's 1K floor.
  - Fallback to browse=updated when tag queries are exhausted.

Usage:
    python scripts/discover_targets.py [--limit 25] [--dry-run]
    WPSCAN_API_KEY=xxx python scripts/discover_targets.py
"""
from __future__ import annotations

import argparse
import os
import random
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

from hunter.db import get_conn, migrate
from hunter.ingestor import (
    DENYLIST as _CORE_DENYLIST,
    PLUGINS_DIR,
    _make_session,
    _ingest_one,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WP_API      = "https://api.wordpress.org/plugins/info/1.2/"
WPSCAN_API  = "https://wpscan.com/api/v3/plugins/{slug}"
RATE_LIMIT_S = 0.8

RECENT_VULN_DAYS   = 60   # plugins with CVE newer than this → skip
VULN_CACHE_TTL_DAYS = 7   # re-check after this many days

# Bounty-focused tag set: only categories that consistently produce CVSS 8.5+
# findings on Patchstack's payout reports. Excludes low-impact categories
# (page-builder, shortcode, cache, calendar, contact-form) that mostly yield
# stored XSS / DoS class issues below the bounty bar.
HIGH_VALUE_TAGS = [
    # Payment / financial (truebooker pattern: nopriv settings write = CVSS 9+)
    "payment", "stripe", "paypal", "checkout", "invoice", "billing",
    "woocommerce", "e-commerce", "order", "shipping",
    # Booking / reservation with payment (truebooker, timetics, food-and-drink-menu)
    "booking", "appointment", "reservation",
    # Membership / subscription (financial + access control)
    "membership", "subscription", "affiliate", "commission", "referral",
    # User reg / role management (privesc to admin = CVSS 9.8)
    "user-registration", "role", "user-management", "registration",
    "user-profile", "social-login",
    # File handling (arbitrary file upload = RCE = CVSS 9-10)
    "file-manager", "import", "export", "migration", "backup",
    "media", "documents", "upload",
    # API / webhook (unauth nopriv handlers, payment webhooks)
    "api", "rest-api", "webhook", "integration",
    # PHP object injection surface
    "serialization", "session",
]

# Install band: 10K–100K is the sweet spot — large enough to have meaningful
# attack surface and Patchstack bounty value, small enough to be under-audited
# compared to the 100K+ tier.
MIN_INSTALLS = 10_0000
MAX_INSTALLS = 500_000

# Keywords that indicate a security-related changelog entry.
_SECURITY_KEYWORDS = re.compile(
    r"\b(security|vulnerabilit|cve-\d|xss|sqli|sql.injection|"
    r"csrf|rce|lfi|rfi|ssrf|injection|privilege|escalat|bypass|"
    r"unauth|unauthorized|disclosure|traversal|patch|critical)\b",
    re.IGNORECASE,
)

# Hard off-limits (already submitted / closed / decided-not-to-file)
HARD_OFFLIMITS = {
    "bookingpress-appointment-booking",
    "multiple-page-generator-plugin-mpg",
    "timetics",
    "storegrowth-sales-booster",
    "ai-copilot-content-generator",
    "legal-texts-connector-it-recht-kanzlei",
    "wp-statistics",
    "food-and-drink-menu",
    "restaurant-reservations",
}

# Surface patterns for promise scoring
_SURFACE_PATTERNS = {
    "rest_routes":              re.compile(r"\bregister_rest_route\s*\("),
    "ajax_nopriv":              re.compile(r"add_action\s*\(\s*['\"]wp_ajax_nopriv_"),
    "ajax_authed":              re.compile(r"add_action\s*\(\s*['\"]wp_ajax_(?!nopriv_)"),
    "admin_post_nopriv":        re.compile(r"add_action\s*\(\s*['\"]admin_post_nopriv_"),
    "admin_post_authed":        re.compile(r"add_action\s*\(\s*['\"]admin_post_(?!nopriv_)"),
    "unserialize":              re.compile(r"\b(?:maybe_)?unserialize\s*\("),
    "unserialize_direct":       re.compile(r"\bunserialize\s*\("),   # direct unserialize > maybe_
    "update_option":            re.compile(r"\bupdate_option\s*\("),
    "update_user_meta":         re.compile(r"\bupdate_user_meta\s*\("),
    "wpdb_query":               re.compile(r"\$wpdb->\s*(?:query|prepare)\s*\("),
    "file_get_contents":        re.compile(r"\bfile_get_contents\s*\(\s*\$"),
    "wp_remote_get":            re.compile(r"\bwp_remote_(?:get|post|request)\s*\("),
    "permission_callback_true": re.compile(r"['\"]permission_callback['\"]\s*=>\s*['\"]__return_true['\"]"),
    "current_user_can":         re.compile(r"\bcurrent_user_can\s*\("),
    "check_ajax_referer":       re.compile(r"\bcheck_ajax_referer\s*\("),
    # payment-specific patterns that yielded real bugs
    "stripe_callback":          re.compile(r"stripe|payment_intent|paymentintent", re.IGNORECASE),
    "paypal_callback":          re.compile(r"paypal|ipn_listener|notify_url", re.IGNORECASE),
    "payment_status":           re.compile(r"payment_status|order_status|paid|completed", re.IGNORECASE),
    # LFI surface: include/require with a variable path
    "include_variable":         re.compile(r"\b(?:include|require)(?:_once)?\s+\$"),
    # Stored XSS surface: shortcode handlers (Contributor+ controls attrs)
    "shortcode_handler":        re.compile(r"\badd_shortcode\s*\("),
    # Privilege escalation surface
    "wp_update_user":           re.compile(r"\bwp_(?:update|insert)_user\s*\("),
    "wp_capabilities_meta":     re.compile(r"['\"]wp_capabilities['\"]"),
    # File upload handling
    "file_upload":              re.compile(r"\$_FILES\s*\["),
    # extract() on shortcode attrs — common stored XSS vector
    "extract_atts":             re.compile(r"\bextract\s*\(\s*shortcode_atts\s*\("),
}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _already_seen_slugs() -> set[str]:
    seen: set[str] = set()
    with get_conn() as conn:
        for r in conn.execute("SELECT slug FROM plugins").fetchall():
            seen.add(r["slug"])
        for r in conn.execute("SELECT plugin_slug FROM manual_reviews").fetchall():
            seen.add(r["plugin_slug"])
    return seen


def _excluded_slugs() -> set[str]:
    return _CORE_DENYLIST | HARD_OFFLIMITS | _already_seen_slugs()


# ---------------------------------------------------------------------------
# WPScan CVE history
# ---------------------------------------------------------------------------

_wpscan_calls_today: int = 0
WPSCAN_DAILY_LIMIT: int = 22  # stay 3 under the 25 req/day free cap


def _ensure_vuln_cache() -> None:
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vuln_cache (
                slug          TEXT PRIMARY KEY,
                checked_at    TEXT NOT NULL,
                has_recent    INTEGER NOT NULL,
                total_vulns   INTEGER NOT NULL DEFAULT 0,
                source        TEXT
            )
        """)
        # Add total_vulns column if upgrading from old schema
        try:
            conn.execute("ALTER TABLE vuln_cache ADD COLUMN total_vulns INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass
        conn.commit()


def _vuln_cache_get(slug: str) -> dict | None:
    """Return cached row dict or None if stale/missing."""
    ttl_cutoff = (
        datetime.now(timezone.utc) - timedelta(days=VULN_CACHE_TTL_DAYS)
    ).isoformat()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT has_recent, total_vulns FROM vuln_cache WHERE slug=? AND checked_at>?",
            (slug, ttl_cutoff),
        ).fetchone()
    return dict(row) if row else None


def _vuln_cache_set(slug: str, has_recent: bool, total_vulns: int, source: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO vuln_cache
                   (slug, checked_at, has_recent, total_vulns, source)
               VALUES (?, ?, ?, ?, ?)""",
            (slug, datetime.now(timezone.utc).isoformat(),
             int(has_recent), total_vulns, source),
        )
        conn.commit()


def _wpscan_query(slug: str, session: requests.Session) -> dict | None:
    """
    Call WPScan API. Returns dict with keys:
        recent_vuln  (bool)   — any CVE in last RECENT_VULN_DAYS
        total_vulns  (int)    — all-time known CVE count
    Returns None if API unavailable / key missing / limit reached.
    """
    global _wpscan_calls_today
    api_key = os.environ.get("WPSCAN_API_KEY", "").strip()
    if not api_key or _wpscan_calls_today >= WPSCAN_DAILY_LIMIT:
        return None
    try:
        resp = session.get(
            WPSCAN_API.format(slug=slug),
            headers={"Authorization": f"Token token={api_key}"},
            timeout=10,
        )
        _wpscan_calls_today += 1
        if resp.status_code in (401, 403):
            print("[discover] WPScan: auth error — check WPSCAN_API_KEY", file=sys.stderr)
            _wpscan_calls_today = WPSCAN_DAILY_LIMIT
            return None
        if resp.status_code == 429:
            print("[discover] WPScan: rate limit hit", file=sys.stderr)
            _wpscan_calls_today = WPSCAN_DAILY_LIMIT
            return None
        if resp.status_code != 200:
            return None

        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None and int(remaining) <= 3:
            print(f"[discover] WPScan: {remaining} requests left today — switching to changelog")
            _wpscan_calls_today = WPSCAN_DAILY_LIMIT

        data  = resp.json()
        vulns = data.get(slug, {}).get("vulnerabilities", [])
        cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_VULN_DAYS)
        recent = False
        for v in vulns:
            raw = v.get("created_at", "") or v.get("published_date", "")
            try:
                ts = datetime.fromisoformat(raw.rstrip("Z")).replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    recent = True
                    break
            except (ValueError, AttributeError):
                continue
        return {"has_recent": recent, "total_vulns": len(vulns)}
    except Exception:
        return None


def _changelog_has_recent_security(slug: str, session: requests.Session) -> bool:
    """Fallback: scan WP.org changelog for security keywords in recent entries."""
    try:
        resp = session.get(
            WP_API,
            params={"action": "plugin_information", "slug": slug},
            timeout=15,
        )
        if resp.status_code != 200:
            return False
        data = resp.json()
    except Exception:
        return False

    changelog = data.get("sections", {}).get("changelog", "")
    if not changelog:
        return False

    cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_VULN_DAYS)
    header_re = re.compile(
        r"<h[2-5][^>]*>[^<]*(\d{4}-\d{2}-\d{2}|\w+\s+\d{1,2},?\s+\d{4})[^<]*</h[2-5]>",
        re.IGNORECASE,
    )

    parts = header_re.split(changelog)
    for i in range(1, len(parts), 2):
        date_str = parts[i].replace(",", "").strip()
        for fmt in ("%Y-%m-%d", "%B %d %Y", "%b %d %Y"):
            try:
                ts = datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    chunk = parts[i - 1] + parts[i] + (parts[i + 1] if i + 1 < len(parts) else "")
                    if _SECURITY_KEYWORDS.search(chunk):
                        return True
                break
            except ValueError:
                continue

    if header_re.search(changelog[:1500]) and _SECURITY_KEYWORDS.search(changelog[:1500]):
        return True
    return False


def _get_vuln_profile(slug: str, session: requests.Session) -> dict:
    """
    Return vuln profile for slug (cached).

    Keys: has_recent (bool), total_vulns (int)
    """
    _ensure_vuln_cache()
    cached = _vuln_cache_get(slug)
    if cached is not None:
        return cached

    # Try WPScan first (authoritative + gives total count)
    ws = _wpscan_query(slug, session)
    if ws is not None:
        _vuln_cache_set(slug, ws["has_recent"], ws["total_vulns"], "wpscan")
        return ws

    # Fallback: changelog heuristic (no total count available)
    recent = _changelog_has_recent_security(slug, session)
    _vuln_cache_set(slug, recent, 0, "changelog")
    return {"has_recent": recent, "total_vulns": 0}


# ---------------------------------------------------------------------------
# WP.org queries — tag-based + fallback
# ---------------------------------------------------------------------------

def _query_by_tag(
    session: requests.Session,
    tag: str,
    excluded: set[str],
    target_count: int,
    max_age_days: int = 730,
    max_pages: int = 10,
) -> list[dict]:
    """Query WP.org plugins by tag, apply install + age + exclusion filters."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    selected: list[dict] = []
    page = 1

    while len(selected) < target_count and page <= max_pages:
        params = {
            "action":                        "query_plugins",
            "request[tag]":                  tag,
            "request[page]":                 page,
            "request[per_page]":             100,
            "request[fields][active_installs]": 1,
            "request[fields][last_updated]": 1,
            "request[fields][tags]":         1,
            "request[fields][short_description]": 1,
            "request[fields][author]":       1,
        }
        try:
            resp = session.get(WP_API, params=params, timeout=20)
        except requests.RequestException:
            break
        time.sleep(RATE_LIMIT_S)

        if resp.status_code != 200:
            break
        page_plugins = resp.json().get("plugins", [])
        if not page_plugins:
            break

        for p in page_plugins:
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
            selected.append(p)
            if len(selected) >= target_count:
                break
        page += 1

    return selected


def _query_browse_fallback(
    session: requests.Session,
    excluded: set[str],
    target_count: int,
    max_age_days: int = 730,
    max_pages: int = 20,
    start_page: int = 1,
) -> list[dict]:
    """Fallback: browse=updated with tight install band when tags exhausted."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    selected: list[dict] = []
    page = start_page

    while len(selected) < target_count and page < start_page + max_pages:
        params = {
            "action":                            "query_plugins",
            "request[page]":                     page,
            "request[per_page]":                 100,
            "request[browse]":                   "updated",
            "request[fields][active_installs]":  1,
            "request[fields][last_updated]":     1,
            "request[fields][tags]":             1,
            "request[fields][short_description]": 1,
            "request[fields][author]":           1,
        }
        try:
            resp = session.get(WP_API, params=params, timeout=20)
        except requests.RequestException:
            break
        time.sleep(RATE_LIMIT_S)

        if resp.status_code != 200:
            break
        page_plugins = resp.json().get("plugins", [])
        if not page_plugins:
            break

        for p in page_plugins:
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
            selected.append(p)
            if len(selected) >= target_count:
                break
        page += 1

    return selected


# ---------------------------------------------------------------------------
# Promise scoring
# ---------------------------------------------------------------------------

def _scan_source(plugin_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {k: 0 for k in _SURFACE_PATTERNS}
    for php in plugin_dir.rglob("*.php"):
        if any(seg in {"vendor", "vendor-prefixed", "node_modules"} for seg in php.parts):
            continue
        try:
            text = php.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, pat in _SURFACE_PATTERNS.items():
            counts[name] += len(pat.findall(text))
    return counts


def _score(meta: dict, source_counts: dict[str, int], vuln_profile: dict) -> int:
    """
    Promise score 0–100.

    AJAX / REST surface:
      +5 per REST route / nopriv AJAX / permission_callback=__return_true
      +3 per authed AJAX

    Leaderboard bug-class signals (weighted by how often they yield real findings):
      +8  per direct unserialize() call — stronger than maybe_unserialize
      +5  per unserialize (either kind)
      +6  per add_shortcode — Contributor+ XSS surface
      +5  per extract(shortcode_atts()) — common stored XSS chain
      +8  per wp_update/insert_user — priv-esc surface
      +8  per 'wp_capabilities' string — direct cap manipulation
      +6  per include/require $var — LFI surface
      +5  per $_FILES handling — file upload XSS / LFI
      +2  per options / user_meta / wpdb / remote mutations

    Payment bonus (known-good class):
      +8 per stripe/paypal callback
      +5 per payment_status

    Defender saturation penalty: -2 per excess defender above surface×2

    CVE-history bonus:
      +20 zero historical CVEs (untouched)
      +10 old CVEs (>60d) — sloppy developer
    """
    s = 0
    s += source_counts["rest_routes"]               * 5
    s += source_counts["ajax_nopriv"]               * 5
    s += source_counts["admin_post_nopriv"]         * 5
    s += source_counts["permission_callback_true"]  * 5
    s += source_counts["ajax_authed"]               * 3
    s += source_counts["admin_post_authed"]         * 3

    # Leaderboard class signals
    s += source_counts["unserialize_direct"]        * 8
    s += source_counts["unserialize"]               * 5
    s += source_counts["shortcode_handler"]         * 6
    s += source_counts["extract_atts"]              * 5
    s += source_counts["wp_update_user"]            * 8
    s += source_counts["wp_capabilities_meta"]      * 8
    s += source_counts["include_variable"]          * 6
    s += source_counts["file_upload"]               * 5

    # General mutation surface
    s += source_counts["update_option"]             * 2
    s += source_counts["update_user_meta"]          * 2
    s += source_counts["wpdb_query"]                * 2
    s += source_counts["file_get_contents"]         * 2
    s += source_counts["wp_remote_get"]             * 2

    # Payment-pattern bonus
    s += source_counts["stripe_callback"]  * 8
    s += source_counts["paypal_callback"]  * 8
    s += source_counts["payment_status"]   * 5

    # Defender saturation penalty
    defender_total = source_counts["current_user_can"] + source_counts["check_ajax_referer"]
    surface_total  = (
        source_counts["rest_routes"] + source_counts["ajax_nopriv"]
        + source_counts["ajax_authed"] + source_counts["admin_post_nopriv"]
        + source_counts["admin_post_authed"]
    )
    if defender_total > surface_total * 2 and surface_total > 0:
        s -= min(20, (defender_total - surface_total * 2))

    # CVE-history bonus
    total_vulns = vuln_profile.get("total_vulns", 0)
    if total_vulns == 0:
        s += 20   # truly untouched by researchers
    else:
        s += 10   # sloppy dev, more bugs likely

    return max(0, min(100, s))


# ---------------------------------------------------------------------------
# Candidate processing
# ---------------------------------------------------------------------------

def _process_candidate(
    p: dict,
    session: requests.Session,
    excluded: set[str],
) -> tuple[str, int] | None:
    slug = p["slug"]
    print(f"\n[discover] ----- {slug} -----")

    # CVE recency filter — skip if recently touched by other researchers
    profile = _get_vuln_profile(slug, session)
    time.sleep(RATE_LIMIT_S)

    if profile["has_recent"]:
        print(f"  [vuln-filter] recent CVE/advisory — skipping")
        excluded.add(slug)
        return None

    history_label = (
        "zero-history (untouched)"    if profile["total_vulns"] == 0
        else f"old-CVEs={profile['total_vulns']} (sloppy dev)"
    )
    print(f"  [vuln-profile] {history_label}")

    status = _ingest_one(slug, session)
    time.sleep(RATE_LIMIT_S)
    if status == "error":
        print("  ingest failed; skipping")
        excluded.add(slug)
        return None

    plugin_dir = PLUGINS_DIR / slug
    if not plugin_dir.exists():
        print("  plugin dir missing after ingest; skipping")
        excluded.add(slug)
        return None

    source_counts = _scan_source(plugin_dir)
    score = _score(p, source_counts, profile)
    print(
        f"  promise_score={score}  surface=("
        f"rest:{source_counts['rest_routes']} "
        f"nopriv:{source_counts['ajax_nopriv']} "
        f"authed:{source_counts['ajax_authed']} "
        f"unser:{source_counts['unserialize']} "
        f"stripe:{source_counts['stripe_callback']} "
        f"paypal:{source_counts['paypal_callback']})"
    )

    with get_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO manual_reviews
                   (plugin_slug, version_reviewed, reviewed_at,
                    promise_score, verdict, notes)
               VALUES (?, ?, NULL, ?, NULL, NULL)""",
            (slug, p.get("version", "unknown"), score),
        )
        conn.commit()

    excluded.add(slug)
    return (slug, score)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    migrate()
    _ensure_vuln_cache()

    excluded = _excluded_slugs()
    print(f"[discover] excluding {len(excluded)} already-seen slugs")
    print(f"[discover] install band: {MIN_INSTALLS:,}–{MAX_INSTALLS:,} (expanded for mid-tier coverage)")
    wpscan_key = bool(os.environ.get("WPSCAN_API_KEY", "").strip())
    print(f"[discover] WPScan API: {'enabled' if wpscan_key else 'disabled (changelog fallback)'}")

    session = _make_session()

    # Shuffle tags each run so we don't always scan the same ones first
    tags = HIGH_VALUE_TAGS[:]
    random.shuffle(tags)

    if args.dry_run:
        tag = tags[0]
        print(f"\n[discover] dry-run: tag='{tag}' ...")
        candidates = _query_by_tag(session, tag, excluded, args.limit)
        print(f"[discover] {len(candidates)} candidates:")
        for p in candidates:
            print(f"  - {p['slug']:40} {p.get('active_installs', 0):>6} installs")
        return 0

    downloaded: list[tuple[str, int]] = []
    attempted  = 0

    # Phase 1: browse=updated (primary) — recently-updated plugins have the
    # freshest code and the least researcher coverage on new additions.
    half = max(1, args.limit // 2)
    print(f"\n[discover] === phase 1: browse=updated (recently-updated plugins) ===")
    candidates = _query_browse_fallback(session, excluded, target_count=half * 6)
    for p in candidates:
        if len(downloaded) >= half:
            break
        attempted += 1
        result = _process_candidate(p, session, excluded)
        if result:
            downloaded.append(result)
            print(f"  >> {len(downloaded)}/{args.limit} downloaded so far")

    # Phase 2: tag-targeted queries — surface-specific pools
    print(f"\n[discover] === phase 2: tag-targeted queries ===")
    tag_idx = 0
    while len(downloaded) < args.limit and tag_idx < len(tags):
        tag = tags[tag_idx]
        tag_idx += 1
        need = args.limit - len(downloaded)
        print(f"\n[discover] tag='{tag}' — need {need} more")

        candidates = _query_by_tag(
            session, tag, excluded,
            target_count=need * 5,
        )
        if not candidates:
            continue

        print(f"[discover] tag='{tag}' found {len(candidates)} raw candidates")
        for p in candidates:
            if len(downloaded) >= args.limit:
                break
            attempted += 1
            result = _process_candidate(p, session, excluded)
            if result:
                downloaded.append(result)
                print(f"  >> {len(downloaded)}/{args.limit} downloaded so far")

    # Final report
    print()
    print("=" * 60)
    print(f"[discover] downloaded {len(downloaded)}/{args.limit} plugins "
          f"after {attempted} attempts, ranked by promise:")
    print("=" * 60)
    downloaded.sort(key=lambda x: -x[1])
    for slug, score in downloaded:
        print(f"  [{score:>3}]  {slug}")
    if len(downloaded) < args.limit:
        print(f"\n[discover] WARNING: only {len(downloaded)}/{args.limit} — "
              "consider widening MAX_INSTALLS or adding more tags.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
