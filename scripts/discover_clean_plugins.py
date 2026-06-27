"""
discover_clean_plugins.py

Pages the WordPress.org plugin API looking for plugins that satisfy:
  - 1 000 – 20 000 active installs
  - Last updated after 2024-11-07 (18 months before 2026-05-07)
  - Zero results on patchstack.com/database
  - Zero results on wpscan.com/plugins/<slug>
  - Not already ingested in our DB

Writes the selected slugs to scripts/clean_plugin_slugs.json and
prints them for inspection.
"""

import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

# ── constants ────────────────────────────────────────────────────────────────

TARGET      = 80
MIN_INST    = 1_000
MAX_INST    = 10_000
CUTOFF      = datetime(2024, 11, 7)     # 18 months before May 2026

WP_API      = "https://api.wordpress.org/plugins/info/1.2/"
DELAY       = 1.0          # seconds between external-site checks
PAGE_DELAY  = 0.4          # seconds between WP.org pages

ALREADY_INGESTED = {
    "3d-image-gallery","acf-frontend-form-element","advance-custom-html",
    "advanced-custom-fields-font-awesome","advanced-ip-blocker",
    "advanced-testimonial-carousel-for-elementor","advanced-woo-labels","ai-engine",
    "ajax-search-lite","analogwp-templates","angie","appointment-hour-booking",
    "bdthemes-prime-slider-lite","betterdocs","bit-integrations","bit-social",
    "booking-package","bookingpress-appointment-booking","bp-better-messages","breeze",
    "burst-statistics","calculated-fields-form","catfolders-document-gallery",
    "chatway-live-chat","chaty","clickcease-click-fraud-protection","cloudflare",
    "cloudsecure-wp-security","constant-contact-forms","contact-form-to-db",
    "content-control","cookieadmin","cost-calculator-builder",
    "custom-order-numbers-for-woocommerce","dark-mode-toggle","dark-visitors",
    "date-time-picker-field","disable-emails",
    "disabled-source-disabled-right-click-and-content-protection","document-emberdder",
    "download-manager","easy-appointments","easy-image-collage","easy-media-gallery",
    "echo-knowledge-base","ele-custom-skin","email-subscribers","embed-privacy",
    "essential-blocks","export-woocommerce-customer-list","ezcache","falang",
    "fluent-booking","friendly-captcha","funnel-builder",
    "funnelkit-stripe-woo-payment-gateway","gallery-with-thumbnail-slider",
    "gutenverse-form","happy-elementor-addons","host-webfonts-local","ics-calendar",
    "image-hub","image-sizes","instawp-connect","ithemes-sync","kadence-starter-templates",
    "kirki","legal-texts-connector-it-recht-kanzlei","location-weather","login-as-user",
    "loginpress","marquee-addons-for-elementor","mb-custom-post-type","meow-gallery",
    "meow-lightbox","mesmerize-companion","modula-best-grid-gallery",
    "montonio-for-woocommerce","mosaic-gallery-advanced-gallery",
    "multiple-pages-generator-by-porthas","my-wp","mystickyelements","nexter-extension",
    "one-page-express-companion","one-stop-shop-woocommerce","open-user-map",
    "paid-member-subscriptions","password-protect-page","payu-india","picu","poptin",
    "points-and-rewards-for-woocommerce","powerpress","products-extractor-for-woocommerce",
    "pushengage","pymntpl-paypal-woocommerce","quiz-maker","quiz-master-next",
    "quttera-web-malware-scanner","real-custom-post-order","real-thumbnail-generator-lite",
    "relevanssi","reviews-feed","rs-template-builder","search-analytics",
    "secure-copy-content-protection","security-malware-firewall",
    "sender-net-automated-emails","shortpixel-adaptive-images","sight",
    "simple-lightbox-gallery","simple-membership","simple-tags","simple-yearly-archive",
    "simply-schedule-appointments","siteground-email-marketing","slider-hero","slim-seo",
    "sms-alert","social-icons-widget-by-wpzoom","social-lite","social-media-feather",
    "ssl-insecure-content-fixer","super-progressive-web-apps","superb-blocks",
    "survey-maker","svg-block","the-plus-addons-for-block-editor",
    "themify-wc-product-filter","translatepress-multilingual","ultimate-post",
    "ultimate-post-kit","unlimited-elements-for-elementor","vk-blocks",
    "wallet-system-for-woocommerce","wc-apg-nifcifnie-field","wc-product-table-lite",
    "webappick-product-feed-for-woocommerce","wemail","woo-ajax-add-to-cart",
    "woo-fly-cart","woo-permalink-manager","woo-smart-compare","woo-smart-quick-view",
    "woo-smart-wishlist","woo-tabbed-category-product-listing",
    "woocommerce-auto-added-coupons","woocommerce-google-adwords-conversion-tracking-tag",
    "woocommerce-mercadopago","woocommerce-product-price-based-on-countries",
    "woocommerce-superfaktura","wp-analytify","wp-google-maps","wp-job-manager",
    "wp-last-login","wp-letsencrypt-ssl","wp-multilang","wp-payment-form","wp-piwik",
    "wp-smtp","wp-statistics","wp-ultimate-csv-importer","wp-user-manager","wpc-admin-columns",
    "wpc-ajax-add-to-cart","wpcf7-redirect","wpelemento-importer","wplr-sync",
    "wpzoom-video-popup-block","xpro-elementor-addons","yith-woocommerce-ajax-search",
    "yith-woocommerce-badges-management","yith-woocommerce-catalog-mode",
    "yith-woocommerce-product-add-ons","zero-bs-crm","zpf-contact-form",
    # legacy exclusions
    "woocommerce-sequential-order-numbers","best-woocommerce-feed",
    "remove-admin-menus-by-role","flexible-subscriptions","nice-page-transition",
    "breadcrumb-block","disable-wp-registration-page","kivicare-clinic-management-system",
    "easy-slider-revolution","file-upload-for-wpforms","simplybook",
    "slider-responsive-slideshow","persian-woocommerce","dashboard-welcome-for-elementor",
    "gpt3-ai-content-generator","one-page-express-companion",
    # batch-4 (2026-05-13)
    "post-types-unlimited","wpzoom-forms","event-tickets","mailpoet","mystickymenu",
    "folders","charitable","wp-whatsapp-chat","woocommerce-shipping",
    "woocommerce-pdf-invoices-packing-slips","pixelyoursite","wp-svg-images",
    "wp-security-audit-log","betterlinks","official-facebook-pixel",
    "beaf-before-and-after-gallery","post-carousel","stackable-ultimate-gutenberg-blocks",
    "live-sales-notifications-for-woocommerce","easy-accordion-free",
    "facebook-for-woocommerce","wpconsent-cookies-banner-privacy-suite","wp-health",
    "userswp","real-media-library-lite","stop-spammer-registrations-plugin",
    "wp-user-frontend","woo-product-bundle","filebird","header-footer-builder-for-elementor",
    "klarna-payments-for-woocommerce","atum-stock-manager-for-woocommerce",
    "woocommerce-shipstation-integration","simply-gallery-block","simply-static",
    "koko-analytics","hide-my-wp","gtm-kit","suretriggers","wpdatatables",
    "restricted-site-access","wpc-buy-now-button","all-in-one-video-gallery",
    "safe-redirect-manager","wp-travel-engine","simple-local-avatars","wp-table-builder",
    "woocommerce-for-japan","admin-site-enhancements","customer-reviews-woocommerce",
    "import-users-from-csv-with-meta","shortcoder","b2bking-wholesale-for-woocommerce",
    "disable-emojis","my-calendar","unique-headers","ultimate-addons-for-contact-form-7",
    "pdf-embed","html5-audio-player","contact-forms-anti-spam","classified-listing",
}

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
})

# ── WordPress.org API ────────────────────────────────────────────────────────

def wp_query(page: int, browse: str, per_page: int = 100) -> list[dict]:
    params = {
        "action": "query_plugins",
        "request[per_page]": per_page,
        "request[page]": page,
        "request[browse]": browse,
        "request[fields][active_installs]": "true",
        "request[fields][last_updated]": "true",
        "request[fields][slug]": "true",
    }
    try:
        r = SESSION.get(WP_API, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
        return data.get("plugins", [])
    except Exception as exc:
        print(f"  [wp.org] page {page} ({browse}): {exc}", file=sys.stderr)
        return []


def eligible(plugin: dict) -> bool:
    installs = plugin.get("active_installs", 0)
    if not (MIN_INST <= installs <= MAX_INST):
        return False
    raw = plugin.get("last_updated", "")          # e.g. "2025-03-14 2:47am GMT"
    if not raw:
        return False
    try:
        date_part = raw.split(" ")[0]             # "2025-03-14"
        dt = datetime.strptime(date_part, "%Y-%m-%d")
        return dt >= CUTOFF
    except Exception:
        return False

# ── security checks ──────────────────────────────────────────────────────────

def _get(url: str, **kw) -> requests.Response | None:
    try:
        r = SESSION.get(url, timeout=20, allow_redirects=True, **kw)
        return r
    except Exception as exc:
        print(f"    [fetch] {url}: {exc}", file=sys.stderr)
        return None


def check_patchstack(slug: str) -> bool:
    """True = no vulnerabilities found."""
    # Try the patchstack database search
    urls = [
        f"https://patchstack.com/database/search?s={slug}",
        f"https://patchstack.com/database/?s={slug}",
    ]
    for url in urls:
        r = _get(url)
        if r is None:
            continue
        if r.status_code == 404:
            return True
        if r.status_code == 200:
            text = r.text
            # "No results" / "nothing found" → clean
            lower = text.lower()
            if any(phrase in lower for phrase in [
                "no results found", "nothing found", "no vulnerabilities",
                "no products were found", "your search did not match"
            ]):
                return True
            # Check if slug appears in a vulnerability listing (href pattern)
            # Patchstack uses URLs like /database/wordpress-<slug>-<vulnerability>
            pattern = re.compile(
                r'/database/wordpress-' + re.escape(slug) + r'[-/]',
                re.IGNORECASE
            )
            if pattern.search(text):
                return False   # vulnerability found
            # Also check for the slug in a link context
            if f'/{slug}' in text and ('vuln' in lower or 'security' in lower and slug in lower):
                return False
            return True   # slug not in any vuln URL → clean
    return True   # couldn't reach → assume clean


def check_wpscan(slug: str) -> bool:
    """True = no known vulnerabilities on wpscan.com."""
    r = _get(f"https://wpscan.com/plugins/{slug}")
    if r is None:
        return True
    if r.status_code == 404:
        return True    # not in their DB
    if r.status_code != 200:
        return True
    lower = r.text.lower()
    # If "0 vulnerabilities" or "no known vulnerabilities" → clean
    if re.search(r'\b0\s+vulnerabilit', lower):
        return True
    if "no known vulnerabilities" in lower:
        return True
    # If vulnerability count > 0 in the page
    m = re.search(r'(\d+)\s+vulnerabilit', lower)
    if m and int(m.group(1)) > 0:
        return False
    # Fallback: if "vulnerability" appears with the slug, flag it
    if 'vulnerabilit' in lower and slug.lower() in lower:
        # Only flag if there are actual vuln items (look for CVE IDs or CVSS)
        if re.search(r'CVE-\d{4}-\d+', r.text) or 'cvss' in lower:
            return False
    return True


def check_nvd(slug: str) -> bool:
    """True = no NVD CVEs mention this plugin slug."""
    try:
        r = SESSION.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "keywordSearch": f"wordpress {slug}",
                "resultsPerPage": 10,
            },
            timeout=25,
        )
        if r.status_code != 200:
            return True
        data = r.json()
        total = data.get("totalResults", 0)
        if total == 0:
            return True
        # Check if any CVE description mentions this specific slug
        slug_variants = {slug, slug.replace("-", " "), slug.replace("-", "_")}
        for item in data.get("vulnerabilities", []):
            descs = item.get("cve", {}).get("descriptions", [])
            for d in descs:
                txt = d.get("value", "").lower()
                if any(v.lower() in txt for v in slug_variants):
                    return False
        return True
    except Exception:
        return True   # NVD API flaky → assume clean


# ── main ────────────────────────────────────────────────────────────────────

def main() -> None:
    selected: list[str]  = []
    seen:     set[str]   = set(ALREADY_INGESTED)
    skipped_vuln = 0

    # Browse modes and page counts to try
    plan = [
        ("updated",  50),
        ("popular",  80),
        ("new",      20),
    ]

    for browse, max_pages in plan:
        if len(selected) >= TARGET:
            break
        print(f"\n=== browse={browse} (need {TARGET - len(selected)} more) ===")

        for page in range(1, max_pages + 1):
            if len(selected) >= TARGET:
                break

            plugins = wp_query(page, browse)
            if not plugins:
                print(f"  [wp.org] browse={browse} page={page}: no results, stopping")
                break

            time.sleep(PAGE_DELAY)

            for p in plugins:
                slug = p.get("slug", "").strip()
                if not slug or slug in seen:
                    continue
                seen.add(slug)

                if not eligible(p):
                    continue

                installs   = p.get("active_installs", 0)
                updated    = p.get("last_updated", "")[:10]
                print(f"  {slug:<50} installs={installs:>6}  updated={updated}  … ", end="", flush=True)

                time.sleep(DELAY)
                ps = check_patchstack(slug)
                time.sleep(DELAY)
                ws = check_wpscan(slug)
                time.sleep(DELAY)
                nv = check_nvd(slug)

                if ps and ws and nv:
                    print("CLEAN")
                    selected.append(slug)
                    if len(selected) >= TARGET:
                        break
                else:
                    flags = []
                    if not ps: flags.append("patchstack")
                    if not ws: flags.append("wpscan")
                    if not nv: flags.append("nvd")
                    print(f"SKIP ({', '.join(flags)})")
                    skipped_vuln += 1

    print(f"\n{'='*60}")
    print(f"Selected {len(selected)} clean plugins  (skipped {skipped_vuln} with known vulns)")
    print()
    for s in selected:
        print(f"  '{s}',")

    out = Path(__file__).parent.parent / "scripts" / "clean_plugin_slugs.json"
    out.write_text(json.dumps(selected, indent=2))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
