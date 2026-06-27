import io
import shutil
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from hunter.db import get_conn

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PLUGINS_DIR = PROJECT_ROOT / "plugins"
WP_API = "https://api.wordpress.org/plugins/info/1.2/"
DOWNLOADS_BASE = "https://downloads.wordpress.org/plugin"
RATE_LIMIT = 1.0  # seconds between outbound requests

DENYLIST = {
    "woocommerce", "elementor", "elementor-pro", "wordpress-seo",
    "contact-form-7", "akismet", "jetpack", "classic-editor", "wordfence",
    "bbpress", "buddypress",
}

MIN_PHP = 5
MAX_PHP = 5000


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "wp-hunter/0.1 (security research; responsible disclosure)"
    return s


def _fetch_metadata(slug: str, session: requests.Session) -> dict | None:
    params = {
        "action": "plugin_information",
        "request[slug]": slug,
        "request[fields][active_installs]": 1,
        "request[fields][last_updated]": 1,
    }
    resp = session.get(WP_API, params=params, timeout=15)
    if resp.status_code != 200:
        return None
    data = resp.json()
    # WP.org returns JSON false for unknown slugs
    if not isinstance(data, dict):
        return None
    return data


def _download_zip(slug: str, dest: Path, session: requests.Session) -> bool:
    url = f"{DOWNLOADS_BASE}/{slug}.latest-stable.zip"
    resp = session.get(url, timeout=60)
    if resp.status_code != 200:
        return False

    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        for member in zf.infolist():
            parts = Path(member.filename).parts
            if len(parts) < 2:
                continue
            rel = Path(*parts[1:])  # strip top-level {slug}/ folder
            target = dest / rel
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(member.filename))
    return True


def _count_php_files(path: Path) -> int:
    return sum(1 for _ in path.rglob("*.php"))


def _already_current(slug: str, version: str) -> bool:
    row = get_conn().execute(
        "SELECT version FROM plugins WHERE slug = ?", (slug,)
    ).fetchone()
    return row is not None and row["version"] == version


def _store_plugin(slug: str, meta: dict, source_path: Path) -> None:
    conn = get_conn()
    conn.execute(
        """INSERT INTO plugins (slug, name, version, active_installs, last_updated, source_path, ingested_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(slug) DO UPDATE SET
               name=excluded.name, version=excluded.version,
               active_installs=excluded.active_installs,
               last_updated=excluded.last_updated,
               source_path=excluded.source_path,
               ingested_at=excluded.ingested_at""",
        (
            slug,
            meta.get("name", slug),
            meta.get("version", "unknown"),
            meta.get("active_installs", 0),
            meta.get("last_updated", ""),
            str(source_path),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


def _ingest_one(slug: str, session: requests.Session) -> str:
    """Download and store one plugin. Returns: 'ingested' | 'skipped' | 'error'."""
    meta = _fetch_metadata(slug, session)
    time.sleep(RATE_LIMIT)
    if not meta:
        return "error"

    version = meta.get("version", "unknown")
    if _already_current(slug, version):
        return "skipped"

    dest = PLUGINS_DIR / slug
    ok = _download_zip(slug, dest, session)
    time.sleep(RATE_LIMIT)
    if not ok:
        return "error"

    php_count = _count_php_files(dest)
    if php_count < MIN_PHP or php_count > MAX_PHP:
        shutil.rmtree(dest, ignore_errors=True)
        return "skipped"

    _store_plugin(slug, meta, dest)
    return "ingested"


def _slugs_from_filter(filter_expr: str, limit: int, session: requests.Session) -> list[str]:
    """Query WP.org API and return slugs matching the filter expression."""
    min_inst, max_inst = 1000, 50000
    max_age_months = 24

    for part in filter_expr.split(","):
        part = part.strip()
        if part.startswith("installs:") and "-" in part:
            lo, hi = part[9:].split("-")
            min_inst, max_inst = int(lo), int(hi)
        elif part.startswith("updated:<") and part.endswith("mo"):
            max_age_months = int(part[9:-2])

    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_months * 30)
    slugs: list[str] = []
    page = 1

    while len(slugs) < limit:
        params = {
            "action": "query_plugins",
            "request[page]": page,
            "request[per_page]": 100,
            "request[browse]": "updated",
        }
        resp = session.get(WP_API, params=params, timeout=15)
        time.sleep(RATE_LIMIT)
        if resp.status_code != 200:
            break

        plugins = resp.json().get("plugins", [])
        if not plugins:
            break

        for p in plugins:
            slug = p.get("slug", "")
            if slug in DENYLIST:
                continue
            if not (min_inst <= p.get("active_installs", 0) <= max_inst):
                continue
            updated_str = p.get("last_updated", "")
            try:
                updated = datetime.strptime(updated_str, "%Y-%m-%d %I:%M%p GMT").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if updated < cutoff:
                continue
            slugs.append(slug)
            if len(slugs) >= limit:
                break

        page += 1

    return slugs


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_ingest(
    slugs: str | None = None,
    filter_expr: str | None = None,
    limit: int = 50,
) -> None:
    import click

    PLUGINS_DIR.mkdir(exist_ok=True)
    session = _make_session()

    if slugs:
        slug_list = [s.strip() for s in slugs.split(",") if s.strip()]
    elif filter_expr:
        click.echo(f"[ingest] Querying WP.org for: {filter_expr}")
        slug_list = _slugs_from_filter(filter_expr, limit, session)
        click.echo(f"[ingest] {len(slug_list)} candidates found")
    else:
        click.echo("[ingest] Provide --slugs or --filter.")
        return

    ingested = skipped = errors = 0
    for slug in slug_list:
        if slug in DENYLIST:
            click.echo(f"[ingest] skip {slug} (denylist)")
            skipped += 1
            continue
        click.echo(f"[ingest] {slug} ...", nl=False)
        result = _ingest_one(slug, session)
        click.echo(f" {result}")
        if result == "ingested":
            ingested += 1
        elif result == "skipped":
            skipped += 1
        else:
            errors += 1

    click.echo(f"[ingest] done — ingested={ingested} skipped={skipped} errors={errors}")
