"""
Tests for hunter.ingestor against 3 known WP.org plugin slugs.
All HTTP calls are mocked — no real network access.
"""
import io
import json
import zipfile
from pathlib import Path

import pytest
import responses as rsps

from hunter.db import get_conn, migrate
from hunter import ingestor as ingestor_mod
from hunter.ingestor import (
    DOWNLOADS_BASE,
    WP_API,
    _already_current,
    _count_php_files,
    _download_zip,
    _fetch_metadata,
    _ingest_one,
    _make_session,
    run_ingest,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEST_SLUGS = ["hello-dolly", "user-role-editor", "simple-tags"]


def _make_zip(slug: str, php_count: int = 6) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{slug}/readme.txt", "=== Plugin ===\nVersion: 1.0")
        for i in range(php_count):
            zf.writestr(f"{slug}/file{i}.php", f"<?php // part {i}")
    return buf.getvalue()


def _meta(slug: str, version="1.2.3", installs=5000, updated="2025-06-01 10:00am GMT") -> dict:
    return {
        "slug": slug,
        "name": slug.replace("-", " ").title(),
        "version": version,
        "active_installs": installs,
        "last_updated": updated,
    }


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Point DB and PLUGINS_DIR at a temp directory for every test."""
    db_file = str(tmp_path / "hunter_test.db")
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()

    monkeypatch.setenv("HUNTER_DB_PATH", db_file)
    monkeypatch.setattr(ingestor_mod, "PLUGINS_DIR", plugins_dir)
    monkeypatch.setattr(ingestor_mod, "RATE_LIMIT", 0)  # no sleeping in tests

    migrate(db_file)
    return tmp_path


# ---------------------------------------------------------------------------
# _fetch_metadata
# ---------------------------------------------------------------------------

@rsps.activate
def test_fetch_metadata_returns_dict_for_known_slug():
    slug = TEST_SLUGS[0]
    rsps.add(rsps.GET, WP_API, json=_meta(slug), status=200)
    meta = _fetch_metadata(slug, _make_session())
    assert meta is not None
    assert meta["slug"] == slug
    assert meta["version"] == "1.2.3"


@rsps.activate
def test_fetch_metadata_returns_none_for_unknown_slug():
    rsps.add(rsps.GET, WP_API, json=False, status=200)
    meta = _fetch_metadata("no-such-plugin-xyz", _make_session())
    assert meta is None


@rsps.activate
def test_fetch_metadata_returns_none_on_http_error():
    rsps.add(rsps.GET, WP_API, status=503)
    meta = _fetch_metadata(TEST_SLUGS[1], _make_session())
    assert meta is None


# ---------------------------------------------------------------------------
# _download_zip / _count_php_files
# ---------------------------------------------------------------------------

@rsps.activate
def test_download_zip_extracts_php_files(tmp_path):
    slug = TEST_SLUGS[0]
    rsps.add(rsps.GET, f"{DOWNLOADS_BASE}/{slug}.latest-stable.zip",
             body=_make_zip(slug, php_count=6), status=200,
             content_type="application/zip")
    dest = tmp_path / slug
    ok = _download_zip(slug, dest, _make_session())
    assert ok is True
    php_files = list(dest.rglob("*.php"))
    assert len(php_files) == 6


@rsps.activate
def test_download_zip_returns_false_on_404(tmp_path):
    slug = TEST_SLUGS[1]
    rsps.add(rsps.GET, f"{DOWNLOADS_BASE}/{slug}.latest-stable.zip", status=404)
    ok = _download_zip(slug, tmp_path / slug, _make_session())
    assert ok is False


def test_count_php_files(tmp_path):
    for i in range(4):
        (tmp_path / f"f{i}.php").write_text("<?php")
    (tmp_path / "style.css").write_text("/* css */")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.php").write_text("<?php")
    assert _count_php_files(tmp_path) == 5


# ---------------------------------------------------------------------------
# _ingest_one — three known slugs
# ---------------------------------------------------------------------------

def _register_slug(slug: str, version="1.0.0", php_count=6):
    rsps.add(rsps.GET, WP_API, json=_meta(slug, version=version), status=200)
    rsps.add(
        rsps.GET, f"{DOWNLOADS_BASE}/{slug}.latest-stable.zip",
        body=_make_zip(slug, php_count=php_count), status=200,
        content_type="application/zip",
    )


@rsps.activate
@pytest.mark.parametrize("slug", TEST_SLUGS)
def test_ingest_one_stores_plugin_in_db(slug):
    _register_slug(slug)
    result = _ingest_one(slug, _make_session())
    assert result == "ingested"
    row = get_conn().execute("SELECT * FROM plugins WHERE slug=?", (slug,)).fetchone()
    assert row is not None
    assert row["slug"] == slug
    assert row["version"] == "1.0.0"
    assert row["active_installs"] == 5000


@rsps.activate
def test_ingest_one_skips_already_current_version():
    slug = TEST_SLUGS[0]
    _register_slug(slug, version="2.0.0")
    _ingest_one(slug, _make_session())          # first ingest

    # Re-register same slug/version; second call should skip
    rsps.add(rsps.GET, WP_API, json=_meta(slug, version="2.0.0"), status=200)
    result = _ingest_one(slug, _make_session())
    assert result == "skipped"


@rsps.activate
def test_ingest_one_skips_plugin_with_too_few_php_files():
    slug = TEST_SLUGS[1]
    _register_slug(slug, php_count=2)  # below MIN_PHP=5
    result = _ingest_one(slug, _make_session())
    assert result == "skipped"
    row = get_conn().execute("SELECT * FROM plugins WHERE slug=?", (slug,)).fetchone()
    assert row is None  # not stored


@rsps.activate
def test_ingest_one_returns_error_when_metadata_missing():
    rsps.add(rsps.GET, WP_API, json=False, status=200)
    result = _ingest_one("ghost-plugin", _make_session())
    assert result == "error"


# ---------------------------------------------------------------------------
# run_ingest — integration
# ---------------------------------------------------------------------------

@rsps.activate
def test_run_ingest_with_slugs(capsys):
    for slug in TEST_SLUGS:
        _register_slug(slug)

    run_ingest(slugs=",".join(TEST_SLUGS))

    out = capsys.readouterr().out
    assert "ingested=3" in out

    rows = get_conn().execute("SELECT slug FROM plugins ORDER BY slug").fetchall()
    assert [r["slug"] for r in rows] == sorted(TEST_SLUGS)


@rsps.activate
def test_run_ingest_skips_denylist(capsys):
    _register_slug("hello-dolly")
    run_ingest(slugs="hello-dolly,woocommerce")

    out = capsys.readouterr().out
    assert "denylist" in out
    rows = get_conn().execute("SELECT slug FROM plugins").fetchall()
    assert len(rows) == 1
    assert rows[0]["slug"] == "hello-dolly"


@rsps.activate
def test_run_ingest_no_args_prints_usage(capsys):
    run_ingest()
    out = capsys.readouterr().out
    assert "--slugs" in out or "--filter" in out
