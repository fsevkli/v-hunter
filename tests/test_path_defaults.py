from pathlib import Path

from hunter import db, ingestor


def test_default_plugins_dir_is_repo_root():
    root = Path(ingestor.__file__).resolve().parent.parent

    assert ingestor.PLUGINS_DIR == root / "plugins"
    assert ingestor.PLUGINS_DIR.is_absolute()


def test_default_db_path_is_repo_root(monkeypatch):
    monkeypatch.delenv("HUNTER_DB_PATH", raising=False)
    root = Path(db.__file__).resolve().parent.parent

    assert Path(db._db_path()) == root / "hunter.db"


def test_hunter_db_path_env_override_still_wins(monkeypatch, tmp_path):
    db_path = tmp_path / "custom.db"
    monkeypatch.setenv("HUNTER_DB_PATH", str(db_path))

    assert db._db_path() == str(db_path)
