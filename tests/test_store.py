"""Tests for SQLite persistence (hosts, keys metadata, reports)."""

import os
import stat
from pathlib import Path

import pytest

from linux_health.store import Store, data_dir


@pytest.fixture()
def store(tmp_path):
    """Isolated store (never touches the real ./data)."""
    return Store(tmp_path / "data")


def test_data_dir_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITLESS_DATA_DIR", str(tmp_path / "custom"))
    assert data_dir() == tmp_path / "custom"
    assert (tmp_path / "custom").is_dir()


def test_data_dir_default_is_relative_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unset AUDITLESS_DATA_DIR resolves to ./data, created on demand."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AUDITLESS_DATA_DIR", raising=False)
    assert data_dir() == Path("data")
    assert (tmp_path / "data").is_dir()


def test_host_crud(store):
    host = store.upsert_host("web", "10.0.0.1", "admin", port=2222, auth="key")
    assert host["name"] == "web"
    assert host["has_key"] == 0
    assert store.get_host(host["id"])["hostname"] == "10.0.0.1"
    assert len(store.list_hosts()) == 1
    assert store.get_host("missing") is None
    assert store.delete_host(host["id"]) is True
    assert store.delete_host(host["id"]) is False
    assert store.list_hosts() == []


def test_host_auth_validated(store):
    with pytest.raises(ValueError, match="auth must be"):
        store.upsert_host("x", "h", "u", auth="token")


def test_key_bytes_never_in_records(store):
    host = store.upsert_host("k", "h", "u", auth="key")
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nSENTINEL-KEY-BYTES\n"
    store.set_host_key(host["id"], secret)
    assert store.has_host_key(host["id"]) is True
    assert store.get_host(host["id"])["has_key"] == 1
    path = store.key_path(host["id"])
    assert path.read_text() == secret
    if os.name != "nt":  # Windows has no POSIX permission bits
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, oct(mode)
    # Metadata-only: no public surface carries the bytes.
    dumped = repr(store.get_host(host["id"])) + repr(store.list_hosts())
    assert "SENTINEL-KEY-BYTES" not in dumped
    store.clear_host_key(host["id"])
    assert store.has_host_key(host["id"]) is False
    assert not path.exists()
    with pytest.raises(KeyError):
        store.set_host_key("missing", secret)


def test_report_roundtrip(store):
    report = {"summary": {"hardening_index": 82}, "checks": []}
    store.save_report("r1", "h", "u", "done", report, None, "host1", 1.0, 2.0)
    store.save_report("r2", "h", "u", "error", None, "boom", None, 3.0, 4.0)
    rows = store.list_reports()
    assert [r["id"] for r in rows] == ["r2", "r1"]
    assert rows[0]["hardening_index"] is None
    assert store.list_reports(host_id="host1")[0]["id"] == "r1"
    import json

    full = store.get_report("r1")
    assert json.loads(full["report_json"])["summary"]["hardening_index"] == 82
    assert store.get_report("missing") is None
    assert store.delete_report("r1") is True
    assert store.delete_report("r1") is False


def test_host_id_traversal_rejected(store, tmp_path):
    """Hostile ids must never reach the filesystem (CodeQL py/path-injection)."""
    from linux_health.store import _safe_id

    for hostile in ("../escape", "..\\escape", "a/b", "", "x" * 65, ".", "a b"):
        with pytest.raises(ValueError):
            _safe_id(hostile)
        with pytest.raises(ValueError):
            store.key_path(hostile)
    # Unknown hostile ids vanish as 404-shaped KeyErrors, touching nothing.
    outside = tmp_path / "data" / "escape"
    assert not outside.exists()
    assert store.delete_host("../escape") is False
    assert not outside.exists()


def test_jump_host_fields_and_keys(store):
    """Jump columns persist; jump keys live apart from host keys."""
    host = store.upsert_host(
        "j",
        "inner",
        "u",
        jump_hostname="bastion",
        jump_port=2222,
        jump_username="b",
        jump_auth="key",
    )
    assert host["jump_hostname"] == "bastion"
    assert host["has_jump_key"] == 0
    store.set_host_key(host["id"], "HOST-PEM", kind="jump")
    assert store.get_host(host["id"])["has_jump_key"] == 1
    assert store.read_host_key(host["id"], kind="jump") == "HOST-PEM"
    assert store.key_path(host["id"], kind="jump").name.endswith(".jump")
    with pytest.raises(ValueError, match="kind must be"):
        store.set_host_key(host["id"], "x", kind="weird")
    store.clear_host_key(host["id"], kind="jump")
    assert store.get_host(host["id"])["has_jump_key"] == 0


def test_legacy_db_gains_jump_columns(tmp_path):
    """Stores created before jump support migrate on open."""
    import sqlite3

    from linux_health.store import Store

    directory = tmp_path / "legacy"
    directory.mkdir()
    with sqlite3.connect(str(directory / "auditless.db")) as conn:
        conn.execute(
            "CREATE TABLE hosts (id TEXT PRIMARY KEY, name TEXT, hostname TEXT,"
            " port INTEGER, username TEXT, auth TEXT, has_key INTEGER,"
            " created_at REAL, updated_at REAL)"
        )
        conn.execute(
            "INSERT INTO hosts VALUES ('h1','n','h',22,'u','password',0,1.0,2.0)"
        )
        conn.commit()
    store = Store(directory)
    row = store.get_host("h1")
    assert row["jump_hostname"] == ""
    assert row["jump_port"] == 22
    updated = store.upsert_host("n", "h", "u", host_id="h1", jump_hostname="b")
    assert updated["jump_hostname"] == "b"


def test_backup_roundtrip_and_prune(store):
    """Snapshots restore fully; only the newest `keep` are retained."""
    store.upsert_host("b", "h", "u")
    first = store.backup(keep=2)
    assert first.exists()
    restored = Store(first.parent.parent)
    assert [h["name"] for h in restored.list_hosts()] == ["b"]
    # Rapid snapshots get unique names; only newest `keep` are retained.
    for _ in range(3):
        store.backup(keep=2)
    remaining = sorted((store.directory / "backups").glob("auditless-*.db"))
    assert len(remaining) == 2
