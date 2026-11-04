"""Tests for SQLite persistence (hosts, keys metadata, reports)."""

import os
import stat

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
