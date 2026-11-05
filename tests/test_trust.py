"""Tests for secret encryption, named tokens, audit log, migration."""

import pytest

from linux_health.secrets import SecretBox, load_master_key, require_master_key

try:
    from cryptography.fernet import Fernet

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

needs_crypto = pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography required")


def _key():
    return Fernet.generate_key().decode("ascii")


@needs_crypto
def test_secret_box_roundtrip_and_passthrough():
    box = SecretBox(_key())
    assert box.enabled is True
    token = box.encrypt("s3cr3t")
    assert token.startswith("gAAAAA")
    assert box.decrypt(token) == "s3cr3t"
    assert SecretBox(None).encrypt("plain") == "plain"
    assert SecretBox(None).decrypt("plain") == "plain"
    assert box.decrypt("plain") == "plain"  # legacy tolerance
    assert box.is_encrypted(token) is True
    assert box.is_encrypted("plain") is False


@needs_crypto
def test_master_key_validation(monkeypatch):
    monkeypatch.delenv("AUDITLESS_MASTER_KEY", raising=False)
    assert load_master_key() is None
    assert require_master_key().enabled is False
    monkeypatch.setenv("AUDITLESS_MASTER_KEY", "not-a-key")
    with pytest.raises(RuntimeError, match="invalid"):
        require_master_key()
    monkeypatch.setenv("AUDITLESS_MASTER_KEY", _key())
    assert require_master_key().enabled is True


@needs_crypto
def test_migrate_and_rotate(tmp_path):
    from linux_health.store import Store

    plain = Store(tmp_path / "a")  # no key: plaintext mode
    host = plain.upsert_host("h", "10.0.0.1", "u", auth="key")
    plain.set_host_key(host["id"], "PEM-BYTES")
    sched = plain.create_schedule(
        host["id"], "n", "* * * * *", webhook_url="https://hooks/x"
    )
    assert plain.migrate_secrets() == {"keys": 0, "webhooks": 0}  # no key: no-op

    key1 = _key()
    enc = Store(tmp_path / "a", SecretBox(key1))  # same dir, key on
    assert enc.migrate_secrets() == {"keys": 1, "webhooks": 1}
    raw = enc.key_path(host["id"]).read_text()
    assert raw.startswith("gAAAAA") and "PEM-BYTES" not in raw
    assert enc.migrate_secrets() == {"keys": 0, "webhooks": 0}  # idempotent
    assert enc.read_host_key(host["id"]) == "PEM-BYTES"

    key2 = _key()
    assert enc.rotate_secrets(SecretBox(key1), SecretBox(key2)) == {
        "keys": 1,
        "webhooks": 1,
    }
    enc2 = Store(tmp_path / "a", SecretBox(key2))
    assert enc2.read_host_key(host["id"]) == "PEM-BYTES"
    assert enc2.get_schedule(sched["id"])["webhook_url"].startswith("gAAAAA")


@needs_crypto
def test_tokens_and_audit(tmp_path):
    from linux_health.store import Store

    store = Store(tmp_path / "data")
    created = store.create_token("ci")
    assert created["token"] and created["name"] == "ci"
    listed = store.list_tokens()
    assert len(listed) == 1 and "token" not in listed[0]
    assert "token_hash" not in listed[0]
    row = store.verify_token(created["token"])
    assert row is not None and row["name"] == "ci"
    assert store.verify_token("wrong") is None
    assert store.list_tokens()[0]["last_used"] is not None
    assert store.delete_token(created["id"]) is True
    assert store.verify_token(created["token"]) is None

    assert store.verify_audit() == {"ok": True, "checked": 0, "broken_at": None}
    store.audit("tester", "scan.completed", "scan", "abc", "index=80")
    store.audit("tester", "host.create", "host", "h1", "web")
    assert store.verify_audit()["ok"] is True
    assert [r["action"] for r in store.list_audit()] == [
        "host.create",
        "scan.completed",
    ]
    # Tamper with a row: verification names the break.
    import sqlite3

    with sqlite3.connect(str(store.db_path)) as conn:
        conn.execute("UPDATE audit_log SET detail = 'forged' WHERE id = 1")
        conn.commit()
    result = store.verify_audit()
    assert result["ok"] is False and result["broken_at"] == 1


def test_token_auth_flow_named(client, monkeypatch):
    """Named tokens authenticate with actor attribution; env fallback kept."""
    from linux_health.client import ApiClient, ApiError

    monkeypatch.delenv("AUDITLESS_TOKEN", raising=False)
    assert client.list_hosts() == []  # open mode preserved
    created = client.create_token("ci-pipe")
    token = created["token"]
    authed = ApiClient(client.base_url, token=token)
    assert authed.create_host("n", "h", "u")["name"] == "n"
    with pytest.raises(ApiError) as exc_info:
        ApiClient(client.base_url, token="wrong").list_hosts()
    assert exc_info.value.status == 401
    audit = authed.list_audit()
    assert any(
        r["actor"] == "token:ci-pipe" and r["action"] == "host.create" for r in audit
    )
    assert authed.verify_audit()["ok"] is True
    assert authed.delete_token(created["id"])["deleted"] == created["id"]
    with pytest.raises(ApiError) as exc_info:
        ApiClient(client.base_url, token=token).list_hosts()
    assert exc_info.value.status == 401


@needs_crypto
def test_migrate_rotate_endpoints(client, monkeypatch):
    """Migration + rotation through the API (write-only key material)."""
    host = client.create_host("mig", "10.9.9.9", "u", auth="key")
    client.put_host_key(host["id"], "PEM-MIGRATE")  # plaintext (no key yet)

    key1 = _key()
    monkeypatch.setenv("AUDITLESS_MASTER_KEY", key1)
    from linux_health import dashboard

    dashboard.reset_store()
    assert client.migrate_secrets()["keys"] == 1
    raw = dashboard.get_store().key_path(host["id"]).read_text()
    assert raw.startswith("gAAAAA")

    key2 = _key()
    assert client.rotate_key(key1, key2) == {"keys": 1, "webhooks": 0}
    monkeypatch.setenv("AUDITLESS_MASTER_KEY", key2)
    dashboard.reset_store()
    assert dashboard.get_store().read_host_key(host["id"]) == "PEM-MIGRATE"


def test_boot_refuses_bad_master_key(monkeypatch):
    monkeypatch.setenv("AUDITLESS_MASTER_KEY", "garbage")
    from linux_health import dashboard

    with pytest.raises(RuntimeError, match="invalid"):
        dashboard.serve_forever("127.0.0.1", 18099)
