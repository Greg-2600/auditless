"""SQLite persistence for hosts, keys metadata, and scan reports.

Storage layout (stdlib sqlite3, no new dependencies):
    $AUDITLESS_DATA_DIR
      auditless.db        hosts + scan reports (JSON payloads)
      keys/<host_id>      private key material, mode 0600, never in the DB

Data-directory rule (single source of truth — see :func:`data_dir`):
    - Unset ``AUDITLESS_DATA_DIR`` → relative ``./data`` under the current
      working directory, created on demand.
    - Containers set ``AUDITLESS_DATA_DIR=/app/data`` explicitly
      (docker-compose.yml, backed by the ``auditless-data`` volume;
      Dockerfile creates and declares it). Nothing else overrides it.

Only key *metadata* (has_key flag) is exposed via the API. Key bytes are
written to disk with owner-only permissions and are never returned,
logged, or included in any response.
"""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


def data_dir() -> Path:
    """Resolve the data directory (env override, created on demand).

    Unset ``AUDITLESS_DATA_DIR`` means relative ``./data``; containers
    pass ``/app/data`` explicitly (see module docstring).
    """
    path = Path(os.environ.get("AUDITLESS_DATA_DIR", "data"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_id(host_id: str) -> str:
    """Validate an id before it touches the filesystem (traversal guard)."""
    import re

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", host_id or ""):
        raise ValueError(f"invalid host id: {host_id!r}")
    return host_id


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Row-factory connection that commits and closes on exit."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL,
    auth TEXT NOT NULL DEFAULT 'password',
    has_key INTEGER NOT NULL DEFAULT 0,
    jump_hostname TEXT NOT NULL DEFAULT '',
    jump_port INTEGER NOT NULL DEFAULT 22,
    jump_username TEXT NOT NULL DEFAULT '',
    jump_auth TEXT NOT NULL DEFAULT 'password',
    has_jump_key INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    host_id TEXT,
    hostname TEXT NOT NULL,
    username TEXT NOT NULL,
    status TEXT NOT NULL,
    hardening_index INTEGER,
    error TEXT,
    report_json TEXT,
    created_at REAL NOT NULL,
    finished_at REAL
);
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    name TEXT NOT NULL,
    cron TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT '',
    webhook_url TEXT NOT NULL DEFAULT '',
    notify_on TEXT NOT NULL DEFAULT 'regression',
    min_index INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run REAL,
    next_run REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_used REAL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL DEFAULT ''
);
"""


class Store:
    """Small typed wrapper around the auditless SQLite database."""

    def __init__(self, directory: Path | None = None, secrets: Any = None) -> None:
        from .secrets import SecretBox, load_master_key

        self.directory = directory or data_dir()
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / "keys").mkdir(exist_ok=True)
        self.db_path = self.directory / "auditless.db"
        self.secrets = secrets if secrets is not None else SecretBox(load_master_key())
        with _connect(self.db_path) as conn:
            conn.executescript(_SCHEMA)
            existing = {row[1] for row in conn.execute("PRAGMA table_info(hosts)")}
            for column, ddl in (
                ("jump_hostname", "TEXT NOT NULL DEFAULT ''"),
                ("jump_port", "INTEGER NOT NULL DEFAULT 22"),
                ("jump_username", "TEXT NOT NULL DEFAULT ''"),
                ("jump_auth", "TEXT NOT NULL DEFAULT 'password'"),
                ("has_jump_key", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in existing:
                    conn.execute(f"ALTER TABLE hosts ADD COLUMN {column} {ddl}")

    # -- hosts --------------------------------------------------------

    def upsert_host(
        self,
        name: str,
        hostname: str,
        username: str,
        port: int = 22,
        auth: str = "password",
        host_id: str | None = None,
        jump_hostname: str = "",
        jump_port: int = 22,
        jump_username: str = "",
        jump_auth: str = "password",
    ) -> dict:
        """Create or replace a host record (key material untouched)."""
        if auth not in ("password", "key"):
            raise ValueError("auth must be 'password' or 'key'")
        if jump_auth not in ("password", "key"):
            raise ValueError("jump_auth must be 'password' or 'key'")
        now = time.time()
        hid = host_id or uuid.uuid4().hex[:12]
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT has_key, has_jump_key FROM hosts WHERE id = ?", (hid,)
            ).fetchone()
            has_key = row["has_key"] if row else 0
            has_jump_key = row["has_jump_key"] if row else 0
            conn.execute(
                "INSERT OR REPLACE INTO hosts"
                " (id, name, hostname, port, username, auth, has_key,"
                " jump_hostname, jump_port, jump_username, jump_auth,"
                " has_jump_key, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE("
                "  (SELECT created_at FROM hosts WHERE id = ?), ?), ?)",
                (
                    hid,
                    name,
                    hostname,
                    port,
                    username,
                    auth,
                    has_key,
                    jump_hostname,
                    jump_port,
                    jump_username,
                    jump_auth,
                    has_jump_key,
                    hid,
                    now,
                    now,
                ),
            )
        result = self.get_host(hid)
        assert result is not None
        return result

    def get_host(self, host_id: str) -> dict | None:
        """Fetch one host record (metadata only, never key bytes)."""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM hosts WHERE id = ?", (host_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_hosts(self) -> list[dict]:
        """All hosts, newest first."""
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM hosts ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_host(self, host_id: str) -> bool:
        """Delete a host and all its stored key material."""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM hosts WHERE id = ?", (host_id,)
            ).fetchone()
            if row is None:
                return False
            self.clear_host_key(host_id)
            self.clear_host_key(host_id, kind="jump")
            conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        return True

    # -- keys (bytes on disk, 0600, write-only via API) ----------------

    @staticmethod
    def _key_kind(kind: str) -> str:
        if kind not in ("host", "jump"):
            raise ValueError("kind must be 'host' or 'jump'")
        return kind

    def key_path(self, host_id: str, kind: str = "host") -> Path:
        """Filesystem location for a key (guarded; jump keys get .jump)."""
        safe = _safe_id(host_id)
        self._key_kind(kind)
        name = safe if kind == "host" else f"{safe}.jump"
        return self.directory / "keys" / name

    def _key_flag(self, kind: str) -> str:
        return "has_key" if kind == "host" else "has_jump_key"

    def set_host_key(self, host_id: str, key_text: str, kind: str = "host") -> None:
        """Store key bytes (encrypted when configured) with 0600 perms."""
        row = self.get_host(host_id)
        if row is None:
            raise KeyError(f"unknown host {host_id}")
        # Path derives from the stored row, never the request value.
        path = self.key_path(row["id"], kind)
        path.write_text(self.secrets.encrypt(key_text), encoding="utf-8")
        os.chmod(path, 0o600)
        with _connect(self.db_path) as conn:
            conn.execute(
                f"UPDATE hosts SET {self._key_flag(kind)} = 1, updated_at = ?"
                " WHERE id = ?",
                (time.time(), host_id),
            )

    def read_host_key(self, host_id: str, kind: str = "host") -> str:
        """Load and decrypt a host key (server-side use only)."""
        row = self.get_host(host_id)
        if row is None:
            raise KeyError(f"unknown host {host_id}")
        return self.secrets.decrypt(
            self.key_path(row["id"], kind).read_text(encoding="utf-8")
        )

    def clear_host_key(self, host_id: str, kind: str = "host") -> None:
        """Remove stored key bytes and clear the flag (idempotent)."""
        row = self.get_host(host_id)
        if row is None:
            return
        try:
            self.key_path(row["id"], kind).unlink()
        except FileNotFoundError:
            pass
        with _connect(self.db_path) as conn:
            conn.execute(
                f"UPDATE hosts SET {self._key_flag(kind)} = 0, updated_at = ?"
                " WHERE id = ?",
                (time.time(), host_id),
            )

    def has_host_key(self, host_id: str, kind: str = "host") -> bool:
        """Whether key bytes exist on disk for the host."""
        row = self.get_host(host_id)
        if row is None:
            return False
        return self.key_path(row["id"], kind).exists()

    def webhook_for(self, schedule: dict) -> str:
        """Decrypt a schedule's webhook URL (server-side delivery only)."""
        return self.secrets.decrypt(schedule.get("webhook_url") or "")

    # -- api tokens ---------------------------------------------------

    @staticmethod
    def _hash_token(token: str) -> str:
        import hashlib

        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_token(self, name: str) -> dict:
        """Create a named token; plaintext is returned exactly once."""
        import secrets as _secrets

        raw = _secrets.token_urlsafe(32)
        tid = uuid.uuid4().hex[:12]
        now = time.time()
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO api_tokens (id, name, token_hash, created_at,"
                " last_used) VALUES (?, ?, ?, ?, NULL)",
                (tid, name, self._hash_token(raw), now),
            )
        return {"id": tid, "name": name, "token": raw, "created_at": now}

    def list_tokens(self) -> list[dict]:
        """Token metadata (hashes and plaintext never exposed)."""
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, name, created_at, last_used FROM api_tokens"
                " ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_token(self, token: str) -> dict | None:
        """Constant-time check; touches last_used on success."""
        import hmac

        digest = self._hash_token(token)
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM api_tokens").fetchall()
            for row in rows:
                if hmac.compare_digest(row["token_hash"], digest):
                    conn.execute(
                        "UPDATE api_tokens SET last_used = ? WHERE id = ?",
                        (time.time(), row["id"]),
                    )
                    return {
                        "id": row["id"],
                        "name": row["name"],
                        "created_at": row["created_at"],
                        "last_used": row["last_used"],
                    }
        return None

    def delete_token(self, token_id: str) -> bool:
        """Revoke a token."""
        with _connect(self.db_path) as conn:
            cursor: sqlite3.Cursor = conn.execute(
                "DELETE FROM api_tokens WHERE id = ?", (token_id,)
            )
        return cursor.rowcount > 0

    # -- audit log ----------------------------------------------------

    @staticmethod
    def _audit_hash(
        prev: str,
        ts: float,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        detail: str,
    ) -> str:
        import hashlib

        body = "|".join([prev, repr(ts), actor, action, target_type, target_id, detail])
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def audit(
        self,
        actor: str,
        action: str,
        target_type: str = "",
        target_id: str = "",
        detail: str = "",
    ) -> int:
        """Append a tamper-evident audit record; returns its id."""
        with _connect(self.db_path) as conn:
            last = conn.execute(
                "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev = last["hash"] if last else ""
            ts = time.time()
            digest = self._audit_hash(
                prev, ts, actor, action, target_type, target_id, detail
            )
            cursor = conn.execute(
                "INSERT INTO audit_log (ts, actor, action, target_type,"
                " target_id, detail, prev_hash, hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, actor, action, target_type, target_id, detail, prev, digest),
            )
            rowid: int = cursor.lastrowid or 0
            return rowid

    def list_audit(self, limit: int = 100) -> list[dict]:
        """Recent audit records, newest first."""
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_audit(self) -> dict:
        """Recompute the hash chain; reports first break, if any."""
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        prev = ""
        checked = 0
        for row in rows:
            expected = self._audit_hash(
                prev,
                row["ts"],
                row["actor"],
                row["action"],
                row["target_type"],
                row["target_id"],
                row["detail"],
            )
            if row["prev_hash"] != prev or row["hash"] != expected:
                return {"ok": False, "checked": checked, "broken_at": row["id"]}
            prev = row["hash"]
            checked += 1
        return {"ok": True, "checked": checked, "broken_at": None}

    # -- secret migration & rotation ----------------------------------

    def migrate_secrets(self) -> dict:
        """Encrypt any plaintext secrets in place (idempotent)."""
        keys = webhooks = 0
        for host in self.list_hosts():
            for kind, flag in (("host", "has_key"), ("jump", "has_jump_key")):
                if not host[flag]:
                    continue
                raw = self.key_path(host["id"], kind).read_text(encoding="utf-8")
                if self.secrets.enabled and not self.secrets.is_encrypted(raw):
                    self.set_host_key(host["id"], self.secrets.decrypt(raw), kind=kind)
                    keys += 1
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, webhook_url FROM schedules WHERE webhook_url != ''"
            ).fetchall()
        for row in rows:
            if self.secrets.enabled and not self.secrets.is_encrypted(
                row["webhook_url"]
            ):
                with _connect(self.db_path) as conn:
                    conn.execute(
                        "UPDATE schedules SET webhook_url = ?, updated_at = ?"
                        " WHERE id = ?",
                        (
                            self.secrets.encrypt(row["webhook_url"]),
                            time.time(),
                            row["id"],
                        ),
                    )
                webhooks += 1
        return {"keys": keys, "webhooks": webhooks}

    def rotate_secrets(self, old_box: Any, new_box: Any) -> dict:
        """Re-encrypt every stored secret (caller swaps the env key after)."""
        keys = webhooks = 0
        for host in self.list_hosts():
            for kind, flag in (("host", "has_key"), ("jump", "has_jump_key")):
                if not host[flag]:
                    continue
                raw = self.key_path(host["id"], kind).read_text(encoding="utf-8")
                plain = old_box.decrypt(raw)
                self.key_path(host["id"], kind).write_text(
                    new_box.encrypt(plain), encoding="utf-8"
                )
                keys += 1
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, webhook_url FROM schedules WHERE webhook_url != ''"
            ).fetchall()
        for row in rows:
            plain = old_box.decrypt(row["webhook_url"])
            with _connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE schedules SET webhook_url = ?, updated_at = ?"
                    " WHERE id = ?",
                    (new_box.encrypt(plain), time.time(), row["id"]),
                )
            webhooks += 1
        return {"keys": keys, "webhooks": webhooks}

    # -- reports ------------------------------------------------------

    def save_report(
        self,
        report_id: str,
        hostname: str,
        username: str,
        status: str,
        report: dict | None,
        error: str | None,
        host_id: str | None,
        created_at: float,
        finished_at: float | None,
    ) -> None:
        """Persist a finished scan (credentials never included)."""
        import json

        hardening = None
        if report:
            hardening = (report.get("summary") or {}).get("hardening_index")
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reports (id, host_id, hostname, username,"
                " status, hardening_index, error, report_json, created_at,"
                " finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report_id,
                    host_id,
                    hostname,
                    username,
                    status,
                    hardening,
                    error,
                    json.dumps(report) if report else None,
                    created_at,
                    finished_at,
                ),
            )

    def get_report(self, report_id: str) -> dict | None:
        """Fetch one stored report row (payload still JSON-encoded)."""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_reports(self, host_id: str | None = None, limit: int = 50) -> list[dict]:
        """Stored reports, newest first, optionally filtered by host."""
        with _connect(self.db_path) as conn:
            if host_id:
                rows = conn.execute(
                    "SELECT id, host_id, hostname, username, status,"
                    " hardening_index, error, created_at, finished_at"
                    " FROM reports WHERE host_id = ? ORDER BY created_at DESC"
                    " LIMIT ?",
                    (host_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, host_id, hostname, username, status,"
                    " hardening_index, error, created_at, finished_at"
                    " FROM reports ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def delete_report(self, report_id: str) -> bool:
        """Forget a stored report."""
        with _connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        return cursor.rowcount > 0

    # -- schedules ----------------------------------------------------

    def create_schedule(
        self,
        host_id: str,
        name: str,
        cron: str,
        profile: str = "",
        webhook_url: str = "",
        notify_on: str = "regression",
        min_index: int | None = None,
        enabled: bool = True,
    ) -> dict:
        """Create a scan schedule (validates host, cron, and policy)."""
        from .cron import CronExpr

        if not self.get_host(host_id):
            raise KeyError(f"unknown host {host_id}")
        if notify_on not in ("regression", "threshold", "always", "never"):
            raise ValueError(f"bad notify_on: {notify_on!r}")
        CronExpr(cron)  # raises ValueError when invalid
        now = time.time()
        sid = uuid.uuid4().hex[:12]
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO schedules (id, host_id, name, cron, profile,"
                " webhook_url, notify_on, min_index, enabled, last_run,"
                " next_run, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)",
                (
                    sid,
                    host_id,
                    name,
                    cron,
                    profile,
                    webhook_url,
                    notify_on,
                    min_index,
                    int(enabled),
                    now,
                    now,
                ),
            )
        self._refresh_next_run(sid)
        result = self.get_schedule(sid)
        assert result is not None
        return result

    def _refresh_next_run(self, schedule_id: str) -> None:
        """Recompute next_run from the cron expression (now-based)."""
        import datetime

        from .cron import CronExpr

        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT cron FROM schedules WHERE id = ?", (schedule_id,)
            ).fetchone()
            if row is None:
                return
            nxt = CronExpr(row["cron"]).next_after(datetime.datetime.now())
            conn.execute(
                "UPDATE schedules SET next_run = ?, updated_at = ? WHERE id = ?",
                (nxt.timestamp(), time.time(), schedule_id),
            )

    def get_schedule(self, schedule_id: str) -> dict | None:
        """Fetch one schedule row (includes webhook URL: server-side only)."""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM schedules WHERE id = ?", (schedule_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_schedules(self, enabled_only: bool = False) -> list[dict]:
        """All schedules, newest first."""
        with _connect(self.db_path) as conn:
            if enabled_only:
                rows = conn.execute(
                    "SELECT * FROM schedules WHERE enabled = 1"
                    " ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM schedules ORDER BY created_at DESC"
                ).fetchall()
        return [dict(row) for row in rows]

    def update_schedule(self, schedule_id: str, **fields: object) -> dict | None:
        """Partial update (recomputes next_run when cron changes)."""
        allowed = {
            "name",
            "cron",
            "profile",
            "webhook_url",
            "notify_on",
            "min_index",
            "enabled",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if "notify_on" in updates and updates["notify_on"] not in (
            "regression",
            "threshold",
            "always",
            "never",
        ):
            raise ValueError(f"bad notify_on: {updates['notify_on']!r}")
        if "cron" in updates:
            from .cron import CronExpr

            CronExpr(str(updates["cron"]))
        if "enabled" in updates:
            updates["enabled"] = int(bool(updates["enabled"]))
        if not updates:
            return self.get_schedule(schedule_id)
        with _connect(self.db_path) as conn:
            if not conn.execute(
                "SELECT id FROM schedules WHERE id = ?", (schedule_id,)
            ).fetchone():
                return None
            sets = ", ".join(f"{k} = ?" for k in updates)
            conn.execute(
                f"UPDATE schedules SET {sets}, updated_at = ? WHERE id = ?",
                (*updates.values(), time.time(), schedule_id),
            )
        if "cron" in updates:
            self._refresh_next_run(schedule_id)
        return self.get_schedule(schedule_id)

    def delete_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule."""
        with _connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        return cursor.rowcount > 0

    # -- maintenance --------------------------------------------------

    def backup(self, keep: int = 7) -> Path:
        """Snapshot the database (prunes to the newest `keep` copies)."""
        import contextlib

        dest_dir = self.directory / "backups"
        dest_dir.mkdir(exist_ok=True)
        dest = (
            dest_dir
            / f"auditless-{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000:06d}.db"
        )
        with _connect(self.db_path) as source:
            target = sqlite3.connect(str(dest))
            try:
                source.backup(target)
            finally:
                target.close()
        # Prune oldest-first by mtime (names can wrap the ns counter).
        by_age = sorted(
            dest_dir.glob("auditless-*.db"),
            key=lambda candidate: (
                candidate.stat().st_mtime_ns,
                candidate.name,
            ),
        )
        for old in by_age[:-keep] if keep else []:
            with contextlib.suppress(OSError):
                old.unlink()
        return dest

    def mark_schedule_run(self, schedule_id: str) -> None:
        """Record a run and advance next_run (best effort)."""
        try:
            with _connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE schedules SET last_run = ?, updated_at = ? WHERE id = ?",
                    (time.time(), time.time(), schedule_id),
                )
            self._refresh_next_run(schedule_id)
        except Exception:
            pass
