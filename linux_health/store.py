"""SQLite persistence for hosts, keys metadata, and scan reports.

Storage layout (stdlib sqlite3, no new dependencies):
    $AUDITLESS_DATA_DIR (default ./data)
      auditless.db        hosts + scan reports (JSON payloads)
      keys/<host_id>      private key material, mode 0600, never in the DB

Only key *metadata* (has_key flag) is exposed via the API. Key bytes are
written to disk with owner-only permissions and are never returned,
logged, or included in any response.
"""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from pathlib import Path


def data_dir() -> Path:
    """Resolve the data directory (env override, created on demand)."""
    path = Path(os.environ.get("AUDITLESS_DATA_DIR", "data"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_id(host_id: str) -> str:
    """Validate an id before it touches the filesystem (traversal guard)."""
    import re

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", host_id or ""):
        raise ValueError(f"invalid host id: {host_id!r}")
    return host_id


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL,
    auth TEXT NOT NULL DEFAULT 'password',
    has_key INTEGER NOT NULL DEFAULT 0,
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
"""


class Store:
    """Small typed wrapper around the auditless SQLite database."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or data_dir()
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / "keys").mkdir(exist_ok=True)
        self.db_path = self.directory / "auditless.db"
        with _connect(self.db_path) as conn:
            conn.executescript(_SCHEMA)

    # -- hosts --------------------------------------------------------

    def upsert_host(
        self,
        name: str,
        hostname: str,
        username: str,
        port: int = 22,
        auth: str = "password",
        host_id: str | None = None,
    ) -> dict:
        """Create or replace a host record (key material untouched)."""
        if auth not in ("password", "key"):
            raise ValueError("auth must be 'password' or 'key'")
        now = time.time()
        hid = host_id or uuid.uuid4().hex[:12]
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT has_key FROM hosts WHERE id = ?", (hid,)
            ).fetchone()
            has_key = row["has_key"] if row else 0
            conn.execute(
                "INSERT OR REPLACE INTO hosts"
                " (id, name, hostname, port, username, auth, has_key,"
                " created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE("
                "  (SELECT created_at FROM hosts WHERE id = ?), ?), ?)",
                (hid, name, hostname, port, username, auth, has_key, hid, now, now),
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
        """Delete a host and its stored key material."""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM hosts WHERE id = ?", (host_id,)
            ).fetchone()
            if row is None:
                return False
            self.clear_host_key(host_id)
            conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        return True

    # -- keys (bytes on disk, 0600, write-only via API) ----------------

    def key_path(self, host_id: str) -> Path:
        """Filesystem location for a host's private key (guarded)."""
        return self.directory / "keys" / _safe_id(host_id)

    def set_host_key(self, host_id: str, key_text: str) -> None:
        """Store key bytes with owner-only permissions; flag the host."""
        if not self.get_host(host_id):
            raise KeyError(f"unknown host {host_id}")
        path = self.key_path(host_id)
        path.write_text(key_text, encoding="utf-8")
        os.chmod(path, 0o600)
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE hosts SET has_key = 1, updated_at = ? WHERE id = ?",
                (time.time(), host_id),
            )

    def clear_host_key(self, host_id: str) -> None:
        """Remove stored key bytes and clear the flag (idempotent)."""
        try:
            self.key_path(host_id).unlink()
        except FileNotFoundError:
            pass
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE hosts SET has_key = 0, updated_at = ? WHERE id = ?",
                (time.time(), host_id),
            )

    def has_host_key(self, host_id: str) -> bool:
        """Whether key bytes exist on disk for the host."""
        return self.key_path(host_id).exists()

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
