"""SSH client wrapper for remote command execution on Linux target systems.

Provides a thin paramiko wrapper with context manager support, timeout handling,
and UTF-8 safe output decoding. Designed for agentless security scanning over SSH.

Classes:
    SSHSession: Context-managed SSH connection handler with automatic cleanup

Example:
    >>> with SSHSession('target.host', 'user', 'pass') as ssh:
    ...     exit_code, stdout, stderr = ssh.run('whoami')
    ...     print(f'Remote user: {stdout}')
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass

import paramiko
from paramiko.client import AutoAddPolicy, RejectPolicy

#: Network-level failures worth retrying (auth failures fail immediately).
_TRANSIENT_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    EOFError,
    paramiko.SSHException,
)


class SSHSession:
    """Lightweight SSH client wrapper around paramiko."""

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: float = 5.0,
        strict_host_key_checking: bool = False,
        key_path: str | None = None,
        gateway: dict | None = None,
        retries: int = 0,
        retry_backoff: float = 1.0,
    ):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.strict_host_key_checking = strict_host_key_checking
        self.key_path = key_path
        # Optional bastion: {"hostname":..,"port":22,"username":..,
        #   "password":..,"key_path":..} — tunneled via direct-tcpip.
        self.gateway = gateway or {}
        # Transient-failure retries (network only; auth fails immediately).
        self.retries = max(0, retries)
        self.retry_backoff = max(0.0, retry_backoff)
        self._client: paramiko.SSHClient | None = None
        self._gateway_transport: paramiko.Transport | None = None

    def __enter__(self) -> "SSHSession":
        self.connect()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def connect(self) -> None:
        """Establish SSH connection to target host.

        By default uses auto-add policy for unknown host keys (convenient
        but vulnerable to MITM on first connect). Pass
        strict_host_key_checking=True (or --strict-host-key-checking) to
        reject unknown host keys and require a pre-populated known_hosts.

        Transient network failures (timeouts, resets, DNS flakes, SSH
        protocol errors) retry with exponential backoff up to ``retries``
        times (or --retries). Authentication failures fail immediately —
        retrying bad credentials only risks account lockout.

        Raises:
            paramiko.AuthenticationException: If credentials are invalid
            paramiko.SSHException: If SSH protocol negotiation fails
            socket.gaierror: If hostname cannot be resolved
        """
        for attempt in range(self.retries + 1):
            try:
                self._connect_once()
                return
            except paramiko.AuthenticationException:
                raise
            except _TRANSIENT_ERRORS:
                if attempt >= self.retries:
                    raise
                time.sleep(self.retry_backoff * (2.0**attempt))

    def _connect_once(self) -> None:
        """Single connection attempt (with cleanup so retries start fresh)."""
        client = paramiko.SSHClient()
        if self.strict_host_key_checking:
            client.set_missing_host_key_policy(RejectPolicy())
        else:
            # Auto-add is the documented default for lab/CI convenience;
            # --strict-host-key-checking switches to RejectPolicy.
            client.set_missing_host_key_policy(AutoAddPolicy())  # nosec B507
        sock = None
        if self.gateway:
            sock = self._open_gateway_channel()
        try:
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password or None,
                timeout=self.timeout,
                key_filename=self.key_path,
                sock=sock,
                allow_agent=False,
                look_for_keys=False,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            with suppress(Exception):
                client.close()
            self.close()
            raise
        self._client = client

    def _open_gateway_channel(self) -> paramiko.Channel:
        """Open a direct-tcpip channel through the bastion host."""
        gw_host = self.gateway.get("hostname", "")
        gw_port = int(self.gateway.get("port", 22) or 22)
        transport = paramiko.Transport((gw_host, gw_port))
        transport.set_keepalive(30)
        transport.connect(
            username=self.gateway.get("username", ""),
            password=self.gateway.get("password") or None,
            pkey=self._load_gateway_key(),
        )
        self._gateway_transport = transport
        return transport.open_channel(
            "direct-tcpip", (self.hostname, self.port), ("127.0.0.1", 0)
        )

    def _load_gateway_key(self) -> paramiko.PKey | None:
        """Load a bastion private key file, any supported type."""
        key_path = self.gateway.get("key_path") or ""
        if not key_path:
            return None
        last_error = None
        for key_class in (
            paramiko.RSAKey,
            paramiko.Ed25519Key,
            paramiko.ECDSAKey,
        ):
            try:
                return key_class.from_private_key_file(key_path)
            except Exception as exc:  # wrong type or encrypted: try next
                last_error = exc
        raise ValueError(f"unreadable gateway key {key_path!r}: {last_error}")

    def close(self) -> None:
        """Close SSH connection and cleanup resources."""
        if self._client:
            self._client.close()
            self._client = None
        if self._gateway_transport is not None:
            self._gateway_transport.close()
            self._gateway_transport = None

    def run(self, command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        """Execute remote command on target system.

        Args:
            command: Shell command to execute on target
            timeout: Command execution timeout in seconds (default: 10.0)

        Returns:
            tuple: (exit_code, stdout, stderr) with UTF-8 safe decoding

        Raises:
            RuntimeError: If SSH session is not connected
            socket.timeout: If command execution exceeds timeout
        """
        if not self._client:
            raise RuntimeError("SSHSession not connected")
        # Executing operator-supplied commands on operator-owned targets
        # over SSH is this tool's entire purpose; scan commands are fixed
        # strings built by the check modules, never remote input.
        _, stdout, stderr = self._client.exec_command(  # nosec B601
            command, timeout=timeout
        )
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return exit_status, out, err

    def is_healthy(self) -> bool:
        """Round-trip health check (transport alive + command executes)."""
        client = self._client
        if client is None:
            return False
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            return False
        try:
            self.run("true", timeout=5.0)
        except Exception:
            return False
        return True


@dataclass(frozen=True)
class PoolKey:
    """Pool identity for a session (never carries secrets).

    Two scans to the same host/user share pooled sessions even when the
    presented passwords differ — the live session is already
    authenticated. ``auth`` records the KIND of credential only.
    """

    hostname: str
    port: int
    username: str
    auth: str
    strict_host_key_checking: bool
    timeout: float
    gateway: tuple[tuple[str, str], ...] = ()


@dataclass
class _IdleEntry:
    session: SSHSession
    expires_at: float


class SessionPool:
    """Bounded pool of idle SSH sessions for long-lived processes.

    One-shot CLI scans connect once per process, so pooling only pays off
    in the serving process (dashboard/scheduler/fleet rescans of the same
    hosts). The pool never changes failure semantics: a dead or expired
    idle session is discarded and a fresh connection is made, so the
    worst case behaves exactly like no pooling.
    """

    def __init__(
        self,
        max_idle_per_host: int = 2,
        max_idle_total: int = 32,
        idle_ttl: float = 120.0,
    ) -> None:
        self.max_idle_per_host = max_idle_per_host
        self.max_idle_total = max_idle_total
        self.idle_ttl = idle_ttl
        self._lock = threading.Lock()
        self._idle: dict[PoolKey, list[_IdleEntry]] = {}

    @staticmethod
    def key_for(
        hostname: str,
        port: int,
        username: str,
        password: str = "",
        key_path: str | None = None,
        strict_host_key_checking: bool = False,
        timeout: float = 5.0,
        gateway: dict | None = None,
    ) -> PoolKey:
        """Build the pool identity (credential kinds only, never secrets)."""
        gw = gateway or {}
        gw_fp = (
            ("hostname", str(gw.get("hostname", ""))),
            ("port", str(gw.get("port", 22))),
            ("username", str(gw.get("username", ""))),
            ("auth", "key" if gw.get("key_path") else "password"),
            ("key_path", str(gw.get("key_path") or "")),
        )
        auth = "key" if key_path else "password"
        _ = password  # kind only; the secret never enters the key
        return PoolKey(
            hostname=hostname,
            port=port,
            username=username,
            auth=auth,
            strict_host_key_checking=strict_host_key_checking,
            timeout=timeout,
            gateway=gw_fp,
        )

    def _take_locked(self, key: PoolKey) -> SSHSession | None:
        entries = self._idle.get(key, [])
        while entries:
            entry = entries.pop()
            if entry.expires_at < time.monotonic():
                entry.session.close()
                continue
            if entry.session.is_healthy():
                return entry.session
            entry.session.close()
        return None

    def acquire(self, key: PoolKey, connect: Callable[[], SSHSession]) -> SSHSession:
        """Return a healthy idle session or connect a fresh one.

        ``connect`` builds and connects a new session on a pool miss; its
        exceptions propagate exactly as without pooling.
        """
        with self._lock:
            session = self._take_locked(key)
        if session is not None:
            return session
        return connect()

    def release(self, key: PoolKey, session: SSHSession) -> None:
        """Park a healthy session for reuse, else close it."""
        with self._lock:
            parked = sum(len(entries) for entries in self._idle.values())
            bucket = self._idle.setdefault(key, [])
            if (
                parked < self.max_idle_total
                and len(bucket) < self.max_idle_per_host
                and session.is_healthy()
            ):
                bucket.append(_IdleEntry(session, time.monotonic() + self.idle_ttl))
                return
        session.close()

    def drain(self) -> None:
        """Close every idle session (tests/shutdown)."""
        with self._lock:
            entries = [entry for bucket in self._idle.values() for entry in bucket]
            self._idle.clear()
        for entry in entries:
            try:
                entry.session.close()
            except Exception:
                pass

    def invalidate(
        self,
        hostname: str,
        port: int | None = None,
        username: str | None = None,
    ) -> int:
        """Drop idle sessions for a host (remediation may restart services).

        Returns the number of sessions closed. A service restart on the
        target can kill pooled connections; callers that change target
        state must invalidate so the next scan redials instead of
        racing a dying session.
        """
        with self._lock:
            doomed = [
                key
                for key in self._idle
                if key.hostname == hostname
                and (port is None or key.port == port)
                and (username is None or key.username == username)
            ]
            entries = [entry for key in doomed for entry in self._idle.pop(key)]
        for entry in entries:
            try:
                entry.session.close()
            except Exception:
                pass
        return len(entries)

    def idle_count(self) -> int:
        """Number of parked sessions (introspection/tests)."""
        with self._lock:
            return sum(len(entries) for entries in self._idle.values())


_DEFAULT_POOL = SessionPool()


@contextmanager
def pooled_session(
    hostname: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: float = 5.0,
    strict_host_key_checking: bool = False,
    key_path: str | None = None,
    gateway: dict | None = None,
    pool: SessionPool | None = None,
    retries: int = 0,
    retry_backoff: float = 1.0,
) -> Iterator[SSHSession]:
    """Yield a session, reusing a healthy pooled one when available.

    Falls back to a fresh connection whenever the pool misses or the
    idle session fails its health check — scans behave as without
    pooling in the worst case. A block exception closes (never parks)
    the session and re-raises.
    """
    active_pool = pool if pool is not None else _DEFAULT_POOL
    key = SessionPool.key_for(
        hostname,
        port,
        username,
        password,
        key_path,
        strict_host_key_checking,
        timeout,
        gateway,
    )

    def connect() -> SSHSession:
        session = SSHSession(
            hostname=hostname,
            username=username,
            password=password,
            port=port,
            timeout=timeout,
            strict_host_key_checking=strict_host_key_checking,
            key_path=key_path,
            gateway=gateway,
            retries=retries,
            retry_backoff=retry_backoff,
        )
        session.connect()
        return session

    session = active_pool.acquire(key, connect)
    try:
        yield session
    except Exception:
        try:
            session.close()
        except Exception:
            pass
        raise
    active_pool.release(key, session)


def drain_session_pool() -> None:
    """Close all pooled idle sessions (tests/process shutdown)."""
    _DEFAULT_POOL.drain()


def invalidate_sessions(
    hostname: str, port: int | None = None, username: str | None = None
) -> int:
    """Drop pooled idle sessions for a host (post-remediation safety)."""
    return _DEFAULT_POOL.invalidate(hostname, port, username)
