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

import paramiko
from paramiko.client import AutoAddPolicy, RejectPolicy


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

        Raises:
            paramiko.AuthenticationException: If credentials are invalid
            paramiko.SSHException: If SSH protocol negotiation fails
            socket.gaierror: If hostname cannot be resolved
        """
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
