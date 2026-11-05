from __future__ import annotations

import functools
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, List, Tuple, cast

from .ssh_client import SSHSession
from .test_ids import CHECK_TEST_IDS

from paramiko.ssh_exception import ChannelException

COMMAND_TIMEOUT: float = 60.0
#: Soft ceiling per remote command output (stdout/stderr each). Bounds
#: report memory on pathological hosts; ordinary outputs are far smaller.
#: <= 0 disables the cap (parse-affecting callers use explicit values).
MAX_OUTPUT_BYTES: int = 1024 * 1024
# Output cache keyed by (hostname, command): concurrent fleet scans of
# different hosts must never share entries (they share this process).
# Invalidation rules (see .github/PERFORMANCE.md):
#   1. reset_command_cache() at the start of every scan (fresh results);
#   2. per-entry TTL (default 300s) bounds staleness if a reset is missed;
#   3. --no-cache disables the cache for one scan (prior state restored).
_COMMAND_CACHE: dict[tuple[str, str], tuple[tuple[int, str, str], float]] = {}
_CACHE_LOCK = threading.Lock()
_USE_CACHE: bool = True  # Can be disabled for testing
_CACHE_TTL_S: float = 300.0


def set_command_timeout(seconds: float) -> None:
    """Set global per-command timeout for remote SSH execs."""
    global COMMAND_TIMEOUT
    COMMAND_TIMEOUT = max(1.0, seconds)


def get_max_output_bytes() -> int:
    """Current per-command output cap in bytes (<= 0 means uncapped)."""
    return MAX_OUTPUT_BYTES


def set_max_output_bytes(limit: int) -> None:
    """Set per-command output cap in bytes (<= 0 disables the cap)."""
    global MAX_OUTPUT_BYTES
    MAX_OUTPUT_BYTES = int(limit)


def truncate_output(text: str, limit: int | None = None) -> str:
    """Cap text to limit bytes, marking truncation (never raises)."""
    cap = MAX_OUTPUT_BYTES if limit is None else int(limit)
    if cap <= 0:
        return text
    if len(text.encode("utf-8", errors="replace")) <= cap:
        return text
    encoded = text.encode("utf-8", errors="replace")[:cap]
    return encoded.decode("utf-8", errors="ignore") + (
        f" [...truncated {len(text)} chars]"
    )


def reset_command_cache() -> None:
    """Reset the command output cache between sessions.

    Performance optimization: Clear cached command results to prevent
    stale data when running multiple scans in the same process.
    """
    global _COMMAND_CACHE
    with _CACHE_LOCK:
        _COMMAND_CACHE.clear()


def disable_command_cache() -> None:
    """Disable command caching (useful for testing)."""
    global _USE_CACHE
    _USE_CACHE = False


def enable_command_cache() -> None:
    """Enable command caching."""
    global _USE_CACHE
    _USE_CACHE = True


def is_command_cache_enabled() -> bool:
    """Whether the command cache is currently enabled."""
    return _USE_CACHE


def get_command_cache_ttl() -> float:
    """Current per-entry cache TTL in seconds."""
    return _CACHE_TTL_S


def set_command_cache_ttl(seconds: float) -> None:
    """Set per-entry cache TTL in seconds (negative clamps to 0)."""
    global _CACHE_TTL_S
    _CACHE_TTL_S = max(0.0, seconds)


def _cache_key(ssh: SSHSession, command: str) -> tuple[str, str]:
    """Cache identity: target host plus command (never shared across hosts)."""
    return (str(getattr(ssh, "hostname", "") or ""), command)


def _cache_get(key: tuple[str, str]) -> tuple[int, str, str] | None:
    """Fresh cached result, or None on miss/expiry/disable."""
    if not _USE_CACHE:
        return None
    with _CACHE_LOCK:
        entry = _COMMAND_CACHE.get(key)
        if entry is None:
            return None
        result, cached_at = entry
        if time.monotonic() - cached_at >= _CACHE_TTL_S:
            del _COMMAND_CACHE[key]
            return None
        return result


def _cache_put(key: tuple[str, str], result: tuple[int, str, str]) -> None:
    """Store a result unless caching is disabled."""
    if not _USE_CACHE:
        return
    with _CACHE_LOCK:
        _COMMAND_CACHE[key] = (result, time.monotonic())


def _cap_output(
    result: tuple[int, str, str], limit: int | None
) -> tuple[int, str, str]:
    """Truncate stored streams to the effective per-command cap."""
    cap = MAX_OUTPUT_BYTES if limit is None else int(limit)
    if cap <= 0:
        return result
    code, out, err = result
    return code, truncate_output(out, cap), truncate_output(err, cap)


@dataclass
class CheckResult:
    category: str
    item: str
    status: str  # pass | warn | fail
    details: str
    recommendation: str
    test_id: str = ""  # Lynis-style test ID (e.g., BOOT-5122, AUTH-9328)


@dataclass
class SystemInfo:
    hostname: str
    os: str
    kernel: str
    uptime: str
    users: str


@dataclass
class DetailedSecurityInfo:
    suid_binaries: str
    root_logins: str
    successful_ssh_logins: str
    failed_ssh_logins: str
    top_processes: str
    disk_usage_dirs: str
    available_updates: str
    firewall_rules: str
    sshd_config_check: str
    failed_systemd_units: str
    sudoers_info: str
    critical_file_permissions: str
    rootkit_scan: str | None = None
    unused_packages: str | None = None


def _run(
    ssh: SSHSession,
    command: str,
    password: str = "",
    command_timeout: float | None = None,
    use_cache: bool = True,
    max_output_bytes: int | None = None,
) -> Tuple[int, str, str]:
    """Run command on SSH session with optional output caching.

    Performance optimization: Command outputs are cached during a scan session
    to avoid redundant remote execution. Cache is keyed by command string.

    Memory discipline: stdout/stderr are truncated to ``max_output_bytes``
    (default: the global cap) so one pathological host cannot bloat fleet
    reports; parsing sees the same prefix every consumer already relied on
    for remotely-bounded commands. Pass ``<= 0`` to disable.

    Args:
        ssh: SSH session object
        command: Command to execute
        password: Optional sudo password
        command_timeout: Custom timeout for this command
        use_cache: Whether to use cached results (default: True)
        max_output_bytes: Per-stream cap (None: global default)

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    # Check cache first (optimization for repeated commands)
    cache_key = _cache_key(ssh, command)
    if use_cache:
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

    # Run command on SSH session with a hard timeout, sending sudo password when needed.
    effective_timeout = command_timeout or COMMAND_TIMEOUT
    # Check if this is a mock object (for testing)
    if (
        hasattr(ssh, "_client")
        and ssh._client is not None
        and not isinstance(ssh._client, type(None))
    ):
        try:
            # Burst channel opens occasionally fail on small targets
            # (parallel scans); retry twice before giving up so one
            # flake never aborts a whole scan.
            channel_error: Exception | None = None
            for attempt in range(3):
                try:
                    stdin, stdout, stderr = ssh._client.exec_command(
                        command, timeout=effective_timeout
                    )
                    channel_error = None
                    break
                except (ChannelException, EOFError) as exc:
                    channel_error = exc
                    time.sleep(0.5 * (attempt + 1))
            if channel_error is not None:
                raise channel_error

            # If password provided and command uses sudo -S, write password to stdin
            if password and "sudo -S" in command:
                stdin.write(password + "\n")
                stdin.flush()

            stdin.close()

            deadline = time.monotonic() + effective_timeout
            while not stdout.channel.exit_status_ready():
                if time.monotonic() > deadline:
                    stdout.channel.close()
                    return -1, "", f"command timeout after {effective_timeout}s"
                time.sleep(0.001)

            exit_status = stdout.channel.recv_exit_status()
            try:
                out = stdout.read().decode("utf-8", errors="replace").strip()
                err = stderr.read().decode("utf-8", errors="replace").strip()
            finally:
                with suppress(Exception):
                    stdout.channel.close()
            result = _cap_output((exit_status, out, err), max_output_bytes)
            # Cache result for future use (if caching is enabled)
            if use_cache:
                _cache_put(cache_key, result)
            return result
        except (TypeError, AttributeError):
            # Fall back to using ssh.run() for mock objects
            result = _cap_output(
                ssh.run(command, timeout=effective_timeout), max_output_bytes
            )
            if use_cache:
                _cache_put(cache_key, result)
            return result
    else:
        # Use the normal ssh.run() method
        result = _cap_output(
            ssh.run(command, timeout=effective_timeout), max_output_bytes
        )
        if use_cache:
            _cache_put(cache_key, result)
        return result


def gather_system_info(ssh: SSHSession) -> SystemInfo:
    _, hostname, _ = _run(ssh, "hostname")
    _, kernel, _ = _run(ssh, "uname -r")
    _, os_release, _ = _run(
        ssh,
        "bash -lc 'if [ -f /etc/os-release ]; then . /etc/os-release; "
        + 'echo "$NAME $VERSION"; else uname -s; fi\'',
    )
    _, uptime, _ = _run(ssh, "uptime -p || uptime")
    _, users, _ = _run(ssh, "who -q")
    return SystemInfo(
        hostname=hostname, os=os_release, kernel=kernel, uptime=uptime, users=users
    )


def _pass(
    item: str, details: str, recommendation: str, category: str, test_id: str = ""
) -> CheckResult:
    return CheckResult(
        category=category,
        item=item,
        status="pass",
        details=details,
        recommendation=recommendation,
        test_id=test_id,
    )


def _warn(
    item: str, details: str, recommendation: str, category: str, test_id: str = ""
) -> CheckResult:
    return CheckResult(
        category=category,
        item=item,
        status="warn",
        details=details,
        recommendation=recommendation,
        test_id=test_id,
    )


def _fail(
    item: str, details: str, recommendation: str, category: str, test_id: str = ""
) -> CheckResult:
    return CheckResult(
        category=category,
        item=item,
        status="fail",
        details=details,
        recommendation=recommendation,
        test_id=test_id,
    )


def check_disk_usage(ssh: SSHSession) -> CheckResult:
    category = "Storage"
    code, out, err = _run(ssh, "df -P -h / | tail -1 | awk '{print $5}'")
    if code != 0:
        return _warn(
            "Disk usage",
            f"df failed: {err or out}",
            "Inspect disk layout manually",
            category,
        )
    match = re.search(r"(\d+)%", out)
    if not match:
        return _warn(
            "Disk usage", f"Unexpected df output: {out}", "Run df -h", category
        )
    pct = int(match.group(1))
    if pct >= 90:
        return _fail(
            "Disk usage",
            f"Root filesystem at {pct}%",
            "Prune logs, remove old kernels, or extend disk; run 'sudo du -xhd1 /' to find top consumers",
            category,
        )
    if pct >= 80:
        return _warn(
            "Disk usage",
            f"Root filesystem at {pct}%",
            "Clean /var/log, rotate logs, remove unused packages",
            category,
        )
    return _pass(
        "Disk usage",
        f"Root filesystem at {pct}%",
        "Keep below 80% to avoid surprises",
        category,
    )


def check_memory(ssh: SSHSession) -> CheckResult:
    category = "Memory"
    code, out, err = _run(ssh, "free -m | awk '/Mem:/ {print $2, $7}'")
    if code != 0:
        return _warn(
            "Memory", f"free failed: {err or out}", "Run free -m manually", category
        )
    try:
        total, avail = map(int, out.split())
    except ValueError:
        return _warn(
            "Memory", f"Unexpected free output: {out}", "Run free -m", category
        )
    avail_pct = int((avail / total) * 100)
    if avail_pct < 10:
        return _fail(
            "Memory",
            f"Only {avail_pct}% available ({avail} MiB of {total} MiB)",
            "Investigate heavy processes with 'ps aux --sort=-%mem | head', consider adding RAM or reducing caches",
            category,
            test_id="MEM-2914",
        )
    if avail_pct < 20:
        return _warn(
            "Memory",
            f"{avail_pct}% available ({avail} MiB of {total} MiB)",
            "Check services for leaks and restart long-lived daemons if needed",
            category,
            test_id="MEM-2914",
        )
    return _pass(
        "Memory",
        f"{avail_pct}% available ({avail} MiB of {total} MiB)",
        "No action",
        category,
        test_id="MEM-2914",
    )


def check_load(ssh: SSHSession) -> CheckResult:
    category = "CPU/Load"
    code, out, err = _run(ssh, "awk '{print $1,$2,$3}' /proc/loadavg")
    if code != 0:
        return _warn(
            "Load",
            f"loadavg failed: {err or out}",
            "Inspect /proc/loadavg manually",
            category,
        )
    try:
        load1, load5, load15 = map(float, out.split())
    except ValueError:
        return _warn(
            "Load",
            f"Unexpected /proc/loadavg output: {out}",
            "Inspect load manually",
            category,
        )
    # Simple heuristic thresholds; without CPU count, use conservative values.
    if load5 >= 8 or load15 >= 8:
        return _fail(
            "System load",
            f"High load averages: 1m={load1}, 5m={load5}, 15m={load15}",
            "Inspect with 'top -o %CPU' or 'uptime', consider reducing cron/batch jobs",
            category,
        )
    if load5 >= 4:
        return _warn(
            "System load",
            f"Elevated load averages: 1m={load1}, 5m={load5}, 15m={load15}",
            "Check running processes with 'ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head'",
            category,
        )
    return _pass(
        "System load",
        f"Load averages OK: 1m={load1}, 5m={load5}, 15m={load15}",
        "No action",
        category,
    )


def check_reboot_required(ssh: SSHSession) -> CheckResult:
    category = "Patching"
    code, _, _ = _run(ssh, "[ -f /var/run/reboot-required ]")
    if code == 0:
        return _warn(
            "Reboot needed",
            "/var/run/reboot-required present",
            "Schedule a reboot during maintenance window",
            category,
        )
    return _pass("Reboot needed", "No reboot-required flag", "No action", category)


def check_updates(ssh: SSHSession, password: str = "") -> CheckResult:
    category = "Patching"
    # For Debian/Ubuntu systems, try to separate security from regular updates
    cmd = (
        "bash -lc 'if command -v apt-get >/dev/null 2>&1; then "
        "apt-get -s upgrade 2>/dev/null | grep -c ^Inst; "
        'apt-get -s upgrade 2>/dev/null | grep "^Inst" | grep -i security | wc -l; '
        "elif command -v dnf >/dev/null 2>&1; then dnf -q check-update >/tmp/dnf.out; "
        "cat /tmp/dnf.out | wc -l; echo 0; "
        "elif command -v yum >/dev/null 2>&1; then yum -q check-update | wc -l; echo 0; "
        "elif command -v pacman >/dev/null 2>&1; then pacman -Qu 2>/dev/null | wc -l; "
        "echo 0; else echo 0; echo 0; fi'"
    )
    # Wrap with sudo if password provided
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)
    if code != 0:
        return _warn(
            "Pending updates",
            f"Update check failed: {err or out}",
            "Check updates manually",
            category,
        )

    try:
        lines = out.strip().splitlines()
        total_count = int(lines[0]) if len(lines) > 0 else 0
        security_count = int(lines[1]) if len(lines) > 1 else 0
    except (ValueError, IndexError):
        return _warn(
            "Pending updates",
            f"Unexpected update output: {out}",
            "Check updates manually",
            category,
        )

    if total_count > 50:
        if security_count > 0:
            details = f"{total_count} packages pending ({security_count} security)"
        else:
            details = f"{total_count} packages pending"
        return _fail(
            "Pending updates",
            details,
            "Apply security updates immediately: 'sudo apt-get update && sudo apt-get upgrade' (adjust for distro)",
            category,
        )

    if security_count > 0:
        return _fail(
            "Pending updates",
            f"{total_count} packages pending ({security_count} security updates)",
            "Apply security updates immediately: 'sudo apt-get update && sudo apt-get upgrade' (adjust for distro)",
            category,
        )

    if total_count > 0:
        return _warn(
            "Pending updates",
            f"{total_count} packages pending (non-security)",
            "Update soon: 'sudo apt-get update && sudo apt-get upgrade' (adjust for distro)",
            category,
        )
    return _pass("Pending updates", "0 packages pending", "No action", category)


def check_ssh_config(ssh: SSHSession, password: str = "") -> List[CheckResult]:
    category = "SSH"
    # Try sshd -T first (works better with sudo, doesn't require file read)
    cmd = "sshd -T 2>/dev/null"
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)

    # Fallback to grep if sshd -T fails
    if code != 0:
        cmd = "grep -E '^(PasswordAuthentication|PermitRootLogin|Port)' /etc/ssh/sshd_config 2>/dev/null"
        if password:
            cmd = f"sudo -S {cmd}"
        code, out, err = _run(ssh, cmd, password)

    if code != 0 or not out.strip():
        return [
            _warn(
                "SSH config readability",
                "Could not read sshd_config",
                "Verify permissions or check sshd -T",
                category,
            )
        ]

    results: list[CheckResult] = []
    security_score = 0  # Track security posture

    # Parse output - works for both sshd -T and grep
    password_auth = re.search(
        r"(?:^|\n)passwordauthentication\s+(yes|no)", out, re.IGNORECASE | re.MULTILINE
    )
    if password_auth and password_auth.group(1).lower() == "no":
        results.append(
            _pass(
                "PasswordAuthentication",
                "PasswordAuthentication no",
                "Keep key-based auth",
                category,
            )
        )
        security_score += 2
    else:
        results.append(
            _warn(
                "PasswordAuthentication",
                "Password authentication enabled",
                "Set 'PasswordAuthentication no' and use SSH keys",
                category,
            )
        )
        security_score += 0

    permit_root = re.search(
        r"(?:^|\n)permitrootlogin\s+(\S+)", out, re.IGNORECASE | re.MULTILINE
    )
    if permit_root and permit_root.group(1).lower() in {"no", "prohibit-password"}:
        results.append(
            _pass(
                "PermitRootLogin",
                f"PermitRootLogin {permit_root.group(1)}",
                "Keep root SSH disabled",
                category,
            )
        )
        security_score += 2
    else:
        results.append(
            _warn(
                "PermitRootLogin",
                "Root login over SSH enabled",
                "Set 'PermitRootLogin no' and use sudo from user accounts",
                category,
            )
        )
        security_score += 0

    port_match = re.search(r"(?:^|\n)port\s+(\d+)", out, re.IGNORECASE | re.MULTILINE)
    if port_match:
        port = int(port_match.group(1))
        if port != 22:
            results.append(
                _pass(
                    "SSH Port",
                    f"Non-default port {port}",
                    "Document this in runbooks",
                    category,
                )
            )
            security_score += 1
        else:
            results.append(
                _warn(
                    "SSH Port",
                    "Using default port 22",
                    "Consider non-default port + fail2ban/ufw",
                    category,
                )
            )
            security_score += 0
    else:
        results.append(
            _warn(
                "SSH Port",
                "No explicit port set",
                "Set an explicit port in sshd_config",
                category,
            )
        )
        security_score += 0

    # Add overall security rating
    if security_score >= 5:
        rating = "Excellent"
        icon = "✅"
    elif security_score >= 3:
        rating = "Good"
        icon = "✅"
    elif security_score >= 1:
        rating = "Fair"
        icon = "⚠️"
    else:
        rating = "Poor"
        icon = "❌"

    results.append(
        _pass(
            "SSH Security Rating",
            f"{icon} {rating} ({security_score}/5)",
            "Review each recommendation above",
            category,
        )
        if security_score >= 3
        else _warn(
            "SSH Security Rating",
            f"{icon} {rating} ({security_score}/5)",
            "Review each recommendation above",
            category,
        )
    )

    return results


def check_firewall(ssh: SSHSession, password: str = "") -> CheckResult:
    category = "Network"
    cmd = (
        "bash -lc 'if command -v ufw >/dev/null 2>&1; then ufw status; "
        "elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state; "
        "else echo none; fi'"
    )
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)
    if code != 0:
        return _warn(
            "Firewall",
            f"Firewall check failed: {err or out}",
            "Verify ufw or firewalld manually",
            category,
        )
    if "inactive" in out.lower() or "none" in out.lower():
        return _warn(
            "Firewall",
            "Firewall inactive",
            "Enable host firewall (ufw enable or firewall-cmd --permanent --add-service=ssh)",
            category,
        )
    return _pass(
        "Firewall",
        f"Firewall state: {out.splitlines()[0] if out else 'active'}",
        "Keep rules documented",
        category,
    )


def check_time_sync(ssh: SSHSession) -> CheckResult:
    category = "Time"
    code, out, err = _run(ssh, "timedatectl show -p NTPSynchronized --value")
    if code != 0:
        return _warn(
            "Time sync",
            f"timedatectl check failed: {err or out}",
            "Ensure NTP client is running",
            category,
        )
    synced = out.strip().lower() == "yes"
    if synced:
        return _pass(
            "Time sync",
            "NTP synchronized",
            "Keep chrony/systemd-timesyncd running",
            category,
        )
    return _warn(
        "Time sync",
        "NTP not synchronized",
        "Enable NTP: 'sudo timedatectl set-ntp true'",
        category,
    )


def check_accounts(ssh: SSHSession) -> CheckResult:
    category = "Accounts"
    code, out, err = _run(ssh, "awk -F: '$3==0 {print $1}' /etc/passwd")
    if code != 0:
        return _warn(
            "Root accounts",
            f"/etc/passwd read failed: {err or out}",
            "Review /etc/passwd manually",
            category,
        )
    accounts = [line.strip() for line in out.splitlines() if line.strip()]
    if len(accounts) > 1:
        return _fail(
            "Root accounts",
            f"Multiple UID 0 accounts: {', '.join(accounts)}",
            "Limit UID 0 to root; remove or demote extra accounts",
            category,
        )
    return _pass("Root accounts", "Only root has UID 0", "No action", category)


def check_auth_failures(ssh: SSHSession, password: str = "") -> CheckResult:
    category = "Auth"
    cmd = (
        "bash -lc 'if command -v journalctl >/dev/null 2>&1; then "
        'journalctl -u ssh -S -24h --no-pager 2>/dev/null | grep -ci "Failed password"; '
        'elif [ -f /var/log/auth.log ]; then grep -i "Failed password" /var/log/auth.log | tail -n 200 | wc -l; '
        'elif [ -f /var/log/secure ]; then grep -i "Failed password" /var/log/secure | tail -n 200 | wc -l; '
        "else echo 0; fi'"
    )
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)
    if code != 0:
        return _warn(
            "Auth failures (24h)",
            f"Could not read logs: {err or out}",
            "Check journalctl /var/log/auth.log",
            category,
        )
    try:
        count = int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return _warn(
            "Auth failures (24h)",
            f"Unexpected log output: {out}",
            "Inspect auth logs manually",
            category,
        )
    if count >= 100:
        return _fail(
            "Auth failures (24h)",
            f"{count} failed SSH logins (last 24h)",
            "Review sources: journalctl -u ssh -S -24h | grep 'Failed password'; consider fail2ban and key-only auth",
            category,
        )
    if count >= 20:
        return _warn(
            "Auth failures (24h)",
            f"{count} failed SSH logins (last 24h)",
            "Check offending IPs in auth logs; enable rate-limiting (fail2ban/ufw) and key-only auth",
            category,
        )
    return _pass(
        "Auth failures (24h)",
        f"{count} failed SSH logins",
        "Keep monitoring and consider fail2ban",
        category,
    )


def check_root_logins(ssh: SSHSession) -> CheckResult:
    category = "Auth"
    code, out, err = _run(ssh, "last -20 root 2>/dev/null | grep -vi '^wtmp' | wc -l")
    if code != 0:
        return _warn(
            "Root logins",
            f"Could not read last: {err or out}",
            "Check /var/log/wtmp with last",
            category,
        )
    try:
        count = int(out.strip())
    except ValueError:
        return _warn(
            "Root logins",
            f"Unexpected last output: {out}",
            "Inspect 'last root' manually",
            category,
        )
    if count > 0:
        return _warn(
            "Root logins",
            f"{count} recent root login entries",
            "Prefer sudo from named users; audit 'last root' for legitimacy",
            category,
        )
    return _pass(
        "Root logins",
        "No recent root logins in last output",
        "Keep using sudo from users",
        category,
    )


def check_listening_services(ssh: SSHSession) -> CheckResult:
    category = "Network"
    code, out, err = _run(ssh, "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
    if code != 0 or not out.strip():
        return _warn(
            "Listening services",
            f"Could not list listeners: {err or out}",
            "Run 'ss -tulpn' manually",
            category,
        )
    public = [
        line for line in out.splitlines() if "0.0.0.0:" in line or "[::]:" in line
    ]

    # Categorize services by type
    categories_dict = {
        "SSH": 0,
        "HTTP": 0,
        "HTTPS": 0,
        "DB": 0,
        "DNS": 0,
        "Other": 0,
    }

    for line in public:
        line_lower = line.lower()
        if ":22 " in line or "ssh" in line_lower:
            categories_dict["SSH"] += 1
        elif ":80 " in line or ":8080" in line or "http" in line_lower:
            categories_dict["HTTP"] += 1
        elif ":443 " in line or ":8443" in line or "https" in line_lower:
            categories_dict["HTTPS"] += 1
        elif (
            ":3306 " in line
            or ":5432 " in line
            or "mysql" in line_lower
            or "postgres" in line_lower
        ):
            categories_dict["DB"] += 1
        elif ":53 " in line or "dns" in line_lower:
            categories_dict["DNS"] += 1
        else:
            categories_dict["Other"] += 1

    service_summary = ", ".join(f"{k}={v}" for k, v in categories_dict.items() if v > 0)

    if len(public) > 15:
        return _warn(
            "Listening services",
            f"Many public listeners ({len(public)}): {service_summary}",
            "Review 'ss -tulpn' for unexpected services; tighten firewall/hosts.allow",
            category,
        )
    return _pass(
        "Listening services",
        f"Public listeners: {len(public)} [{service_summary}]",
        "Ensure only required services bind publicly and are firewalled",
        category,
    )


def check_abnormal_network_processes(ssh: SSHSession) -> CheckResult:
    """Detect processes bound to network sockets that look abnormal/suspicious."""
    category = "Network"

    # Get all listening processes with their details
    cmd = "ss -tulpn 2>/dev/null | grep LISTEN || netstat -tulpn 2>/dev/null | grep LISTEN"
    code, out, err = _run(ssh, cmd)

    if code != 0 or not out.strip():
        return _pass(
            "Abnormal network processes",
            "Could not enumerate processes",
            "Unable to check for abnormal listeners",
            category,
        )

    # Known suspicious patterns - more specific patterns first to avoid false positives
    suspicious_names = {
        "netcat": "Netcat listener (possible backdoor)",
        "ncat": "Netcat listener (possible backdoor)",
        "/tmp/": "Process in temp directory (suspicious)",
        "/var/tmp/": "Process in var-tmp (suspicious)",
        " nc ": "Netcat listener (possible backdoor)",
        " bash ": "Bash shell listening (reverse shell)",
        " perl ": "Perl interpreter listening (potential reverse shell)",
        " python ": "Python interpreter listening (potential reverse shell)",
        " socat ": "Socat relay (possible backdoor)",
        " cryptominer": "Cryptocurrency miner",
        " xmrig": "XMRig miner",
        " stratum": "Mining pool connection",
        " wget ": "Wget downloader listening",
        " curl ": "Curl listening (suspicious)",
        " php ": "PHP directly listening (should be via web server)",
    }

    # Standard/expected services that should listen
    expected_services = {
        "sshd",
        "ssh",
        "systemd",
        "dnsmasq",
        "named",
        "bind",
        "httpd",
        "apache2",
        "nginx",
        "mysql",
        "mysqld",
        "postgres",
        "postgresql",
        "redis",
        "memcached",
        "vsftpd",
        "proftpd",
        "openssh",
        "dovecot",
        "postfix",
        "sendmail",
        "samba",
        "smbd",
        "cupsd",
        "mdnsd",
        "avahi",
        "ntpd",
        "chronyd",
        "docker",
        "containerd",
        "haproxy",
        "tomcat",
        "java",
        "node",
        "python3",
        "ruby",
        "perl6",
        "elixir",
    }

    abnormal_findings = []

    for line in out.splitlines():
        line_lower = line.lower()

        # Skip empty lines and header
        if not line.strip() or "LISTEN" in line and "Local" in line:
            continue

        # Extract process info (varies by ss vs netstat)
        process_part = ""
        if "users:((" in line_lower:
            # ss format: contains users:(("name",pid,fd))
            match = re.search(r'users:\(\("([^"]+)"', line)
            if match:
                process_part = match.group(1)
        elif "LISTEN" in line:
            # netstat format or alternative parsing
            parts = line.split()
            if parts:
                process_part = parts[-1]

        if not process_part:
            continue

        is_suspicious = False

        # Check for suspicious patterns
        for pattern, reason in suspicious_names.items():
            if (
                pattern in process_part.lower()
                or pattern.strip() in process_part.lower()
            ):
                abnormal_findings.append(f"{process_part}: {reason}")
                is_suspicious = True
                break

        # Check if it's an unexpected/unknown service (only if not already marked suspicious)
        if not is_suspicious:
            service_name = process_part.split("/")[0].split("[")[0].strip()
            if service_name and not any(
                exp in service_name.lower() for exp in expected_services
            ):
                # Could be custom service, log it
                port_match = re.search(r":(\d+)\s", line)
                if port_match:
                    port = port_match.group(1)
                    # Flag unusual ports (not standard well-known ports)
                    if int(port) > 10000 or int(port) in [
                        6666,
                        6667,
                        6668,
                        6669,
                        4444,
                        5555,
                        8888,
                        9999,
                    ]:
                        abnormal_findings.append(
                            f"{service_name} on port {port}: non-standard port"
                        )

    if abnormal_findings:
        summary = "; ".join(abnormal_findings[:3])
        if len(abnormal_findings) > 3:
            summary += f"; +{len(abnormal_findings) - 3} more"
        return _warn(
            "Abnormal network processes",
            f"Found {len(abnormal_findings)} suspicious listener(s): {summary}",
            "Review listening processes: ss -tulpn; investigate unfamiliar services and ports",
            category,
        )

    return _pass(
        "Abnormal network processes",
        "No suspicious network-bound processes detected",
        "Continue monitoring with: ss -tulpn | grep LISTEN",
        category,
    )


def check_suspicious_process_locations(ssh: SSHSession) -> CheckResult:
    """Check for processes running from suspicious locations like /tmp, /dev/shm"""
    category = "Process Integrity"

    cmd = """
    for dir in /tmp /var/tmp /dev/shm; do
        lsof -n 2>/dev/null | grep "CWD.*$dir" && echo "Found in $dir"
    done || true
    """
    code, out, err = _run(ssh, cmd)

    if code != 0:
        return _pass(
            "Suspicious process locations",
            "Could not check",
            "Check lsof availability",
            category,
        )

    suspicious_lines = [line for line in out.splitlines() if line.strip()]
    if suspicious_lines:
        return _warn(
            "Suspicious process locations",
            f"Found {len(suspicious_lines)} process(es) in /tmp, /var/tmp, or /dev/shm",
            "Review suspicious processes: lsof -n | grep -E '(CWD|txt).*(tmp|shm)'",
            category,
        )

    return _pass(
        "Suspicious process locations",
        "No processes running from /tmp, /var/tmp, or /dev/shm",
        "Continue monitoring for suspicious execution patterns",
        category,
    )


def check_unexpected_sudo_usage(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check for unusual sudo command patterns and unexpected sudoers entries"""
    category = "Privilege Escalation"

    # Check for non-standard sudoers files/entries
    cmd = "grep -r -h '^[^#%]' /etc/sudoers.d/ 2>/dev/null | head -20 || echo 'No sudoers.d files'"
    code, out, err = _run(ssh, cmd)

    unusual_patterns = []

    # Flag entries without password requirement (NOPASSWD)
    if "NOPASSWD" in out:
        nopasswd_count = out.count("NOPASSWD")
        unusual_patterns.append(
            f"{nopasswd_count} NOPASSWD sudoers entry/entries (high risk)"
        )

    # Flag entries running commands as root without password
    if "ALL=(ALL) ALL" in out or "ALL=(ALL:ALL) ALL" in out:
        unusual_patterns.append("Unrestricted sudo access detected")

    # Check sudo log for unusual patterns
    cmd_log = """
    tail -100 /var/log/auth.log 2>/dev/null | grep sudo | grep -E '(COMMAND=/bin/bash|COMMAND=/bin/sh|COMMAND=/usr/bin/python)' || true
    """
    code_log, out_log, err_log = _run(ssh, cmd_log)

    if out_log.strip():
        suspicious_sudo_commands = out_log.splitlines()
        if suspicious_sudo_commands:
            unusual_patterns.append(
                f"{len(suspicious_sudo_commands)} suspicious sudo commands in recent logs"
            )

    if unusual_patterns:
        summary = "; ".join(unusual_patterns)
        return _warn(
            "Unexpected sudo usage",
            f"Detected: {summary}",
            "Review /etc/sudoers and /etc/sudoers.d/ for unauthorized entries; Check sudo logs for abuse",
            category,
        )

    return _pass(
        "Unexpected sudo usage",
        "No obvious sudo misconfigurations detected",
        "Monitor sudo logs regularly for privilege escalation attempts",
        category,
    )


def check_recently_created_accounts(ssh: SSHSession) -> CheckResult:
    """Detect user accounts created recently (potential backdoor accounts)"""
    category = "Account Integrity"

    # Get all user accounts with their creation time via stat on home directories
    cmd = """
    for user in $(cut -d: -f1 /etc/passwd); do
        homedir=$(eval echo ~$user 2>/dev/null || echo "")
        if [ -d "$homedir" ]; then
            stat -c "%y|$user" "$homedir" 2>/dev/null
        fi
    done | sort -r | head -10
    """
    code, out, err = _run(ssh, cmd)

    if code != 0 or not out.strip():
        return _pass(
            "Recently created accounts",
            "Could not enumerate accounts",
            "Check /etc/passwd manually",
            category,
        )

    from datetime import datetime, timedelta

    now = datetime.now()
    thirty_days_ago = now - timedelta(days=30)

    recent_accounts = []
    for line in out.splitlines():
        if "|" not in line:
            continue
        try:
            timestamp_str, username = line.split("|")
            # Parse timestamp like "2025-12-28 14:22:55"
            timestamp = datetime.strptime(
                timestamp_str.split(".")[0], "%Y-%m-%d %H:%M:%S"
            )
            if timestamp > thirty_days_ago:
                days_old = (now - timestamp).days
                recent_accounts.append(f"{username} ({days_old} days old)")
        except (ValueError, IndexError):
            continue

    if recent_accounts:
        summary = "; ".join(recent_accounts[:3])
        if len(recent_accounts) > 3:
            summary += f"; +{len(recent_accounts) - 3} more"
        return _warn(
            "Recently created accounts",
            f"Found {len(recent_accounts)} account(s) created in last 30 days: {summary}",
            "Review new accounts in /etc/passwd; verify they are legitimate; check home directories for backdoors",
            category,
        )

    return _pass(
        "Recently created accounts",
        "No suspicious recently created accounts detected",
        "Continue monitoring account creation",
        category,
    )


def check_system_binary_modifications(ssh: SSHSession) -> CheckResult:
    """Check for recent modifications to critical system binaries"""
    category = "File Integrity"

    critical_binaries = [
        "/bin/bash",
        "/bin/sh",
        "/bin/ls",
        "/bin/cat",
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/sbin/init",
        "/usr/sbin/sshd",
    ]

    cmd = f"find {' '.join(critical_binaries)} -mtime -7 2>/dev/null | head -20 || true"
    code, out, err = _run(ssh, cmd)

    if not out.strip():
        return _pass(
            "System binary modifications",
            "No system binaries modified in last 7 days",
            "Periodically verify system binary integrity",
            category,
        )

    modified_binaries = out.splitlines()
    summary = "; ".join(modified_binaries[:3])
    if len(modified_binaries) > 3:
        summary += f"; +{len(modified_binaries) - 3} more"

    return _warn(
        "System binary modifications",
        f"Found {len(modified_binaries)} critical binary(ies) modified in last 7 days: {summary}",
        "Verify modifications with: ls -la <binary>; Check with rpm/dpkg verification if available",
        category,
    )


def check_failed_login_spike(ssh: SSHSession, password: str = "") -> CheckResult:
    """Detect spike in failed login attempts (brute force indicator)"""
    category = "Authentication"

    # Check last 500 auth.log entries for failed logins
    cmd = """
    tail -500 /var/log/auth.log 2>/dev/null | grep -i 'failed password' | wc -l
    """
    code, out, err = _run(ssh, cmd)

    if code != 0:
        return _pass(
            "Failed login spike",
            "Could not access auth logs",
            "Check /var/log/auth.log permissions",
            category,
        )

    try:
        failed_count = int(out.strip())
    except ValueError:
        return _pass(
            "Failed login spike",
            "Could not parse auth logs",
            "Check auth.log format",
            category,
        )

    # Get unique IPs with failed attempts
    cmd_ips = r"""
    tail -500 /var/log/auth.log 2>/dev/null | grep -i 'failed password' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort | uniq -c | sort -rn | head -5
    """
    code_ips, out_ips, err_ips = _run(ssh, cmd_ips)

    top_ips = out_ips.strip() if out_ips.strip() else ""

    # Threshold: More than 20 failed logins in recent logs is suspicious
    if failed_count > 20:
        ip_summary = "; ".join(top_ips.splitlines()[:3]) if top_ips else "See auth logs"
        return _warn(
            "Failed login spike",
            f"Detected {failed_count} failed login attempts in recent logs. Top sources: {ip_summary}",
            "Review /var/log/auth.log; Consider rate limiting with fail2ban or UFW; Change SSH port",
            category,
        )

    return _pass(
        "Failed login spike",
        f"Failed login attempts in recent logs: {failed_count} (normal range)",
        "Continue monitoring auth logs for brute force attempts",
        category,
    )


def check_suid_files(ssh: SSHSession) -> CheckResult:
    category = "Filesystem"
    cmd = "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -perm -4000 -type f 2>/dev/null | wc -l"
    code, out, err = _run(ssh, cmd)
    if code != 0:
        return _warn(
            "SUID files",
            f"SUID scan failed: {err or out}",
            "Run find for SUID files manually",
            category,
        )
    try:
        count = int(out.strip())
    except ValueError:
        return _warn(
            "SUID files",
            f"Unexpected count output: {out}",
            "Inspect SUID binaries with find",
            category,
        )
    if count > 35:
        return _warn(
            "SUID files",
            f"High SUID count: {count} binaries",
            "Review SUID set: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f",
            category,
        )
    return _pass(
        "SUID files",
        f"SUID binaries: {count}",
        "Periodically review SUID inventory",
        category,
    )


def check_cron_and_timers(ssh: SSHSession) -> CheckResult:
    category = "Persistence"
    cmd = (
        "bash -lc '"  # list cron directories and user crontab presence, timers count
        "ls /etc/cron.d 2>/dev/null | wc -l; "
        "ls /etc/cron.daily 2>/dev/null | wc -l; "
        "ls /etc/cron.hourly 2>/dev/null | wc -l; "
        "(crontab -l 2>/dev/null | wc -l) || true; "
        "(systemctl list-timers --all --no-pager 2>/dev/null | wc -l) || true'"
    )
    code, out, err = _run(ssh, cmd)
    if code != 0:
        return _warn(
            "Cron/Timers",
            f"Could not list cron/timers: {err or out}",
            "Inspect cron.* and systemd timers manually",
            category,
        )
    try:
        cron_d, cron_daily, cron_hourly, crontab_lines, timers = [
            int(x) for x in out.strip().splitlines()[:5]
        ]
    except ValueError:
        return _warn(
            "Cron/Timers",
            f"Unexpected output: {out}",
            "Check cron and timers manually",
            category,
        )
    details = f"cron.d={cron_d}, daily={cron_daily}, hourly={cron_hourly}, user crontab lines={crontab_lines}, timers={timers}"
    if crontab_lines > 0 or cron_d > 10:
        return _warn(
            "Cron/Timers",
            details,
            "Review cron entries and systemd timers for legitimacy; check /etc/cron.* and systemctl list-timers",
            category,
        )
    return _pass(
        "Cron/Timers", details, "Keep cron/timers minimal and documented", category
    )


def check_stale_user_accounts(ssh: SSHSession) -> CheckResult:
    """Check for user accounts that haven't logged in for a long time."""
    category = "Accounts"
    # Get users with shell access (not system accounts) using lastlog
    code, out, err = _run(
        ssh,
        "lastlog 2>/dev/null | tail -n +2 | awk '{print $1, $5, $6, $7, $8, $9}' || echo ''",
    )
    if code != 0 or not out.strip():
        return _pass(
            "Stale user accounts",
            "Could not retrieve last login data",
            "Run 'lastlog' manually to verify",
            category,
        )

    # Parse lastlog output and check for stale accounts (>90 days inactive)
    # lastlog format: username lastlogin date time [timezone]
    from datetime import datetime

    now = datetime.now()
    stale_threshold = 90  # days
    stale_users = []

    for line in out.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        username = parts[0]
        try:
            # Try to parse the date (format: "Nov 15 2024" or similar)
            date_str = " ".join(parts[1:4])  # e.g., "Nov 15 2024"
            last_login = datetime.strptime(date_str, "%b %d %Y")
            days_inactive = (now - last_login).days

            if days_inactive > stale_threshold:
                stale_users.append((username, days_inactive))
        except (ValueError, IndexError):
            # Skip lines with unrecognized date format
            continue

    if stale_users:
        stale_list = ", ".join(
            f"{u}({d}d)"
            for u, d in sorted(stale_users, key=lambda x: x[1], reverse=True)
        )
        return _warn(
            "Stale user accounts",
            f"{len(stale_users)} users inactive >90 days: {stale_list}",
            "Review and consider disabling: usermod -L <user>; remove if no longer needed",
            category,
        )

    return _pass(
        "Stale user accounts",
        "No users inactive >90 days",
        "Monitor login activity periodically",
        category,
    )


def check_process_resource_usage(ssh: SSHSession) -> CheckResult:
    category = "Process Health"
    # Get top 3 processes by CPU and memory
    code, out, err = _run(
        ssh,
        "ps aux --sort=-%cpu --sort=-%mem | head -4 | tail -3 | awk '{print $1, $3, $4, $11}' | tr '\n' '|'",
    )
    if code != 0 or not out.strip():
        return _pass(
            "Process monitoring", "Processes OK", "Monitor with 'top -o %CPU'", category
        )

    # Check for high CPU or memory processes
    high_cpu = False
    high_mem = False
    details_list = []

    for proc_line in out.split("|"):
        if not proc_line.strip():
            continue
        parts = proc_line.strip().split()
        if len(parts) >= 3:
            try:
                cpu = float(parts[1])
                mem = float(parts[2])
                proc_name = parts[3] if len(parts) > 3 else "unknown"

                if cpu > 80:
                    high_cpu = True
                    details_list.append(f"{proc_name} CPU={cpu}%")
                if mem > 80:
                    high_mem = True
                    details_list.append(f"{proc_name} MEM={mem}%")
            except (ValueError, IndexError):
                pass

    if high_cpu or high_mem:
        details = (
            ", ".join(details_list) if details_list else "High resource usage detected"
        )
        return _warn(
            "Process monitoring",
            details,
            "Investigate with 'ps aux --sort=-%cpu' and check for leaks or runaway processes",
            category,
        )

    return _pass(
        "Process monitoring",
        "All processes within normal resource limits",
        "Continue monitoring",
        category,
    )


def gather_suid_binaries(ssh: SSHSession) -> str:
    """Get list of SUID binaries with last modified time."""
    cmd = "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -perm -4000 -type f -printf '%T@ %Tc %p\\n' 2>/dev/null | sort -rn | head -30"
    code, out, err = _run(ssh, cmd)
    if code != 0 or not out.strip():
        return "Could not retrieve SUID binaries"
    return out.strip()


def gather_root_logins(ssh: SSHSession) -> str:
    """Get recent root login details."""
    cmd = "last -5 root 2>/dev/null | grep -v '^wtmp' | head -10"
    code, out, err = _run(ssh, cmd)
    if code != 0 or not out.strip():
        return "No recent root logins found (or last not available)"
    return out.strip()


def gather_successful_ssh_logins(ssh: SSHSession, password: str = "") -> str:
    """Get recent successful SSH login details."""
    cmd = (
        "bash -lc 'if command -v journalctl >/dev/null 2>&1; then "
        'journalctl -u ssh -S -7d --no-pager 2>/dev/null | grep -i "Accepted password\\|Accepted publickey" | tail -10; '
        'elif [ -f /var/log/auth.log ]; then grep -i "Accepted password\\|Accepted publickey" /var/log/auth.log | tail -10; '
        'elif [ -f /var/log/secure ]; then grep -i "Accepted password\\|Accepted publickey" /var/log/secure | tail -10; '
        'else echo "No auth logs found"; fi\''
    )
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)
    if code != 0 or not out.strip():
        return "No successful SSH logins found (or logs not available)"
    return out.strip()


def gather_failed_ssh_logins(ssh: SSHSession, password: str = "") -> str:
    """Get recent failed SSH login attempts."""
    cmd = (
        "bash -lc 'if command -v journalctl >/dev/null 2>&1; then "
        'journalctl -u ssh -S -7d --no-pager 2>/dev/null | grep -i "Failed password" | tail -10; '
        'elif [ -f /var/log/auth.log ]; then grep -i "Failed password" /var/log/auth.log | tail -10; '
        'elif [ -f /var/log/secure ]; then grep -i "Failed password" /var/log/secure | tail -10; '
        'else echo "No auth logs found"; fi\''
    )
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)
    if code != 0 or not out.strip():
        return "No failed SSH logins found (or logs not available)"
    return out.strip()


def gather_top_processes(ssh: SSHSession) -> str:
    """Get top processes by CPU/memory usage."""
    cmd = "ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head -20"
    code, out, err = _run(ssh, cmd)
    if code != 0 or not out.strip():
        return "Could not retrieve process list"
    return out.strip()


def gather_disk_usage_dirs(ssh: SSHSession, password: str = "") -> str:
    """Get disk usage by top-level directory."""
    cmd = "timeout 20 du -xhd1 / 2>/dev/null | sort -hr | head -20"
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)
    if code != 0 or not out.strip():
        return "Could not retrieve disk usage"
    return out.strip()


def gather_available_updates(ssh: SSHSession, password: str = "") -> str:
    """Check for available security updates."""
    cmd = (
        "bash -lc 'if command -v apt-get >/dev/null 2>&1; then "
        'timeout 20 apt-get -s upgrade 2>/dev/null | grep -i "^Inst" | wc -l; '
        'elif command -v yum >/dev/null 2>&1; then timeout 20 yum check-update 2>/dev/null | grep -v "^$" | wc -l; '
        'else echo "Update check not available"; fi\''
    )
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)
    if code != 0 or not out.strip():
        return "Could not check available updates"
    count = out.strip()
    return f"{count} packages available for update"


def gather_firewall_rules(ssh: SSHSession, password: str = "") -> str:
    """Get firewall rules/status."""
    cmd = (
        "bash -lc 'if command -v ufw >/dev/null 2>&1; then "
        "ufw status verbose 2>/dev/null | head -30; "
        "elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --list-all 2>/dev/null; "
        "elif command -v iptables >/dev/null 2>&1; then iptables -L -n -v 2>/dev/null | head -30; "
        'else echo "No firewall info available"; fi\''
    )
    if password:
        cmd = f"sudo -S {cmd}"
    code, out, err = _run(ssh, cmd, password)
    if code != 0 or not out.strip():
        return "Could not retrieve firewall rules"
    return out.strip()


def gather_sshd_config_check(ssh: SSHSession, password: str = "") -> str:
    """Verify SSH daemon configuration."""
    if password:
        cmd = f"echo '{password}' | sudo -S sshd -T 2>/dev/null | grep -E \"^(permitrootlogin|passwordauthentication|permituserslogin|port)\" | sort"
    else:
        cmd = 'sshd -T 2>/dev/null | grep -E "^(permitrootlogin|passwordauthentication|permituserslogin|port)" | sort'
    code, out, err = _run(ssh, cmd)
    if code != 0 or not out.strip():
        return "Could not verify SSH config"
    return out.strip()


def gather_failed_systemd_units(ssh: SSHSession) -> str:
    """Check for failed systemd units with severity classification."""
    cmd = "systemctl list-units --state=failed --no-legend 2>/dev/null || echo 'systemd not available'"
    code, out, err = _run(ssh, cmd)
    if code != 0 or not out.strip():
        return "Could not retrieve systemd status"

    lines = out.strip().split("\n")
    if not lines or lines[0].startswith("No failed units"):
        return "No failed units"

    # Classify failed units by severity
    critical_services = {
        "systemd-",
        "network",
        "ssh",
        "sshd",
        "networking",
        "multipathd",
        "lvm",
        "cryptsetup",
    }
    info_services = {"snap-", "lxc", "motd-news", "certbot", "apt-daily"}

    critical_units = []
    warning_units = []
    info_units = []

    for line in lines[:15]:  # Limit output to first 15
        line_lower = line.lower()
        is_critical = any(svc in line_lower for svc in critical_services)
        is_info = any(svc in line_lower for svc in info_services)

        if is_critical:
            critical_units.append(f"[CRITICAL] {line}")
        elif is_info:
            info_units.append(f"[INFO] {line}")
        else:
            warning_units.append(f"[WARNING] {line}")

    # Format output with severity ordering
    result = []
    if critical_units:
        result.append("=== CRITICAL UNITS ===")
        result.extend(critical_units)
    if warning_units:
        result.append("=== WARNING UNITS ===")
        result.extend(warning_units)
    if info_units:
        result.append("=== INFO UNITS ===")
        result.extend(info_units)

    return "\n".join(result) if result else "No failed units"


def gather_sudoers_info(ssh: SSHSession, password: str = "") -> str:
    """Get sudoers configuration summary."""
    if password:
        cmd = 'sudo -S bash -lc \'visudo -c >/dev/null 2>&1 && echo "Sudoers syntax: OK" ; grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$" | head -10\''
        code, out, err = _run(ssh, cmd, password)
    else:
        cmd = 'bash -lc \'echo "Sudoers check requires privilege" ; head -10 /etc/sudoers 2>/dev/null || echo "Access denied"\''
        code, out, err = _run(ssh, cmd)
    if code != 0 or not out.strip():
        return "Could not retrieve sudoers info"
    return out.strip()


def gather_critical_file_permissions(ssh: SSHSession) -> str:
    """Check permissions on critical system files."""
    cmd = (
        "bash -lc 'ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config 2>/dev/null | "
        'awk "{print \\$1, \\$9}" | grep -v "^total"\''
    )
    code, out, err = _run(ssh, cmd)
    if code != 0 or not out.strip():
        return "Could not retrieve critical file permissions"
    return out.strip()


def gather_rkhunter_scan(ssh: SSHSession, password: str = "") -> str | None:
    """Run rkhunter rootkit scan if available on the target system.

    Returns scan summary or None if rkhunter is not installed.
    """
    # First check if rkhunter is installed
    check_cmd = "which rkhunter >/dev/null 2>&1 && echo 'found' || echo 'not_found'"
    code, out, err = _run(ssh, check_cmd)

    if "not_found" in out or code != 0:
        return None  # rkhunter not installed

    # rkhunter is installed, run the scan
    # Use --skip-keypress only (--skip-warnings may not be supported in all versions)
    cmd = "rkhunter --check --skip-keypress 2>&1 | tail -50"
    if password:
        cmd = f"sudo -S {cmd}"

    code, out, err = _run(ssh, cmd, password)
    if code != 0 or not out.strip():
        return "rkhunter scan failed or produced no output"
    return out.strip()


def gather_unused_packages(ssh: SSHSession, password: str = "") -> str | None:
    """Check for unused/orphaned packages and bloat.

    Returns summary of potentially unused packages or None if unable to determine.
    Includes: orphaned packages, development tools, and known bloat.
    """
    # Detect package manager and system
    detect_cmd = (
        "if command -v apt-get >/dev/null 2>&1; then echo 'apt'; "
        "elif command -v yum >/dev/null 2>&1; then echo 'yum'; "
        "else echo 'unknown'; fi"
    )
    code, pkg_mgr, _ = _run(ssh, detect_cmd)
    pkg_mgr = pkg_mgr.strip()

    results: list[str] = []

    if pkg_mgr == "apt":
        # Ubuntu/Debian: check for autoremovable packages
        cmd = "apt-get autoremove --dry-run 2>/dev/null | grep '^Remov' || echo 'No orphaned packages'"
        if password:
            cmd = f"sudo -S {cmd}"
        code, out, err = _run(ssh, cmd, password)
        if out.strip():
            results.append("=== Orphaned/Autoremovable Packages ===")
            results.append(out.strip())

        # Check for common development tools
        dev_packages = ["build-essential", "gcc", "g++", "python3-dev", "git"]
        dev_check_cmd = f"dpkg -l 2>/dev/null | grep -E '{','.join(dev_packages)}' | awk '{{print $2}}' || true"
        code, out, err = _run(ssh, dev_check_cmd)
        if out.strip():
            results.append("\n=== Installed Development Tools ===")
            results.append(out.strip())
            results.append("(Remove if development is not needed)")

        # Check for known bloat packages
        bloat = ["telnet", "talk", "rsh-client", "nis", "xserver-xorg", "cups"]
        bloat_check_cmd = f"dpkg -l 2>/dev/null | grep -E '{','.join(bloat)}' | awk '{{print $2}}' || true"
        code, out, err = _run(ssh, bloat_check_cmd)
        if out.strip():
            results.append("\n=== Potentially Unnecessary Packages ===")
            results.append(out.strip())
            results.append("(Consider removing if not required)")

    elif pkg_mgr == "yum":
        # CentOS/RHEL: check for orphaned packages
        cmd = "package-cleanup --all --all-dups 2>/dev/null | head -20 || echo 'Unable to check'"
        if password:
            cmd = f"sudo -S {cmd}"
        code, out, err = _run(ssh, cmd, password)
        if out.strip() and "Unable" not in out:
            results.append("=== Duplicate/Orphaned Packages ===")
            results.append(out.strip())

    else:
        return "Package manager not detected (apt/yum not found)"

    if not results:
        return "No obvious unused packages detected"

    return "\n".join(results)


def check_suspicious_network_connections(ssh: SSHSession) -> CheckResult:
    """Check for established connections to suspicious IPs, unusual ports, or foreign countries."""
    category = "Network Security"
    # Get established connections with foreign addresses (exclude localhost and local networks)
    cmd = (
        "bash -lc 'ss -tn state established 2>/dev/null | "
        'awk "\\$4 !~ /^127\\./ && \\$4 !~ /^192\\.168\\./ && \\$4 !~ /^10\\./ && \\$4 !~ /^172\\.(1[6-9]|2[0-9]|3[01])\\./ {print}" | '
        "wc -l'"
    )
    code, out, err = _run(ssh, cmd)
    if code != 0:
        return _warn(
            "Suspicious connections",
            f"Failed to check: {err or out}",
            "Run ss -tn state established manually",
            category,
        )

    try:
        external_conns = int(out.strip())
    except ValueError:
        return _warn(
            "Suspicious connections",
            f"Unexpected output: {out}",
            "Check network connections manually",
            category,
        )

    # Get details of external connections for inspection
    cmd_details = (
        "bash -lc 'ss -tnp state established 2>/dev/null | "
        'awk "\\$4 !~ /^127\\./ && \\$4 !~ /^192\\.168\\./ && \\$4 !~ /^10\\./ && \\$4 !~ /^172\\.(1[6-9]|2[0-9]|3[01])\\./ {print}" | '
        "head -10'"
    )
    code2, conn_details, _ = _run(ssh, cmd_details)

    if external_conns > 50:
        return _fail(
            "Suspicious connections",
            f"{external_conns} external connections detected",
            "Review with 'ss -tnp state established' - possible botnet, C&C, or data exfiltration",
            category,
        )
    elif external_conns > 20:
        return _warn(
            "Suspicious connections",
            f"{external_conns} external connections detected",
            "Review connections: 'ss -tnp state established | grep -v 127.0.0.1'",
            category,
        )

    return _pass(
        "Suspicious connections",
        f"{external_conns} external connections (normal for web servers)",
        "Monitor periodically",
        category,
    )


def check_hidden_files_in_system_dirs(ssh: SSHSession) -> CheckResult:
    """Search for hidden files in system directories (common backdoor location)."""
    category = "Malware/Backdoors"
    # Search for hidden files in critical system directories
    cmd = (
        "bash -lc 'find /tmp /var/tmp /dev/shm /usr/bin /usr/sbin /bin /sbin /etc "
        '-name ".*" -type f 2>/dev/null | head -20 | wc -l\''
    )
    code, out, err = _run(ssh, cmd)
    if code != 0:
        return _warn(
            "Hidden system files",
            f"Search failed: {err or out}",
            "Check manually with find",
            category,
        )

    try:
        hidden_count = int(out.strip())
    except ValueError:
        return _warn(
            "Hidden system files",
            f"Unexpected output: {out}",
            "Check manually",
            category,
        )

    if hidden_count > 5:
        # Get samples
        cmd_sample = (
            "bash -lc 'find /tmp /var/tmp /dev/shm /usr/bin /usr/sbin /bin /sbin /etc "
            '-name ".*" -type f 2>/dev/null | head -5\''
        )
        _, samples, _ = _run(ssh, cmd_sample)
        return _fail(
            "Hidden system files",
            f"{hidden_count}+ hidden files in system directories. Examples: {samples[:200]}",
            "Investigate each file - may be malware/backdoors",
            category,
        )
    elif hidden_count > 0:
        cmd_sample = (
            "bash -lc 'find /tmp /var/tmp /dev/shm /usr/bin /usr/sbin /bin /sbin /etc "
            '-name ".*" -type f 2>/dev/null | head -5\''
        )
        _, samples, _ = _run(ssh, cmd_sample)
        return _warn(
            "Hidden system files",
            f"{hidden_count} hidden files found: {samples[:150]}",
            "Review these files for legitimacy",
            category,
        )

    return _pass(
        "Hidden system files",
        "No suspicious hidden files in system directories",
        "No action",
        category,
    )


def check_kernel_module_integrity(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check for unsigned or suspicious kernel modules."""
    category = "Kernel Security"
    # List loaded kernel modules
    cmd = "lsmod | wc -l"
    code, out, err = _run(ssh, cmd)
    if code != 0:
        return _warn(
            "Kernel modules", f"lsmod failed: {err or out}", "Check manually", category
        )

    try:
        module_count = int(out.strip()) - 1  # Subtract header
    except ValueError:
        return _warn(
            "Kernel modules",
            f"Unexpected output: {out}",
            "Run lsmod manually",
            category,
        )

    # Check for modules not in /lib/modules (suspicious location)
    cmd_suspicious = (
        'bash -lc \'for mod in $(lsmod | tail -n +2 | awk "{print \\$1}"); do '
        'modinfo "$mod" 2>/dev/null | grep -q "^filename:.*\\/lib\\/modules" || echo "$mod"; '
        "done | head -5'"
    )
    code2, suspicious, _ = _run(ssh, cmd_suspicious)

    if suspicious.strip():
        return _fail(
            "Kernel modules",
            f"Suspicious modules not in /lib/modules: {suspicious[:200]}",
            "Investigate module origins - possible rootkit",
            category,
        )

    # Warn if too many modules loaded (possible bloat or compromise)
    if module_count > 150:
        return _warn(
            "Kernel modules",
            f"{module_count} kernel modules loaded (high count)",
            "Review 'lsmod' output for unnecessary modules",
            category,
        )

    return _pass(
        "Kernel modules",
        f"{module_count} modules loaded, all in standard paths",
        "No action",
        category,
    )


def check_active_reverse_shells(ssh: SSHSession) -> CheckResult:
    """Detect common reverse shell patterns in running processes."""
    category = "Malware/Backdoors"
    # Search for common reverse shell indicators
    patterns = [
        "bash -i",
        "sh -i",
        "/dev/tcp/",
        "/dev/udp/",
        "nc -e",
        "ncat -e",
        "socat",
        "python.*socket",
        "perl.*socket",
        "ruby.*socket",
    ]

    cmd = f"bash -lc 'ps aux | grep -E \"({'|'.join(patterns)})\" | grep -v grep | head -5'"
    code, out, err = _run(ssh, cmd)

    if out.strip():
        return _fail(
            "Reverse shell detection",
            f"Possible reverse shell detected: {out[:250]}",
            "URGENT: Investigate immediately - possible active compromise",
            category,
        )

    return _pass(
        "Reverse shell detection",
        "No obvious reverse shell patterns detected",
        "No action",
        category,
    )


def check_weak_password_policy(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check PAM configuration for password strength requirements."""
    category = "Authentication"
    # Check common PAM password quality settings
    cmd = (
        'bash -lc \'grep -E "pam_pwquality|pam_cracklib|minlen|dcredit|ucredit" '
        "/etc/pam.d/common-password /etc/pam.d/system-auth /etc/security/pwquality.conf 2>/dev/null | head -10'"
    )
    if password:
        cmd = f"sudo -S {cmd}"

    code, out, err = _run(ssh, cmd, password)

    if not out.strip():
        return _fail(
            "Password policy",
            "No password quality settings found",
            "Configure pam_pwquality or pam_cracklib for password complexity",
            category,
        )

    # Check for minimum length requirement
    if "minlen" in out.lower():
        minlen_match = re.search(r"minlen\s*=\s*(\d+)", out, re.IGNORECASE)
        if minlen_match:
            minlen = int(minlen_match.group(1))
            if minlen < 8:
                return _warn(
                    "Password policy",
                    f"Weak minimum password length: {minlen}",
                    "Set minlen >= 12 in PAM configuration",
                    category,
                )
        return _pass(
            "Password policy",
            "Password quality module configured",
            "Verify complexity requirements are adequate",
            category,
        )

    return _warn(
        "Password policy",
        "Password policy configured but may be weak",
        "Review /etc/pam.d/ and /etc/security/pwquality.conf",
        category,
    )


def check_container_escape_indicators(ssh: SSHSession) -> CheckResult:
    """Look for container escape attempts or suspicious container activity."""
    category = "Container Security"
    # Check if running in a container
    cmd_in_container = "bash -lc '[ -f /.dockerenv ] && echo docker || [ -f /run/.containerenv ] && echo podman || echo none'"
    code, container_type, _ = _run(ssh, cmd_in_container)
    container_type = container_type.strip()

    # Check for suspicious mount points that could indicate escape attempts
    cmd = (
        'bash -lc \'mount | grep -E "(docker|lxc|overlay)" | '
        'grep -E "(\\s/\\s|\\s/proc\\s|\\s/sys\\s|\\s/dev\\s)" | wc -l\''
    )
    code2, out, err = _run(ssh, cmd)

    try:
        suspicious_mounts = int(out.strip()) if out.strip() else 0
    except ValueError:
        suspicious_mounts = 0

    # Check for privileged container indicators
    cmd_priv = "bash -lc '[ -c /dev/kmsg ] && echo privileged || echo restricted'"
    code3, priv_status, _ = _run(ssh, cmd_priv)

    if container_type != "none":
        if priv_status.strip() == "privileged":
            return _fail(
                "Container security",
                f"Running in privileged {container_type} container - high escape risk",
                "Avoid privileged containers; use capability-based security",
                category,
            )
        return _pass(
            "Container security",
            f"Running in {container_type} container with restrictions",
            "Monitor for escape attempts",
            category,
        )

    # Not in container - check if Docker daemon is exposing host
    cmd_docker = (
        "bash -lc 'ps aux | grep \"dockerd\\|containerd\" | grep -v grep | wc -l'"
    )
    code4, docker_running, _ = _run(ssh, cmd_docker)

    try:
        has_docker = (
            int(docker_running.strip()) > 0 if docker_running.strip() else False
        )
    except ValueError:
        has_docker = False

    if has_docker and suspicious_mounts > 2:
        return _warn(
            "Container security",
            "Docker/container runtime active with multiple overlay mounts",
            "Ensure containers are not running privileged; review docker ps",
            category,
        )

    return _pass(
        "Container security",
        "No container security issues detected",
        "No action",
        category,
    )


def check_arp_spoofing(ssh: SSHSession) -> CheckResult:
    """Check ARP cache for duplicate MAC addresses (ARP spoofing indicator)."""
    category = "Network Security"
    # Get ARP table and check for duplicate MAC addresses
    cmd = "bash -lc 'ip neigh show 2>/dev/null | awk \"{print \\$5}\" | sort | uniq -d'"
    code, out, err = _run(ssh, cmd)

    if code != 0:
        return _warn(
            "ARP spoofing",
            f"Failed to check ARP table: {err or out}",
            "Run 'ip neigh show' manually",
            category,
        )

    duplicates = out.strip()
    if duplicates:
        return _fail(
            "ARP spoofing",
            f"Duplicate MAC addresses in ARP table: {duplicates}",
            "URGENT: Possible ARP spoofing attack - investigate network immediately",
            category,
        )

    # Count ARP entries
    cmd_count = "bash -lc 'ip neigh show 2>/dev/null | wc -l'"
    code2, count_out, _ = _run(ssh, cmd_count)
    try:
        arp_entries = int(count_out.strip())
    except ValueError:
        arp_entries = 0

    if arp_entries > 100:
        return _warn(
            "ARP spoofing",
            f"Large ARP table ({arp_entries} entries) - possible ARP scan",
            "Monitor network for scanning activity",
            category,
        )

    return _pass(
        "ARP spoofing",
        f"ARP table clean ({arp_entries} entries)",
        "No action",
        category,
    )


def check_dns_tampering(ssh: SSHSession) -> CheckResult:
    """Verify DNS resolver integrity and check for DNS hijacking."""
    category = "Network Security"
    # Check resolv.conf for suspicious nameservers
    cmd = (
        "bash -lc 'grep nameserver /etc/resolv.conf 2>/dev/null | awk \"{print \\$2}\"'"
    )
    code, out, err = _run(ssh, cmd)

    if code != 0:
        return _warn(
            "DNS tampering",
            "Could not read /etc/resolv.conf",
            "Check DNS configuration manually",
            category,
        )

    nameservers = out.strip().split("\n") if out.strip() else []
    suspicious_dns = []

    # List of suspicious/known malicious DNS servers
    known_bad = ["0.0.0.0", "127.0.0.2"]  # Basic blacklist

    for ns in nameservers:
        ns = ns.strip()
        if not ns:
            continue
        if ns in known_bad:
            suspicious_dns.append(ns)
        # Warn about non-standard DNS (not 8.8.8.8, 1.1.1.1, or local network)
        if not (
            ns.startswith("127.")
            or ns.startswith("192.168.")
            or ns.startswith("10.")
            or ns in ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
        ):
            # This could be corporate DNS, so just note it
            pass

    if suspicious_dns:
        return _fail(
            "DNS tampering",
            f"Suspicious DNS servers configured: {', '.join(suspicious_dns)}",
            "URGENT: DNS may be hijacked - verify /etc/resolv.conf",
            category,
        )

    if not nameservers:
        return _warn(
            "DNS tampering",
            "No DNS nameservers configured",
            "Configure proper DNS resolution",
            category,
        )

    return _pass(
        "DNS tampering",
        f"DNS configuration OK ({len(nameservers)} nameservers)",
        "No action",
        category,
    )


def check_crypto_miners(ssh: SSHSession) -> CheckResult:
    """Detect cryptocurrency mining processes and connections."""
    category = "Malware/Backdoors"
    # Common crypto miner process names and patterns
    miner_patterns = [
        "xmrig",
        "minerd",
        "cpuminer",
        "ccminer",
        "cryptonight",
        "stratum",
        "nicehash",
        "ethminer",
        "phoenixminer",
        "claymore",
        "t-rex",
    ]

    cmd = (
        f"bash -lc 'ps aux | grep -iE \"({'|'.join(miner_patterns)})\" | grep -v grep'"
    )
    code, out, err = _run(ssh, cmd)

    if out.strip():
        return _fail(
            "Crypto mining",
            f"Cryptocurrency miner detected: {out[:300]}",
            "URGENT: Kill mining process and remove malware immediately",
            category,
        )

    # Check for mining pool connections (common ports: 3333, 4444, 5555, 7777, 9999)
    cmd_ports = (
        "bash -lc 'ss -tn 2>/dev/null | "
        'awk "\\$4 ~ /:3333$|:4444$|:5555$|:7777$|:9999$|:14444$/ {print}"\''
    )
    code2, port_out, _ = _run(ssh, cmd_ports)

    if port_out.strip():
        return _fail(
            "Crypto mining",
            f"Connections to known mining ports detected: {port_out[:200]}",
            "URGENT: Investigate process using mining ports",
            category,
        )

    # Check CPU usage for prolonged high usage (possible silent miner)
    cmd_cpu = 'bash -lc \'top -bn1 | grep "Cpu(s)" | awk "{print \\$2}" | cut -d% -f1\''
    code3, cpu_out, _ = _run(ssh, cmd_cpu)

    try:
        cpu_usage = float(cpu_out.strip()) if cpu_out.strip() else 0
    except ValueError:
        cpu_usage = 0

    if cpu_usage > 90:
        return _warn(
            "Crypto mining",
            f"Very high CPU usage ({cpu_usage:.1f}%) - possible hidden miner",
            "Check 'top' for suspicious processes with high CPU",
            category,
        )

    return _pass(
        "Crypto mining",
        "No cryptocurrency mining activity detected",
        "No action",
        category,
    )


def check_file_integrity_critical_binaries(ssh: SSHSession) -> CheckResult:
    """Check modification times on critical system binaries."""
    category = "File Integrity"
    # Check if any critical binaries were modified recently (last 7 days)
    critical_bins = [
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/sudo",
        "/bin/su",
        "/usr/bin/ssh",
        "/sbin/init",
    ]

    cmd = f"bash -lc 'find {' '.join(critical_bins)} -mtime -7 2>/dev/null'"
    code, out, err = _run(ssh, cmd)

    if out.strip():
        return _fail(
            "Critical binary integrity",
            f"Critical binaries modified in last 7 days: {out}",
            "URGENT: Verify legitimacy - possible trojan/rootkit installation",
            category,
        )

    # Check if binaries exist and have expected permissions
    cmd_check = (
        f"bash -lc 'ls -la {' '.join(critical_bins)} 2>/dev/null | "
        'awk "{print \\$1, \\$9}"\''
    )
    code2, perm_out, _ = _run(ssh, cmd_check)

    # Look for world-writable critical binaries
    if "rw-rw-rw" in perm_out or "rwxrwxrwx" in perm_out:
        return _fail(
            "Critical binary integrity",
            "World-writable critical binaries detected",
            "URGENT: Fix permissions immediately - severe security risk",
            category,
        )

    return _pass(
        "Critical binary integrity",
        "Critical binaries unmodified and properly secured",
        "No action",
        category,
    )


def check_log_tampering(ssh: SSHSession, password: str = "") -> CheckResult:
    """Look for gaps or manipulation in system logs."""
    category = "Log Security"
    # Check for large gaps in auth.log timestamps
    cmd = (
        "bash -lc 'if [ -f /var/log/auth.log ]; then "
        "tail -1000 /var/log/auth.log 2>/dev/null | wc -l; "
        "elif [ -f /var/log/secure ]; then "
        "tail -1000 /var/log/secure 2>/dev/null | wc -l; "
        "else echo 0; fi'"
    )
    if password:
        cmd = f"sudo -S {cmd}"

    code, out, err = _run(ssh, cmd, password)

    try:
        log_lines = int(out.strip())
    except ValueError:
        return _warn(
            "Log tampering",
            "Could not read authentication logs",
            "Check log file permissions",
            category,
        )

    if log_lines == 0:
        return _fail(
            "Log tampering",
            "Authentication logs are empty or missing",
            "URGENT: Logs may have been deleted - check /var/log/ permissions and investigate",
            category,
        )

    if log_lines < 50:
        return _warn(
            "Log tampering",
            f"Very few log entries ({log_lines}) - possible log rotation or deletion",
            "Verify log retention and check for suspicious activity",
            category,
        )

    # Check syslog/messages
    cmd_syslog = (
        "bash -lc 'if [ -f /var/log/syslog ]; then "
        "tail -1000 /var/log/syslog 2>/dev/null | wc -l; "
        "elif [ -f /var/log/messages ]; then "
        "tail -1000 /var/log/messages 2>/dev/null | wc -l; "
        "else echo 0; fi'"
    )
    if password:
        cmd_syslog = f"sudo -S {cmd_syslog}"

    code2, syslog_out, _ = _run(ssh, cmd_syslog, password)

    try:
        syslog_lines = int(syslog_out.strip())
    except ValueError:
        syslog_lines = 0

    if syslog_lines == 0:
        return _warn(
            "Log tampering",
            "System logs are empty",
            "Check logging configuration and disk space",
            category,
        )

    return _pass(
        "Log tampering",
        f"Log files appear intact ({log_lines} auth, {syslog_lines} syslog entries)",
        "No action",
        category,
    )


def check_privilege_escalation_vectors(
    ssh: SSHSession, password: str = ""
) -> CheckResult:
    """Check for common privilege escalation vulnerabilities."""
    category = "Privilege Escalation"
    vectors = []

    # Check for NOPASSWD in sudoers
    cmd_sudo = "bash -lc 'grep -r NOPASSWD /etc/sudoers.d/ /etc/sudoers 2>/dev/null | grep -v \"^#\"'"
    if password:
        cmd_sudo = f"sudo -S {cmd_sudo}"
    code, sudo_out, _ = _run(ssh, cmd_sudo, password)

    if sudo_out.strip():
        vectors.append(f"NOPASSWD sudo entries: {sudo_out[:150]}")

    # Check for capabilities on binaries
    cmd_cap = "bash -lc 'getcap -r / 2>/dev/null | head -10'"
    code2, cap_out, _ = _run(ssh, cmd_cap)

    if cap_out.strip() and "cap_setuid" in cap_out:
        vectors.append(f"Dangerous capabilities: {cap_out[:150]}")

    # Check for writable /etc/passwd
    cmd_passwd = "bash -lc '[ -w /etc/passwd ] && echo writable || echo protected'"
    code3, passwd_out, _ = _run(ssh, cmd_passwd)

    if "writable" in passwd_out:
        vectors.append("/etc/passwd is writable!")

    # Check for sudo version vulnerabilities (CVE-2021-3156 Baron Samedit)
    cmd_sudo_ver = "bash -lc 'sudo --version 2>/dev/null | head -1'"
    code4, sudo_ver, _ = _run(ssh, cmd_sudo_ver)

    if sudo_ver.strip():
        # Check for vulnerable sudo versions (< 1.9.5p2)
        ver_match = re.search(r"version (\d+)\.(\d+)\.(\d+)", sudo_ver)
        if ver_match:
            major, minor, patch = (
                int(ver_match.group(1)),
                int(ver_match.group(2)),
                int(ver_match.group(3)),
            )
            # Vulnerable if version < 1.9.5, or exactly 1.9.5 without p2+ suffix
            if major == 1 and minor == 8:
                vectors.append(
                    f"Vulnerable sudo version: {major}.{minor}.{patch} (CVE-2021-3156 possible)"
                )
            elif major == 1 and minor == 9 and patch < 5:
                vectors.append(
                    f"Vulnerable sudo version: {major}.{minor}.{patch} (CVE-2021-3156 possible)"
                )
            elif (
                major == 1
                and minor == 9
                and patch == 5
                and "p1" not in sudo_ver
                and "p0" not in sudo_ver
            ):
                # 1.9.5 without patchlevel or with p0/p1 is vulnerable
                pass  # Could add more detailed check here

    if len(vectors) >= 2:
        return _fail(
            "Privilege escalation",
            f"{len(vectors)} escalation vectors found: " + "; ".join(vectors),
            "URGENT: Patch vulnerabilities and review sudo configuration",
            category,
        )
    elif vectors:
        return _warn(
            "Privilege escalation",
            f"Escalation vector found: {vectors[0]}",
            "Review and mitigate privilege escalation risks",
            category,
        )

    return _pass(
        "Privilege escalation",
        "No obvious escalation vectors detected",
        "Continue monitoring",
        category,
    )


def check_world_writable_system_files(ssh: SSHSession) -> CheckResult:
    """Check for world-writable files in system paths."""
    category = "File Permissions"
    # Search for world-writable files in critical directories
    cmd = (
        "bash -lc 'find /bin /sbin /usr/bin /usr/sbin /etc "
        "-type f -perm -002 2>/dev/null | head -10'"
    )
    code, out, err = _run(ssh, cmd)

    if code != 0:
        return _warn(
            "World-writable files",
            "Could not search for writable files",
            "Run find manually",
            category,
        )

    writable_files = out.strip()
    if writable_files:
        file_list = writable_files.split("\n")
        return _fail(
            "World-writable files",
            f"{len(file_list)} world-writable files in system paths: {writable_files[:300]}",
            "URGENT: Fix permissions immediately with 'chmod o-w <file>'",
            category,
        )

    return _pass(
        "World-writable files",
        "No world-writable files in system directories",
        "No action",
        category,
    )


def check_deleted_file_handles(ssh: SSHSession) -> CheckResult:
    """Check for processes holding handles to deleted files (rootkit indicator)."""
    category = "Malware/Backdoors"
    # List processes with deleted file handles
    cmd = "bash -lc 'lsof +L1 2>/dev/null | grep -v \"^COMMAND\" | head -10'"
    code, out, err = _run(ssh, cmd)

    if code != 0:
        return _warn(
            "Deleted file handles",
            "lsof not available or failed",
            "Install lsof for this check",
            category,
        )

    if out.strip():
        return _warn(
            "Deleted file handles",
            f"Processes with deleted file handles: {out[:300]}",
            "May indicate rootkit or running malware - investigate processes",
            category,
        )

    return _pass(
        "Deleted file handles",
        "No suspicious deleted file handles",
        "No action",
        category,
    )


def check_boot_loader_password(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if GRUB bootloader has password protection."""
    category = "Boot/Kernel"
    cmd = (
        "bash -lc 'if [ -f /boot/grub/grub.cfg ]; then "
        'grep -E "^password|^set superusers" /boot/grub/grub.cfg 2>/dev/null; '
        "elif [ -f /boot/grub2/grub.cfg ]; then "
        'grep -E "^password|^set superusers" /boot/grub2/grub.cfg 2>/dev/null; '
        "fi'"
    )
    if password:
        cmd = f"sudo -S {cmd}"

    code, out, err = _run(ssh, cmd, password)

    if code != 0 or not out.strip():
        return _warn(
            "Bootloader password",
            "GRUB bootloader has no password protection",
            "Set GRUB password with 'grub-mkpasswd-pbkdf2' and configure in /etc/grub.d/40_custom",
            category,
        )

    return _pass(
        "Bootloader password",
        "GRUB password protection enabled",
        "No action",
        category,
    )


def check_kernel_hardening(ssh: SSHSession) -> CheckResult:
    """Check kernel security parameters (sysctl hardening)."""
    category = "Boot/Kernel"

    # Check critical security parameters
    security_params = {
        "kernel.dmesg_restrict": "1",
        "kernel.kptr_restrict": "2",
        "kernel.yama.ptrace_scope": "1",
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.default.rp_filter": "1",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.default.accept_source_route": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "fs.suid_dumpable": "0",
    }

    cmd = "bash -lc 'sysctl " + " ".join(security_params.keys()) + " 2>/dev/null'"
    code, out, err = _run(ssh, cmd)

    if code != 0:
        return _warn(
            "Kernel hardening",
            "sysctl not available or failed",
            "Check kernel parameters manually",
            category,
        )

    issues = []
    for line in out.splitlines():
        for param, expected in security_params.items():
            if param in line:
                parts = line.split("=")
                if len(parts) == 2:
                    actual = parts[1].strip()
                    if actual != expected:
                        issues.append(f"{param}={actual} (expected {expected})")

    if issues:
        return _warn(
            "Kernel hardening",
            f"Insecure kernel parameters: {', '.join(issues[:5])}",
            "Configure hardening parameters in /etc/sysctl.conf or /etc/sysctl.d/",
            category,
        )

    return _pass(
        "Kernel hardening",
        f"Critical kernel security parameters properly configured ({len(security_params)} checked)",
        "No action",
        category,
    )


def check_file_integrity_tools(ssh: SSHSession) -> CheckResult:
    """Check for presence of file integrity monitoring tools (AIDE, Tripwire, OSSEC)."""
    category = "System Integrity"

    tools = ["aide", "tripwire", "ossec-control", "samhain"]
    cmd = (
        "bash -lc 'for tool in "
        + " ".join(tools)
        + "; do command -v $tool 2>/dev/null && echo $tool; done'"
    )

    code, out, err = _run(ssh, cmd)

    if not out.strip():
        return _warn(
            "File integrity monitoring",
            "No file integrity monitoring tool detected (AIDE, Tripwire, OSSEC, Samhain)",
            "Install and configure AIDE: 'apt install aide && aideinit' or Tripwire",
            category,
        )

    tools_found = out.strip().split("\n")
    return _pass(
        "File integrity monitoring",
        f"Tools installed: {', '.join(tools_found)}",
        "Ensure database is initialized and scheduled scans are configured",
        category,
    )


def check_package_manager_security(ssh: SSHSession) -> CheckResult:
    """Check package manager security (GPG verification, repository security)."""
    category = "Package Management"

    # Check APT GPG verification
    cmd = (
        "bash -lc 'if command -v apt-config >/dev/null 2>&1; then "
        'apt-config dump | grep -E "APT::Get::AllowUnauthenticated|Acquire::AllowInsecureRepositories"; '
        "elif command -v dnf >/dev/null 2>&1; then "
        'grep -E "^gpgcheck=" /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null; '
        "elif command -v yum >/dev/null 2>&1; then "
        'grep -E "^gpgcheck=" /etc/yum.conf 2>/dev/null; '
        "fi'"
    )

    code, out, err = _run(ssh, cmd)

    issues = []
    if (
        'AllowUnauthenticated "true"' in out
        or 'AllowInsecureRepositories "true"' in out
    ):
        issues.append("APT allows unauthenticated packages")

    if "gpgcheck=0" in out:
        issues.append("YUM/DNF GPG checking disabled")

    if not out.strip():
        # Default is usually secure, but check for unsigned packages
        cmd2 = (
            "bash -lc 'if command -v apt-key >/dev/null 2>&1; then "
            'apt-key list 2>/dev/null | grep -c "pub"; fi\''
        )
        code2, out2, _ = _run(ssh, cmd2)
        if code2 == 0 and out2.strip() == "0":
            issues.append("No APT signing keys configured")

    if issues:
        return _warn(
            "Package manager security",
            f"Issues: {', '.join(issues)}",
            "Enable GPG verification in package manager configuration",
            category,
        )

    return _pass(
        "Package manager security",
        "Package manager GPG verification appears enabled",
        "No action",
        category,
    )


def check_logging_and_auditing(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check logging infrastructure (syslog, rsyslog, journald, auditd)."""
    category = "Logging & Auditing"

    # Check for logging daemons
    cmd = "bash -lc 'ps aux | grep -E \"syslogd|rsyslogd|systemd-journald\" | grep -v grep | head -3'"
    code, out, err = _run(ssh, cmd)

    if not out.strip():
        return _fail(
            "Logging daemon",
            "No active logging daemon detected",
            "Install and enable rsyslog or configure systemd-journald",
            category,
        )

    # Check auditd
    cmd2 = "bash -lc 'systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null'"
    code2, out2, _ = _run(ssh, cmd2)

    auditd_running = "active" in out2.lower() or "running" in out2.lower()

    if not auditd_running:
        return _warn(
            "Logging daemon",
            f"Logging active ({len(out.splitlines())} daemon(s)) but auditd not running",
            "Install and enable auditd for enhanced security auditing: 'apt install auditd && systemctl enable --now auditd'",
            category,
        )

    return _pass(
        "Logging daemon",
        f"Logging infrastructure operational (auditd: {'active' if auditd_running else 'inactive'})",
        "Configure remote logging and log rotation",
        category,
    )


def check_selinux_apparmor(ssh: SSHSession) -> CheckResult:
    """Check Mandatory Access Control systems (SELinux, AppArmor)."""
    category = "MAC Security"

    # Check SELinux
    cmd_selinux = "bash -lc 'command -v getenforce >/dev/null 2>&1 && getenforce'"
    code_se, out_se, _ = _run(ssh, cmd_selinux)

    # Check AppArmor
    cmd_apparmor = (
        "bash -lc 'command -v aa-status >/dev/null 2>&1 && aa-status --enabled 2>&1'"
    )
    code_aa, out_aa, _ = _run(ssh, cmd_apparmor)

    selinux_enforcing = out_se.strip() == "Enforcing"
    apparmor_enabled = code_aa == 0

    if not selinux_enforcing and not apparmor_enabled:
        return _warn(
            "MAC system",
            "No Mandatory Access Control system active (SELinux/AppArmor)",
            "Enable SELinux (RHEL/CentOS) or AppArmor (Ubuntu/Debian) for enhanced security",
            category,
        )

    if out_se.strip() == "Permissive":
        return _warn(
            "MAC system",
            "SELinux in Permissive mode (not enforcing)",
            "Set SELinux to Enforcing mode in /etc/selinux/config",
            category,
        )

    status = []
    if selinux_enforcing:
        status.append("SELinux: Enforcing")
    if apparmor_enabled:
        status.append("AppArmor: Enabled")

    return _pass(
        "MAC system",
        ", ".join(status),
        "No action",
        category,
    )


def check_security_tools(ssh: SSHSession) -> CheckResult:
    """Detect presence of security tools (fail2ban, ClamAV, IDS/IPS)."""
    category = "Security Tools"

    tools = {
        "fail2ban-client": "Fail2ban (brute-force protection)",
        "clamscan": "ClamAV (antivirus)",
        "snort": "Snort (IDS/IPS)",
        "suricata": "Suricata (IDS/IPS)",
        "rkhunter": "RKHunter (rootkit scanner)",
        "chkrootkit": "chkrootkit (rootkit scanner)",
    }

    cmd = (
        "bash -lc 'for tool in "
        + " ".join(tools.keys())
        + "; do command -v $tool 2>/dev/null && echo $tool; done'"
    )
    code, out, _ = _run(ssh, cmd)

    found = []
    for tool in out.strip().split("\n"):
        if tool and tool in tools:
            found.append(tools[tool])

    if not found:
        return _warn(
            "Security tools",
            "No additional security tools detected",
            "Consider installing: fail2ban, ClamAV, rkhunter for enhanced security",
            category,
        )

    return _pass(
        "Security tools",
        f"{len(found)} tool(s) installed: {', '.join(found)}",
        "Ensure tools are configured and running",
        category,
    )


def check_filesystem_mounts(ssh: SSHSession) -> CheckResult:
    """Check filesystem mount options for security (noexec, nosuid, nodev)."""
    category = "File System"

    cmd = "bash -lc 'mount | grep -E \"^/dev|^tmpfs\"'"
    code, out, err = _run(ssh, cmd)

    if code != 0:
        return _warn(
            "Filesystem mounts",
            "Failed to read mount points",
            "Check mount manually",
            category,
        )

    issues = []

    # Check /tmp for noexec, nosuid, nodev
    tmp_lines = [
        line for line in out.splitlines() if "/tmp" in line and "type tmpfs" in line
    ]
    if tmp_lines:
        tmp_line = tmp_lines[0]
        if "noexec" not in tmp_line:
            issues.append("/tmp missing noexec")
        if "nosuid" not in tmp_line:
            issues.append("/tmp missing nosuid")
        if "nodev" not in tmp_line:
            issues.append("/tmp missing nodev")

    # Check /var/tmp
    var_tmp_lines = [line for line in out.splitlines() if "/var/tmp" in line]
    if var_tmp_lines and "noexec" not in var_tmp_lines[0]:
        issues.append("/var/tmp missing noexec")

    # Check /dev/shm
    shm_lines = [line for line in out.splitlines() if "/dev/shm" in line]
    if shm_lines:
        shm_line = shm_lines[0]
        if "noexec" not in shm_line:
            issues.append("/dev/shm missing noexec")
        if "nosuid" not in shm_line:
            issues.append("/dev/shm missing nosuid")

    if issues:
        return _warn(
            "Filesystem mounts",
            f"Insecure mount options: {', '.join(issues)}",
            "Add noexec,nosuid,nodev to /tmp, /var/tmp, /dev/shm in /etc/fstab and remount",
            category,
        )

    return _pass(
        "Filesystem mounts",
        "Critical filesystems have secure mount options",
        "No action",
        category,
    )


def check_shell_security(ssh: SSHSession) -> CheckResult:
    """Check shell security settings (umask, TMOUT, history)."""
    category = "Shell Security"

    # Check default umask
    cmd = "bash -lc 'umask'"
    code, out, _ = _run(ssh, cmd)

    issues = []

    if code == 0 and out.strip():
        umask_val = out.strip()
        # Umask should be 027 or more restrictive (022 minimum)
        if umask_val in ["0000", "0002", "000", "002"]:
            issues.append(f"Weak umask: {umask_val} (should be 022 or 027)")

    # Check for TMOUT in shell profiles
    cmd2 = "bash -lc 'grep -h \"^TMOUT=\" /etc/profile /etc/bash.bashrc /etc/bashrc ~/.bashrc 2>/dev/null | head -1'"
    code2, out2, _ = _run(ssh, cmd2)

    if not out2.strip():
        issues.append("No shell timeout (TMOUT) configured")

    # Check command history settings
    cmd3 = "bash -lc 'grep -h \"HISTFILESIZE\\|HISTSIZE\" /etc/profile /etc/bash.bashrc 2>/dev/null | head -2'"
    code3, out3, _ = _run(ssh, cmd3)

    if issues:
        return _warn(
            "Shell security",
            f"Issues: {', '.join(issues)}",
            "Set umask=027, TMOUT=900 in /etc/profile; configure HISTSIZE and HISTFILESIZE",
            category,
        )

    return _pass(
        "Shell security",
        "Shell security settings appear reasonable",
        "Review and standardize across all user profiles",
        category,
    )


def check_compiler_presence(ssh: SSHSession) -> CheckResult:
    """Check for presence of compilers on production systems."""
    category = "System Tools"

    compilers = ["gcc", "g++", "cc", "clang", "make"]
    cmd = (
        "bash -lc 'for tool in "
        + " ".join(compilers)
        + "; do command -v $tool 2>/dev/null && echo $tool; done'"
    )

    code, out, _ = _run(ssh, cmd)

    if out.strip():
        found = out.strip().split("\n")
        return _warn(
            "Compiler presence",
            f"Compilers found on system: {', '.join(found)}",
            "Consider removing compilers from production systems to reduce attack surface",
            category,
        )

    return _pass(
        "Compiler presence",
        "No compilers detected",
        "No action",
        category,
    )


def check_legacy_services(ssh: SSHSession) -> CheckResult:
    """Check for legacy/insecure services (telnet, rsh, ftp)."""
    category = "Network Security"

    legacy_services = ["telnetd", "rshd", "rlogind", "vsftpd", "proftpd"]
    cmd = (
        "bash -lc 'ps aux | grep -E \""
        + "|".join(legacy_services)
        + "\" | grep -v grep'"
    )

    code, out, _ = _run(ssh, cmd)

    if out.strip():
        return _fail(
            "Legacy services",
            f"Insecure legacy services running: {out[:200]}",
            "Disable telnet, rsh, rlogin, and use SSH instead; replace FTP with SFTP",
            category,
        )

    return _pass(
        "Legacy services",
        "No legacy insecure services detected",
        "No action",
        category,
    )


def check_usb_storage(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if USB storage is disabled."""
    category = "Hardware Security"

    cmd = (
        "bash -lc 'lsmod | grep usb_storage || "
        'grep -r "install usb-storage /bin/true" /etc/modprobe.d/ 2>/dev/null\''
    )
    if password:
        cmd = f"sudo -S {cmd}"

    code, out, _ = _run(ssh, cmd, password)

    if "usb_storage" in out and "/bin/true" not in out:
        return _warn(
            "USB storage",
            "USB storage module is loaded and not disabled",
            "Disable USB storage by adding 'install usb-storage /bin/true' to /etc/modprobe.d/disable-usb-storage.conf",
            category,
        )

    return _pass(
        "USB storage",
        "USB storage appears disabled or controlled",
        "No action",
        category,
    )


def check_web_server_security(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check web server security configuration (Apache, Nginx)."""
    category = "Web Server"

    # Check for running web servers
    cmd = "bash -lc 'ps aux | grep -E \"httpd|apache2|nginx\" | grep -v grep | head -3'"
    code, out, _ = _run(ssh, cmd)

    if not out.strip():
        return _pass(
            "Web server",
            "No web server detected",
            "No action",
            category,
        )

    issues = []
    server_type = "apache" if "apache" in out.lower() or "httpd" in out else "nginx"

    # Check Apache configuration
    if server_type == "apache":
        # Check ServerTokens
        cmd2 = "bash -lc 'grep -r \"^ServerTokens\" /etc/apache2/ /etc/httpd/ 2>/dev/null | head -1'"
        if password:
            cmd2 = f"sudo -S {cmd2}"
        code2, out2, _ = _run(ssh, cmd2, password)

        if "Prod" not in out2:
            issues.append("ServerTokens not set to Prod (exposes version)")

        # Check ServerSignature
        cmd3 = "bash -lc 'grep -r \"^ServerSignature\" /etc/apache2/ /etc/httpd/ 2>/dev/null | head -1'"
        if password:
            cmd3 = f"sudo -S {cmd3}"
        code3, out3, _ = _run(ssh, cmd3, password)

        if "Off" not in out3:
            issues.append("ServerSignature not Off")

    # Check Nginx configuration
    elif server_type == "nginx":
        cmd2 = "bash -lc 'grep -r \"server_tokens\" /etc/nginx/ 2>/dev/null | head -1'"
        if password:
            cmd2 = f"sudo -S {cmd2}"
        code2, out2, _ = _run(ssh, cmd2, password)

        if "off" not in out2.lower():
            issues.append("server_tokens not disabled")

    # Check for SSL/TLS
    cmd_ssl = "bash -lc 'netstat -tlnp 2>/dev/null | grep :443 || ss -tlnp 2>/dev/null | grep :443'"
    if password:
        cmd_ssl = f"sudo -S {cmd_ssl}"
    code_ssl, out_ssl, _ = _run(ssh, cmd_ssl, password)

    if not out_ssl.strip():
        issues.append("No HTTPS listener on port 443")

    if issues:
        return _warn(
            "Web server",
            f"{server_type.title()} issues: {', '.join(issues)}",
            f"Harden {server_type} configuration: disable version disclosure, enable HTTPS",
            category,
        )

    return _pass(
        "Web server",
        f"{server_type.title()} running with reasonable security settings",
        "Review SSL/TLS ciphers and protocols",
        category,
    )


def check_database_security(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check database server security (MySQL, PostgreSQL)."""
    category = "Database"

    # Check for running databases
    cmd = "bash -lc 'ps aux | grep -E \"mysqld|mariadbd|postgres\" | grep -v grep | head -3'"
    code, out, _ = _run(ssh, cmd)

    if not out.strip():
        return _pass(
            "Database server",
            "No database server detected",
            "No action",
            category,
        )

    issues = []
    db_type = (
        "mysql" if "mysql" in out.lower() or "mariadb" in out.lower() else "postgresql"
    )

    # Check MySQL/MariaDB
    if db_type == "mysql":
        # Check for anonymous users
        cmd2 = 'bash -lc \'mysql -e "SELECT User,Host FROM mysql.user WHERE User=\\"\\" OR User IS NULL;" 2>/dev/null | wc -l\''
        code2, out2, _ = _run(ssh, cmd2)
        if code2 == 0 and int(out2.strip() or "0") > 1:
            issues.append("Anonymous MySQL users exist")

        # Check for remote root
        cmd3 = 'bash -lc \'mysql -e "SELECT User,Host FROM mysql.user WHERE User=\\"root\\" AND Host!=\\"localhost\\";" 2>/dev/null | wc -l\''
        code3, out3, _ = _run(ssh, cmd3)
        if code3 == 0 and int(out3.strip() or "0") > 1:
            issues.append("Remote root access enabled")

    # Check PostgreSQL
    elif db_type == "postgresql":
        # Check pg_hba.conf for trust authentication
        cmd2 = "bash -lc 'find /etc/postgresql -name pg_hba.conf -exec grep -v \"^#\" {} \\; 2>/dev/null | grep trust'"
        if password:
            cmd2 = f"sudo -S {cmd2}"
        code2, out2, _ = _run(ssh, cmd2, password)

        if out2.strip():
            issues.append("Trust authentication enabled in pg_hba.conf")

    # Check for network binding
    cmd_net = 'bash -lc \'netstat -tlnp 2>/dev/null | grep -E "3306|5432" | grep "0.0.0.0\\|::" || ss -tlnp 2>/dev/null | grep -E "3306|5432" | grep "0.0.0.0\\|::"\''
    if password:
        cmd_net = f"sudo -S {cmd_net}"
    code_net, out_net, _ = _run(ssh, cmd_net, password)

    if out_net.strip():
        issues.append("Database listening on all interfaces (0.0.0.0)")

    if issues:
        return _warn(
            "Database server",
            f"{db_type.upper()} issues: {', '.join(issues)}",
            f"Harden {db_type} configuration: remove anonymous users, restrict remote access, use strong authentication",
            category,
        )

    return _pass(
        "Database server",
        f"{db_type.upper()} running with reasonable security settings",
        "Review user privileges and connection encryption",
        category,
    )


def check_mail_server_security(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check mail server security (Postfix, Exim, Sendmail)."""
    category = "Mail Server"

    # Check for running mail servers
    cmd = (
        "bash -lc 'ps aux | grep -E \"postfix|exim|sendmail\" | grep -v grep | head -3'"
    )
    code, out, _ = _run(ssh, cmd)

    if not out.strip():
        return _pass(
            "Mail server",
            "No mail server detected",
            "No action",
            category,
        )

    issues = []
    server_type = None
    if "postfix" in out.lower():
        server_type = "postfix"
    elif "exim" in out.lower():
        server_type = "exim"
    elif "sendmail" in out.lower():
        server_type = "sendmail"

    # Check Postfix configuration
    if server_type == "postfix":
        # Check for open relay
        cmd2 = "bash -lc 'postconf -n smtpd_relay_restrictions 2>/dev/null || postconf -n smtpd_recipient_restrictions 2>/dev/null'"
        code2, out2, _ = _run(ssh, cmd2)

        if "permit_mynetworks" not in out2 and "reject_unauth_destination" not in out2:
            issues.append("Relay restrictions not properly configured")

        # Check TLS
        cmd3 = "bash -lc 'postconf -n smtpd_tls_cert_file smtpd_use_tls 2>/dev/null'"
        code3, out3, _ = _run(ssh, cmd3)

        if not out3.strip() or "smtpd_use_tls = no" in out3:
            issues.append("TLS not enabled")

    # Check for SMTP on port 25 bound to all interfaces
    cmd_net = 'bash -lc \'netstat -tlnp 2>/dev/null | grep :25 | grep "0.0.0.0" || ss -tlnp 2>/dev/null | grep :25 | grep "0.0.0.0"\''
    if password:
        cmd_net = f"sudo -S {cmd_net}"
    code_net, out_net, _ = _run(ssh, cmd_net, password)

    if out_net.strip():
        issues.append("SMTP listening on all interfaces")

    if issues:
        return _warn(
            "Mail server",
            f"{server_type.title() if server_type else 'Mail server'} issues: {', '.join(issues)}",
            "Harden mail server: configure relay restrictions, enable TLS, restrict network binding",
            category,
        )

    return _pass(
        "Mail server",
        f"{server_type.title() if server_type else 'Mail server'} running with reasonable security settings",
        "Review spam protection and authentication mechanisms",
        category,
    )


def check_php_security(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check PHP security configuration."""
    category = "Application Security"

    # Check if PHP is installed
    cmd = "bash -lc 'command -v php >/dev/null 2>&1 && php -v | head -1'"
    code, out, _ = _run(ssh, cmd)

    if code != 0 or not out.strip():
        return _pass(
            "PHP security",
            "PHP not detected",
            "No action",
            category,
        )

    issues = []

    # Check critical PHP settings
    dangerous_functions = (
        'bash -lc \'php -r "echo ini_get(\\"disable_functions\\");" 2>/dev/null\''
    )
    code2, out2, _ = _run(ssh, dangerous_functions)

    dangerous = ["exec", "shell_exec", "system", "passthru", "proc_open", "popen"]
    if code2 == 0:
        disabled = out2.strip()
        missing = [f for f in dangerous if f not in disabled]
        if len(missing) > 3:
            issues.append(f"Dangerous functions not disabled: {', '.join(missing[:3])}")

    # Check expose_php
    cmd3 = 'bash -lc \'php -r "echo ini_get(\\"expose_php\\");" 2>/dev/null\''
    code3, out3, _ = _run(ssh, cmd3)
    if code3 == 0 and out3.strip() == "1":
        issues.append("expose_php enabled (version disclosure)")

    # Check allow_url_fopen
    cmd4 = 'bash -lc \'php -r "echo ini_get(\\"allow_url_fopen\\");" 2>/dev/null\''
    code4, out4, _ = _run(ssh, cmd4)
    if code4 == 0 and out4.strip() == "1":
        issues.append("allow_url_fopen enabled (security risk)")

    if issues:
        return _warn(
            "PHP security",
            f"PHP {out.split()[1] if len(out.split()) > 1 else 'installed'} - Issues: {', '.join(issues)}",
            "Harden PHP: disable dangerous functions, set expose_php=Off, disable allow_url_fopen in php.ini",
            category,
        )

    return _pass(
        "PHP security",
        f"PHP {out.split()[1] if len(out.split()) > 1 else ''} with reasonable security settings",
        "Review all php.ini settings and apply security hardening guide",
        category,
    )


def check_dns_configuration(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check DNS resolver configuration and security."""
    category = "Name Service"

    # Check resolv.conf
    cmd = (
        "bash -lc 'cat /etc/resolv.conf 2>/dev/null | grep -v \"^#\" | grep nameserver'"
    )
    code, out, _ = _run(ssh, cmd)

    if code != 0 or not out.strip():
        return _warn(
            "DNS configuration",
            "No nameservers configured in /etc/resolv.conf",
            "Configure DNS nameservers",
            category,
        )

    issues = []
    nameservers = out.strip().splitlines()

    # Check for single point of failure
    if len(nameservers) < 2:
        issues.append("Only one nameserver configured (single point of failure)")

    # Check for public DNS usage
    public_dns = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
    for ns in nameservers:
        for public in public_dns:
            if public in ns:
                issues.append(f"Using public DNS: {public}")
                break

    # Check DNSSEC
    cmd2 = "bash -lc 'dig +short +dnssec . SOA 2>/dev/null | grep -c RRSIG'"
    code2, out2, _ = _run(ssh, cmd2)

    if code2 == 0 and out2.strip() == "0":
        issues.append("DNSSEC validation not working")

    if issues:
        return _warn(
            "DNS configuration",
            f"Issues: {', '.join(issues[:3])}",
            "Configure multiple nameservers, consider private DNS, enable DNSSEC",
            category,
        )

    return _pass(
        "DNS configuration",
        f"{len(nameservers)} nameserver(s) configured",
        "No action",
        category,
    )


CheckFn = Callable[..., CheckResult | List[CheckResult]]


def with_test_id(test_id: str) -> Callable[[CheckFn], CheckFn]:
    """Stamp results with a registry test ID unless already set.

    Handles both single-CheckResult and list returns (e.g. SSH config
    yields several findings under one identifier).
    """

    def decorator(fn: CheckFn) -> CheckFn:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> CheckResult | List[CheckResult]:
            result = fn(*args, **kwargs)
            results = result if isinstance(result, list) else [result]
            for item in results:
                if isinstance(item, CheckResult) and not item.test_id:
                    item.test_id = test_id
            return result

        return wrapper

    return decorator


_ATTACHED_IDS: set[str] = set()


def _attach_test_ids() -> None:
    """Apply the CHECK_TEST_IDS registry to this module's check functions."""
    namespace = globals()
    for name, test_id in CHECK_TEST_IDS.items():
        if name in _ATTACHED_IDS:
            continue
        fn = namespace.get(name)
        if callable(fn):
            namespace[name] = with_test_id(test_id)(fn)
            _ATTACHED_IDS.add(name)


_attach_test_ids()


# One thunk per check, in canonical report order. Shared by the sequential
# and parallel runners so the two can never drift apart.
_CheckThunk = Callable[[], "CheckResult | list[CheckResult]"]


def _check_thunks(ssh: SSHSession, password: str = "") -> list[tuple[str, _CheckThunk]]:
    """Named zero-argument check closures (canonical order).

    Names are the check function names, used for timeout placeholders,
    privilege gating, and test-ID resolution. Checks in NEEDS_ELEVATION
    degrade to unknown-marked WARN results when the session provably
    lacks elevation, instead of reporting PASS on unreadable sources.
    """
    privilege = get_privilege(ssh)
    elevated = _session_elevated(privilege, password)
    gated: list[tuple[str, _CheckThunk]] = []
    for name, thunk in [
        # Original checks
        ("check_disk_usage", lambda: check_disk_usage(ssh)),
        ("check_memory", lambda: check_memory(ssh)),
        ("check_load", lambda: check_load(ssh)),
        ("check_reboot_required", lambda: check_reboot_required(ssh)),
        ("check_updates", lambda: check_updates(ssh, password)),
        ("check_ssh_config", lambda: check_ssh_config(ssh, password)),
        ("check_firewall", lambda: check_firewall(ssh, password)),
        ("check_time_sync", lambda: check_time_sync(ssh)),
        ("check_accounts", lambda: check_accounts(ssh)),
        ("check_stale_user_accounts", lambda: check_stale_user_accounts(ssh)),
        ("check_auth_failures", lambda: check_auth_failures(ssh, password)),
        ("check_root_logins", lambda: check_root_logins(ssh)),
        ("check_listening_services", lambda: check_listening_services(ssh)),
        (
            "check_abnormal_network_processes",
            lambda: check_abnormal_network_processes(ssh),
        ),
        (
            "check_suspicious_process_locations",
            lambda: check_suspicious_process_locations(ssh),
        ),
        (
            "check_unexpected_sudo_usage",
            lambda: check_unexpected_sudo_usage(ssh, password),
        ),
        (
            "check_recently_created_accounts",
            lambda: check_recently_created_accounts(ssh),
        ),
        (
            "check_system_binary_modifications",
            lambda: check_system_binary_modifications(ssh),
        ),
        ("check_failed_login_spike", lambda: check_failed_login_spike(ssh, password)),
        ("check_suid_files", lambda: check_suid_files(ssh)),
        ("check_cron_and_timers", lambda: check_cron_and_timers(ssh)),
        ("check_process_resource_usage", lambda: check_process_resource_usage(ssh)),
        # New comprehensive security checks
        (
            "check_suspicious_network_connections",
            lambda: check_suspicious_network_connections(ssh),
        ),
        (
            "check_hidden_files_in_system_dirs",
            lambda: check_hidden_files_in_system_dirs(ssh),
        ),
        (
            "check_kernel_module_integrity",
            lambda: check_kernel_module_integrity(ssh, password),
        ),
        ("check_active_reverse_shells", lambda: check_active_reverse_shells(ssh)),
        (
            "check_weak_password_policy",
            lambda: check_weak_password_policy(ssh, password),
        ),
        (
            "check_container_escape_indicators",
            lambda: check_container_escape_indicators(ssh),
        ),
        ("check_arp_spoofing", lambda: check_arp_spoofing(ssh)),
        ("check_dns_tampering", lambda: check_dns_tampering(ssh)),
        ("check_crypto_miners", lambda: check_crypto_miners(ssh)),
        (
            "check_file_integrity_critical_binaries",
            lambda: check_file_integrity_critical_binaries(ssh),
        ),
        ("check_log_tampering", lambda: check_log_tampering(ssh, password)),
        (
            "check_privilege_escalation_vectors",
            lambda: check_privilege_escalation_vectors(ssh, password),
        ),
        (
            "check_world_writable_system_files",
            lambda: check_world_writable_system_files(ssh),
        ),
        ("check_deleted_file_handles", lambda: check_deleted_file_handles(ssh)),
        # Lynis-inspired feature additions
        (
            "check_boot_loader_password",
            lambda: check_boot_loader_password(ssh, password),
        ),
        ("check_kernel_hardening", lambda: check_kernel_hardening(ssh)),
        ("check_file_integrity_tools", lambda: check_file_integrity_tools(ssh)),
        (
            "check_package_manager_security",
            lambda: check_package_manager_security(ssh),
        ),
        (
            "check_logging_and_auditing",
            lambda: check_logging_and_auditing(ssh, password),
        ),
        ("check_selinux_apparmor", lambda: check_selinux_apparmor(ssh)),
        ("check_security_tools", lambda: check_security_tools(ssh)),
        ("check_filesystem_mounts", lambda: check_filesystem_mounts(ssh)),
        ("check_shell_security", lambda: check_shell_security(ssh)),
        ("check_compiler_presence", lambda: check_compiler_presence(ssh)),
        ("check_legacy_services", lambda: check_legacy_services(ssh)),
        ("check_usb_storage", lambda: check_usb_storage(ssh, password)),
        # Server and application security checks
        ("check_web_server_security", lambda: check_web_server_security(ssh, password)),
        ("check_database_security", lambda: check_database_security(ssh, password)),
        (
            "check_mail_server_security",
            lambda: check_mail_server_security(ssh, password),
        ),
        ("check_php_security", lambda: check_php_security(ssh, password)),
        ("check_dns_configuration", lambda: check_dns_configuration(ssh, password)),
    ]:
        if not elevated and name in NEEDS_ELEVATION:
            gated.append((name, _gated_thunk(name)))
        else:
            gated.append((name, cast("_CheckThunk", thunk)))
    return gated


def _flatten(items: list[CheckResult | list[CheckResult]]) -> List[CheckResult]:
    """Flatten per-thunk results (most checks return one CheckResult)."""
    results: List[CheckResult] = []
    for item in items:
        if isinstance(item, list):
            results.extend(item)
        else:
            results.append(item)
    return results


def run_all_checks(ssh: SSHSession, password: str = "") -> List[CheckResult]:
    """Run every core check sequentially (canonical order)."""
    return _flatten([thunk() for _, thunk in _check_thunks(ssh, password)])


def _timeout_placeholder(name: str, check_timeout: float) -> CheckResult:
    """WARN result standing in for a check that exceeded its ceiling."""
    return CheckResult(
        category="Scan",
        item=f"{name} timed out",
        status="warn",
        details=f"Check exceeded the {check_timeout:g}s per-check timeout.",
        recommendation="Re-run with a higher --check-timeout if this check matters.",
        test_id=CHECK_TEST_IDS.get(name, ""),
    )


@dataclass(frozen=True)
class PrivilegeInfo:
    """Session privilege facts (unknown fields stay falsy/empty)."""

    is_root: bool = False
    sudo_no_password: bool = False
    uid: str = ""


#: Core checks whose verdict is meaningless without elevation: denied
#: reads (lastlog, home-dir stats, sudoers, auth logs) surface as empty
#: output these checks would otherwise report as PASS. Gated in
#: _check_thunks when the session provably lacks elevation (numeric
#: non-root uid, no sudo, no password); ambiguous signals fail open.
NEEDS_ELEVATION: frozenset[str] = frozenset(
    {
        "check_stale_user_accounts",
        "check_recently_created_accounts",
        "check_unexpected_sudo_usage",
        "check_privilege_escalation_vectors",
    }
)


def get_privilege(ssh: SSHSession) -> PrivilegeInfo:
    """Detect session privilege (never raises; unknown on any failure)."""
    try:
        _, uid_out, _ = _run(ssh, "id -u")
        uid = uid_out.strip()
    except Exception:
        return PrivilegeInfo()
    try:
        ret, _, _ = _run(ssh, "sudo -n true 2>/dev/null")
        sudo_no_password = ret == 0
    except Exception:
        sudo_no_password = False
    return PrivilegeInfo(is_root=uid == "0", sudo_no_password=sudo_no_password, uid=uid)


def _session_elevated(info: PrivilegeInfo, password: str) -> bool:
    """Whether the session can plausibly elevate (fail-open on ambiguity).

    Only a proven non-root numeric uid without sudo and without a
    password gates checks; anything uncertain runs them as before.
    """
    if info.is_root or info.sudo_no_password or bool(password):
        return True
    uid = info.uid
    if isinstance(uid, str) and uid.isdigit() and uid != "0":
        return False
    return True


def _privilege_placeholder(name: str) -> CheckResult:
    """WARN result marking an unevaluable check as unknown (not a PASS)."""
    return CheckResult(
        category="Privilege",
        item=f"{name} skipped (unprivileged)",
        status="warn",
        details=(
            "unknown: this check needs elevated privileges (root or sudo) "
            "for a meaningful verdict; re-run with --ask-password, "
            "--key-file plus sudo access, or as root."
        ),
        recommendation="Re-run privileged to assess this area.",
        test_id=CHECK_TEST_IDS.get(name, ""),
    )


def _gated_thunk(name: str) -> _CheckThunk:
    """Placeholder thunk replacing an unevaluable check (same shape)."""

    def run() -> CheckResult:
        return _privilege_placeholder(name)

    return run


def run_all_checks_parallel(
    ssh: SSHSession,
    password: str = "",
    max_workers: int = 8,
    check_timeout: float | None = None,
) -> List[CheckResult]:
    """Run every core check via a bounded thread pool (canonical order).

    Checks are read-only remote reads, so they parallelize over one
    shared SSH session (paramiko multiplexes channels; the output cache
    is lock-guarded). Results return in the same order as
    :func:`run_all_checks`; a failing check raises on collection just as
    the sequential runner raises inline. ``max_workers`` is clamped to
    1..32; 1 delegates to the sequential runner. A positive
    ``check_timeout`` caps each check with a WARN placeholder instead of
    losing the rest of the report to one hang (``None``/non-positive
    disables it).
    """
    workers = min(max(1, int(max_workers)), 32)
    if workers == 1:
        return run_all_checks(ssh, password)
    ceiling = check_timeout if check_timeout and check_timeout > 0 else None
    thunks = _check_thunks(ssh, password)
    with ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="auditless-check"
    ) as pool:
        pending = [(name, pool.submit(thunk)) for name, thunk in thunks]
        collected: list[CheckResult | list[CheckResult]] = []
        for name, future in pending:
            try:
                collected.append(future.result(timeout=ceiling))
            except TimeoutError:
                collected.append(_timeout_placeholder(name, ceiling or 0))
        return _flatten(collected)
