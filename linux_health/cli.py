"""Command-line interface for Linux Health Security Scanner.

Provides argument parsing, SSH session management, and report orchestration
for security scanning of Linux systems over SSH.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
import warnings
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from .checks import (
    CheckResult,
    DetailedSecurityInfo,
    gather_available_updates,
    gather_critical_file_permissions,
    gather_disk_usage_dirs,
    gather_failed_ssh_logins,
    gather_failed_systemd_units,
    gather_firewall_rules,
    gather_rkhunter_scan,
    gather_root_logins,
    gather_sshd_config_check,
    gather_successful_ssh_logins,
    gather_sudoers_info,
    gather_suid_binaries,
    gather_system_info,
    gather_top_processes,
    gather_unused_packages,
    run_all_checks,
    run_all_checks_parallel,
    set_command_timeout,
    set_max_output_bytes,
)
from .checks_audit import run_all_audit_checks
from .checks_container import run_all_checks as run_all_container_checks
from .checks_database import run_all_database_checks
from .checks_dns import run_all_dns_checks
from .checks_filesystem import run_all_filesystem_checks
from .checks_packages import run_all_package_management_checks
from .checks_webserver import run_all_webserver_checks
from .report import render_report, render_report_json, render_report_text
from .scanner import COMMON_PORTS, scan_ports
from .ssh_client import SSHSession, pooled_session

try:
    from .config import load_profile, should_skip_test

    HAS_CONFIG = True
except ImportError:
    HAS_CONFIG = False


def parse_ports(raw: str | None) -> list[int]:
    """Parse comma-separated port list or return common ports.

    Args:
        raw: Comma-separated port string or None

    Returns:
        List of port integers, or COMMON_PORTS if empty

    Raises:
        argparse.ArgumentTypeError: If any port is not a valid integer
    """
    if not raw:
        return COMMON_PORTS
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ports.append(int(part))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid port: {part}") from exc
    return ports if ports else COMMON_PORTS


def build_parser() -> argparse.ArgumentParser:
    """Build and return argument parser for CLI.

    Returns:
        Configured argparse.ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog="auditless",
        description="Auditless — agentless Linux security assessment over SSH",
        epilog="Entry points: auditless (primary), linux-health (deprecated "
        "alias through v3.x), python -m linux_health. "
        "Docs: https://github.com/Greg-2600/auditless",
    )
    parser.add_argument("hostname", nargs="?", default=None, help="Target host")
    parser.add_argument("username", nargs="?", default=None, help="SSH username")
    parser.add_argument(
        "password",
        nargs="?",
        default=None,
        help="SSH password (prefer key auth in production; use '-' with --ask-password to prompt)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--scan-ports",
        dest="scan_ports",
        type=str,
        default=None,
        help="Comma-separated ports to scan; default uses common ports",
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="SSH connect timeout seconds"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Retry transient SSH failures with backoff (auth fails fast; 0 disables)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable the command-output cache for this scan (slower, always fresh)",
    )
    parser.add_argument(
        "--max-output-bytes",
        type=int,
        default=1048576,
        help="Cap retained bytes per remote command output (<=0 disables)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="Concurrent check workers per host (1=sequential, max 32)",
    )
    parser.add_argument(
        "--check-timeout",
        type=float,
        default=120.0,
        help="Per-check ceiling in seconds for the parallel runner "
        "(WARN placeholder on expiry; <=0 disables)",
    )
    parser.add_argument(
        "--deadline",
        type=float,
        default=0.0,
        help="Global scan deadline in seconds; renders a partial report "
        "with completed checks on expiry (0 disables)",
    )
    parser.add_argument(
        "--reuse-session",
        action="store_true",
        help="Reuse a healthy pooled SSH session across scans in this "
        "process (dashboard/scheduler); one-shot scans connect fresh",
    )
    parser.add_argument(
        "--command-timeout",
        type=float,
        default=60.0,
        help="Per-command SSH execution timeout seconds",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to write report; prints to stdout if omitted",
    )
    parser.add_argument(
        "--format",
        choices=["md", "text", "json"],
        default="text",
        help="Report format (md, text, or json)",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="Load scan profile from YAML file (allows test filtering)",
    )
    parser.add_argument(
        "--ask-password",
        action="store_true",
        help="Prompt for SSH password (ignores positional password if set)",
    )
    parser.add_argument(
        "--key-file",
        type=str,
        default=None,
        help="SSH private key file for key auth (password then only used for sudo)",
    )
    parser.add_argument(
        "--jump-host",
        type=str,
        default="",
        help="Bastion host to tunnel through (empty = direct connection)",
    )
    parser.add_argument("--jump-port", type=int, default=22, help="Bastion SSH port")
    parser.add_argument("--jump-user", type=str, default="", help="Bastion username")
    parser.add_argument(
        "--jump-password",
        type=str,
        default="",
        help="Bastion password (prefer key auth; use with --jump-key-file)",
    )
    parser.add_argument(
        "--jump-key-file", type=str, default="", help="Bastion private key file"
    )
    parser.add_argument(
        "--strict-host-key-checking",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Reject unknown SSH host keys instead of auto-adding them "
        "(MITM protection; requires pre-populated known_hosts; "
        "--no-strict-host-key-checking opts out for labs)",
    )
    parser.add_argument(
        "--enable-rootkit-scan",
        action="store_true",
        help="Enable rkhunter rootkit scan (if available on target)",
    )
    parser.add_argument(
        "--check-package-hygiene",
        action="store_true",
        help="Check for unused/orphaned packages and bloat",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Run the local web dashboard instead of a one-shot scan",
    )
    parser.add_argument(
        "--serve-host",
        type=str,
        default=os.environ.get("AUDITLESS_HOST", "127.0.0.1"),
        help="Dashboard bind address (env AUDITLESS_HOST; default: 127.0.0.1,"
        " keep loopback unless behind auth + TLS)",
    )
    parser.add_argument(
        "--serve-port",
        type=int,
        default=int(os.environ.get("AUDITLESS_PORT", "8080")),
        help="Dashboard port (env AUDITLESS_PORT; default: 8080)",
    )
    parser.add_argument(
        "--no-scheduler",
        action="store_true",
        help="Disable unattended scheduled scans while serving",
    )
    return parser


def _warn_if_deprecated_alias() -> None:
    """Note the linux-health entry-point deprecation (kept through v3.x)."""
    invoked = os.path.splitext(
        os.path.basename((sys.argv[0] or "").replace("\\", "/"))
    )[0]
    if invoked == "linux-health":
        message = (
            "The 'linux-health' command is deprecated, use 'auditless' "
            "instead (removal slated for v4.0)."
        )
        warnings.warn(message, DeprecationWarning, stacklevel=3)
        print(f"warning: {message}", file=sys.stderr)


def _preflight_sudo(ssh: SSHSession, password: str) -> bool:
    """Verify sudo works before the scan (no password prompts mid-scan).

    All remote sudo invocations use ``sudo -S`` with stdin, so nothing
    can block on a TTY prompt; this probe only decides whether a given
    password actually elevates. Inconclusive probes (odd sessions in
    tests) assume success so checks degrade exactly as before.
    """
    if not password:
        return True
    try:
        from .checks import _run

        ret, _, _ = _run(ssh, "sudo -S true 2>/dev/null", password=password)
        return ret == 0
    except Exception:
        return True


def _open_session(
    args: argparse.Namespace, password: str, gateway: dict | None
) -> AbstractContextManager[SSHSession]:
    """Open the scan session, pooled when --reuse-session is passed."""
    if args.reuse_session:
        return pooled_session(
            hostname=args.hostname,
            username=args.username,
            password=password,
            port=args.port,
            timeout=args.timeout,
            strict_host_key_checking=args.strict_host_key_checking,
            key_path=args.key_file,
            gateway=gateway,
            retries=args.retries,
        )
    return SSHSession(
        hostname=args.hostname,
        username=args.username,
        password=password,
        port=args.port,
        timeout=args.timeout,
        strict_host_key_checking=args.strict_host_key_checking,
        key_path=args.key_file,
        gateway=gateway,
        retries=args.retries,
    )


def main(argv: list[str] | None = None) -> int:
    """Execute the security scan orchestration from CLI arguments.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:] if None)

    Returns:
        Exit code (0 for success, 1 for errors)
    """
    _warn_if_deprecated_alias()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.serve:
        from .dashboard import serve_forever

        serve_forever(args.serve_host, args.serve_port, not args.no_scheduler)
        return 0

    if not args.hostname or not args.username:
        parser.error("hostname and username are required (or use --serve)")
    if args.password is None and not args.key_file:
        parser.error("password is required (or use --key-file / --serve)")
    ports = parse_ports(args.scan_ports)

    password = args.password or ""
    if args.ask_password or password == "-":
        password = getpass.getpass("SSH password: ")
    elif password or args.jump_password:
        print(
            "Warning: password passed on the command line is visible in "
            "process listings and shell history; prefer '--ask-password'.",
            file=sys.stderr,
        )

    # Load profile if specified
    profile = None
    if args.profile and HAS_CONFIG:
        try:
            profile = load_profile(args.profile)
            print(f"Loaded scan profile from {args.profile}")
        except (FileNotFoundError, ValueError) as e:
            print(f"Warning: Failed to load profile {args.profile}: {e}")

    # Apply per-command timeout for all SSH execs
    set_command_timeout(args.command_timeout)

    # Cap retained output bytes per command (fleet memory discipline)
    set_max_output_bytes(args.max_output_bytes)

    # Reset command cache for fresh scan results
    from .checks import (
        disable_command_cache,
        enable_command_cache,
        is_command_cache_enabled,
        reset_command_cache,
    )

    reset_command_cache()
    cache_was_enabled = is_command_cache_enabled()
    if args.no_cache:
        disable_command_cache()

    try:
        gateway = None
        if args.jump_host:
            gateway = {
                "hostname": args.jump_host,
                "port": args.jump_port,
                "username": args.jump_user,
                "password": args.jump_password,
                "key_path": args.jump_key_file or "",
            }
        with _open_session(args, password, gateway) as ssh:
            if password and not _preflight_sudo(ssh, password):
                parser.error(
                    f"sudo authentication failed for user '{args.username}': "
                    "wrong password or no sudo rights. Re-run with the "
                    "correct password (--ask-password), or omit the password "
                    "for an unprivileged assessment."
                )
            system_info = gather_system_info(ssh)
            scan_start = time.monotonic()
            deadline = args.deadline if args.deadline and args.deadline > 0 else None

            def _expired() -> bool:
                return (
                    deadline is not None and (time.monotonic() - scan_start) >= deadline
                )

            def _run_core() -> list[CheckResult]:
                if args.jobs > 1:
                    return run_all_checks_parallel(
                        ssh,
                        password,
                        max_workers=args.jobs,
                        check_timeout=args.check_timeout,
                    )
                return run_all_checks(ssh, password)

            suites: list[tuple[str, Callable[[], list[CheckResult]]]] = [
                ("core", _run_core),
                ("database", lambda: run_all_database_checks(ssh, password)),
                ("audit", lambda: run_all_audit_checks(ssh, password)),
                (
                    "filesystem",
                    lambda: run_all_filesystem_checks(ssh, password),
                ),
                (
                    "packages",
                    lambda: run_all_package_management_checks(ssh, password),
                ),
                (
                    "container",
                    lambda: run_all_container_checks(ssh, args.command_timeout),
                ),
                ("webserver", lambda: run_all_webserver_checks(ssh, password)),
                ("dns", lambda: run_all_dns_checks(ssh, password)),
            ]
            check_results: list[CheckResult] = []
            truncated = False
            completed: list[str] = []
            for label, run_suite in suites:
                if _expired():
                    truncated = True
                    break
                check_results.extend(run_suite())
                completed.append(label)
            if truncated:
                done = ", ".join(completed) if completed else "none"
                check_results.append(
                    CheckResult(
                        category="Scan",
                        item="Scan deadline exceeded",
                        status="warn",
                        details=(
                            "Partial report: the global scan deadline "
                            f"({deadline:g}s) expired; phases completed: "
                            f"{done}."
                        ),
                        recommendation=(
                            "Re-run with a higher --deadline, or narrower "
                            "scope via --profile/--scan-ports."
                        ),
                        test_id="",
                    )
                )

            if _expired():
                truncated = True
                detailed_security = None
            else:
                detailed_security = DetailedSecurityInfo(
                    suid_binaries=gather_suid_binaries(ssh),
                    root_logins=gather_root_logins(ssh),
                    successful_ssh_logins=gather_successful_ssh_logins(ssh, password),
                    failed_ssh_logins=gather_failed_ssh_logins(ssh, password),
                    top_processes=gather_top_processes(ssh),
                    disk_usage_dirs=gather_disk_usage_dirs(ssh, password),
                    available_updates=gather_available_updates(ssh, password),
                    firewall_rules=gather_firewall_rules(ssh, password),
                    sshd_config_check=gather_sshd_config_check(ssh, password),
                    failed_systemd_units=gather_failed_systemd_units(ssh),
                    sudoers_info=gather_sudoers_info(ssh, password),
                    critical_file_permissions=gather_critical_file_permissions(ssh),
                    rootkit_scan=(
                        gather_rkhunter_scan(ssh, password)
                        if args.enable_rootkit_scan
                        else None
                    ),
                    unused_packages=(
                        gather_unused_packages(ssh, password)
                        if args.check_package_hygiene
                        else None
                    ),
                )
    except Exception as exc:  # pylint: disable=broad-except
        parser.error(f"SSH failed: {exc}")
        return 2
    finally:
        if cache_was_enabled:
            enable_command_cache()

    port_results = scan_ports(args.hostname, ports)

    # Filter checks if profile provided
    if profile and HAS_CONFIG:
        check_results = [
            c
            for c in check_results
            if not should_skip_test(c.test_id, c.category, profile)
        ]

    if args.format == "text":
        report = render_report_text(
            system_info, check_results, port_results, detailed_security
        )
    elif args.format == "json":
        report = render_report_json(
            system_info, check_results, port_results, detailed_security
        )
    else:
        report = render_report(
            system_info, check_results, port_results, detailed_security
        )

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        # Print to stdout with UTF-8 encoding to handle Unicode characters on Windows
        stdout: Any = sys.stdout
        stdout.reconfigure(encoding="utf-8")
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
