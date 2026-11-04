"""Command-line interface for Linux Health Security Scanner.

Provides argument parsing, SSH session management, and report orchestration
for security scanning of Linux systems over SSH.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .checks import (
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
    set_command_timeout,
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
from .ssh_client import SSHSession

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
    parser = argparse.ArgumentParser(description="Linux host health checker over SSH")
    parser.add_argument("hostname", help="Target host")
    parser.add_argument("username", help="SSH username")
    parser.add_argument(
        "password",
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
        "--enable-rootkit-scan",
        action="store_true",
        help="Enable rkhunter rootkit scan (if available on target)",
    )
    parser.add_argument(
        "--check-package-hygiene",
        action="store_true",
        help="Check for unused/orphaned packages and bloat",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute the security scan orchestration from CLI arguments.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:] if None)

    Returns:
        Exit code (0 for success, 1 for errors)
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    ports = parse_ports(args.scan_ports)

    password = args.password
    if args.ask_password or password == "-":
        password = getpass.getpass("SSH password: ")

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

    # Reset command cache for fresh scan results
    from .checks import reset_command_cache

    reset_command_cache()

    try:
        with SSHSession(
            hostname=args.hostname,
            username=args.username,
            password=password,
            port=args.port,
            timeout=args.timeout,
        ) as ssh:
            system_info = gather_system_info(ssh)
            check_results = run_all_checks(ssh, password)

            # Run new Phase 1 checks (Database & Audit)
            database_results = run_all_database_checks(ssh, password)
            audit_results = run_all_audit_checks(ssh, password)
            check_results.extend(database_results)
            check_results.extend(audit_results)

            # Run Phase 2 checks (Filesystem & NFS)
            filesystem_results = run_all_filesystem_checks(ssh, password)
            check_results.extend(filesystem_results)

            # Run Phase 2 checks (Extended Package Management)
            package_results = run_all_package_management_checks(ssh, password)
            check_results.extend(package_results)

            # Run Phase 3 checks (Container Security)
            container_results = run_all_container_checks(ssh, args.command_timeout)
            check_results.extend(container_results)

            # Run Phase 3 checks (Web Server Security)
            webserver_results = run_all_webserver_checks(ssh, password)
            check_results.extend(webserver_results)

            # Run Phase 3 checks (DNS Security)
            dns_results = run_all_dns_checks(ssh, password)
            check_results.extend(dns_results)

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
        sys.stdout.reconfigure(encoding="utf-8")
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
