"""Report rendering and formatting for security scan results.

Provides multiple output formats (text, markdown, JSON) for scan results,
including hardening index calculation and category-based organization.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from . import __version__
from .checks import CheckResult, DetailedSecurityInfo, SystemInfo
from .scanner import PortStatus

STATUS_ICON = {
    "pass": "✅",
    "warn": "⚠️",
    "fail": "❌",
}

STATUS_SYMBOL = {
    "pass": "[PASS]",
    "warn": "[WARN]",
    "fail": "[FAIL]",
}


def _status_icon(status: str) -> str:
    return STATUS_ICON.get(status, "⬜")


def _port_service_suffix(port: PortStatus) -> str:
    """Render ' (service version)' for identified open ports, else ''."""
    if not port.service and not port.version:
        return ""
    label = port.service or "unknown"
    if port.version:
        label += f" {port.version}"
    return f" ({label})"


def calculate_hardening_index(checks: Iterable[CheckResult]) -> dict[str, Any]:
    """Calculate Lynis-style hardening index (0-100) with breakdown."""
    checks_list = list(checks)

    if not checks_list:
        return {
            "overall_index": 0,
            "total_checks": 0,
            "passed": 0,
            "warned": 0,
            "failed": 0,
            "categories": {},
        }

    total = len(checks_list)
    passed = sum(1 for c in checks_list if c.status == "pass")
    warned = sum(1 for c in checks_list if c.status == "warn")
    failed = sum(1 for c in checks_list if c.status == "fail")

    # Calculate overall hardening index
    # Pass = 100% weight, Warn = 50% weight, Fail = 0% weight
    weighted_score = (passed * 100) + (warned * 50) + (failed * 0)
    max_score = total * 100
    overall_index = int((weighted_score / max_score * 100)) if max_score > 0 else 0

    # Calculate per-category breakdown
    categories: dict[str, dict] = {}
    for check in checks_list:
        cat = check.category
        if cat not in categories:
            categories[cat] = {"pass": 0, "warn": 0, "fail": 0, "total": 0}

        categories[cat]["total"] += 1
        if check.status == "pass":
            categories[cat]["pass"] += 1
        elif check.status == "warn":
            categories[cat]["warn"] += 1
        elif check.status == "fail":
            categories[cat]["fail"] += 1

    # Calculate index per category
    for cat, stats in categories.items():
        cat_weighted = (stats["pass"] * 100) + (stats["warn"] * 50)
        cat_max = stats["total"] * 100
        stats["index"] = int((cat_weighted / cat_max * 100)) if cat_max > 0 else 0

    return {
        "overall_index": overall_index,
        "total_checks": total,
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "categories": categories,
    }


def get_hardening_level(index: int) -> tuple[str, str]:
    """Get hardening level and color based on index score."""
    if index >= 90:
        return ("EXCELLENT", "🟢")
    if index >= 75:
        return ("GOOD", "🟡")
    if index >= 60:
        return ("FAIR", "🟠")
    if index >= 40:
        return ("POOR", "🔴")
    return ("CRITICAL", "🔴🔴")


def render_report_text(
    system: SystemInfo,
    checks: Iterable[CheckResult],
    ports: Iterable[PortStatus],
    detailed: DetailedSecurityInfo | None = None,
) -> str:
    """Render a clean text-based report."""
    checks_list = list(checks)

    ports_list = list(ports)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    total = len(checks_list)
    passed = sum(1 for c in checks_list if c.status == "pass")
    warned = sum(1 for c in checks_list if c.status == "warn")
    failed = sum(1 for c in checks_list if c.status == "fail")

    # Calculate hardening index
    hardening = calculate_hardening_index(checks_list)
    level, level_icon = get_hardening_level(hardening["overall_index"])

    sep = "=" * 80

    lines: list[str] = []
    lines.append(sep)
    lines.append(f"LINUX HOST HEALTH REPORT: {system.hostname.upper()}")
    lines.append(sep)
    lines.append(f"Generated: {ts}\n")

    lines.append("SYSTEM INFORMATION")
    lines.append("-" * 80)
    lines.append(f"  Hostname:      {system.hostname}")
    lines.append(f"  OS:            {system.os}")
    lines.append(f"  Kernel:        {system.kernel}")
    lines.append(f"  Uptime:        {system.uptime}")
    lines.append(f"  Logged-in:     {system.users}\n")

    lines.append("SUMMARY")
    lines.append("-" * 80)
    lines.append(f"  Total Checks:  {total}")
    lines.append(f"  ✅ Passed:     {passed}")
    lines.append(f"  ⚠️  Warnings:   {warned}")
    lines.append(f"  ❌ Failed:     {failed}")
    lines.append("")
    lines.append(
        f"  HARDENING INDEX: {hardening['overall_index']}/100 {level_icon} ({level})"
    )
    open_ports = [p.port for p in ports_list if p.open]
    ports_info = f"({', '.join(map(str, open_ports))})" if open_ports else "(none)"
    lines.append(f"  Open Ports:    {len(open_ports)} {ports_info}\n")

    # Add category breakdown
    lines.append("HARDENING BY CATEGORY")
    lines.append("-" * 80)
    # Sort categories by index (worst first)
    sorted_cats = sorted(hardening["categories"].items(), key=lambda x: x[1]["index"])
    for cat, stats in sorted_cats:
        _, cat_icon = get_hardening_level(stats["index"])
        lines.append(
            f"  {cat_icon} {stats['index']:3d}/100  {cat:<25} "
            f"(✅{stats['pass']} ⚠️{stats['warn']} ❌{stats['fail']})"
        )
    lines.append("")

    lines.append("HEALTH CHECKS")
    lines.append("-" * 80)
    # Sort by status: fail, warn, pass
    status_order = {"fail": 0, "warn": 1, "pass": 2}
    sorted_checks = sorted(
        checks_list, key=lambda c: status_order.get(c.status.lower(), 3)
    )
    for check in sorted_checks:
        status_sym = STATUS_SYMBOL.get(check.status, "????")
        lines.append(f"{status_sym} {check.item:<25} | {check.category}")
        lines.append(f"    Details: {check.details}")
        lines.append(f"    Action:  {check.recommendation}\n")

    lines.append("PORT SCAN RESULTS")
    lines.append("-" * 80)
    open_only = [p for p in ports_list if p.open]
    if not open_only:
        lines.append("  No open ports found (all scanned ports were closed/filtered)")
    else:
        for port in open_only:
            lines.append(
                f"  Port {port.port:5d}  OPEN      {port.reason or ''}"
                f"{_port_service_suffix(port)}"
            )
    lines.append("")

    if detailed:
        lines.append("DETAILED SECURITY FINDINGS")
        lines.append("-" * 80)

        lines.append("\nTOP PROCESSES BY CPU/MEMORY")
        lines.append("~" * 80)
        for line in detailed.top_processes.splitlines()[:20]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("DISK USAGE BY DIRECTORY")
        lines.append("~" * 80)
        for line in detailed.disk_usage_dirs.splitlines()[:20]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("AVAILABLE UPDATES")
        lines.append("~" * 80)
        lines.append(f"  {detailed.available_updates}")
        lines.append("")

        lines.append("FIREWALL RULES/STATUS")
        lines.append("~" * 80)
        for line in detailed.firewall_rules.splitlines()[:15]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("SSH DAEMON CONFIG CHECK")
        lines.append("~" * 80)
        for line in detailed.sshd_config_check.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("FAILED SYSTEMD UNITS")
        lines.append("~" * 80)
        for line in detailed.failed_systemd_units.splitlines()[:10]:
            lines.append(f"  {line}")
        if not detailed.failed_systemd_units.strip():
            lines.append("  No failed units")
        lines.append("")

        lines.append("SUDOERS CONFIGURATION")
        lines.append("~" * 80)
        for line in detailed.sudoers_info.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("CRITICAL FILE PERMISSIONS")
        lines.append("~" * 80)
        for line in detailed.critical_file_permissions.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        if detailed.rootkit_scan is not None:
            lines.append("RKHUNTER ROOTKIT SCAN")
            lines.append("~" * 80)
            for line in detailed.rootkit_scan.splitlines()[:30]:
                lines.append(f"  {line}")
            if len(detailed.rootkit_scan.splitlines()) > 30:
                lines.append(
                    f"  ... (showing first 30 of {len(detailed.rootkit_scan.splitlines())} lines)"
                )
            lines.append("")

        if detailed.unused_packages is not None:
            lines.append("PACKAGE HYGIENE")
            lines.append("~" * 80)
            for line in detailed.unused_packages.splitlines()[:30]:
                lines.append(f"  {line}")
            if len(detailed.unused_packages.splitlines()) > 30:
                lines.append(
                    f"  ... (showing first 30 of "
                    f"{len(detailed.unused_packages.splitlines())} lines)"
                )
            lines.append("")

        lines.append("SUID BINARIES (recent activity)")
        lines.append("~" * 80)
        for line in detailed.suid_binaries.splitlines()[:15]:
            lines.append(f"  {line}")
        if len(detailed.suid_binaries.splitlines()) > 15:
            lines.append(
                f"  ... and {len(detailed.suid_binaries.splitlines()) - 15} more"
            )
        lines.append("")

        lines.append("RECENT ROOT LOGINS")
        lines.append("~" * 80)
        for line in detailed.root_logins.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("SUCCESSFUL SSH LOGINS (last 7 days)")
        lines.append("~" * 80)
        for line in detailed.successful_ssh_logins.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("FAILED SSH LOGIN ATTEMPTS (last 7 days)")
        lines.append("~" * 80)
        for line in detailed.failed_ssh_logins.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("-" * 80)
    lines.append(
        "  • ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head     (inspect top processes)"
    )
    lines.append(
        "  • sudo du -xhd1 / | sort -h                        (disk usage by directory)"
    )
    lines.append(
        "  • sudo apt-get update && apt-get upgrade           (apply security updates)"
    )
    lines.append(
        "  • sudo ufw status verbose                          (review firewall rules)"
    )
    lines.append(
        "  • sudo sshd -T                                     (verify SSH config)"
    )
    lines.append("")

    lines.append(sep)
    lines.append("End of Report")
    lines.append(sep)

    return "\n".join(lines)


def render_report(
    system: SystemInfo,
    checks: Iterable[CheckResult],
    ports: Iterable[PortStatus],
    detailed: DetailedSecurityInfo | None = None,
) -> str:
    """Render comprehensive security report in multiple formats.

    Orchestrates rendering based on format selection, delegating to
    format-specific functions (text, markdown, JSON).

    Args:
        system: System information from target
        checks: Security check results
        ports: Port scan results
        detailed: Optional detailed security information

    Returns:
        Formatted report string
    """
    checks_list = list(checks)
    ports_list = list(ports)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    total = len(checks_list)
    passed = sum(1 for c in checks_list if c.status == "pass")
    warned = sum(1 for c in checks_list if c.status == "warn")
    failed = sum(1 for c in checks_list if c.status == "fail")

    # Calculate hardening index
    hardening = calculate_hardening_index(checks_list)
    level, level_icon = get_hardening_level(hardening["overall_index"])

    lines: list[str] = []
    lines.append(f"# Linux Host Health Report: {system.hostname}")
    lines.append("")
    lines.append(f"Generated: {ts}")
    lines.append("")
    lines.append("## System")
    lines.append(f"- Hostname: {system.hostname}")
    lines.append(f"- OS: {system.os}")
    lines.append(f"- Kernel: {system.kernel}")
    lines.append(f"- Uptime: {system.uptime}")
    lines.append(f"- Logged-in users: {system.users}")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- Checks: {total} (✅ {passed} / ⚠️ {warned} / ❌ {failed})")
    lines.append(
        f"- **Hardening Index: {hardening['overall_index']}/100** {level_icon} **({level})**"
    )
    open_ports = [p.port for p in ports_list if p.open]
    open_str = ", ".join(map(str, open_ports)) if open_ports else "none"
    lines.append(f"- Open ports (scanned): {len(open_ports)} -> {open_str}")
    lines.append("")

    # Add category breakdown
    lines.append("## Hardening by Category")
    lines.append("")
    lines.append("| Category | Index | Passed | Warned | Failed |")
    lines.append("| --- | --- | --- | --- | --- |")
    # Sort categories by index (worst first)
    sorted_cats = sorted(hardening["categories"].items(), key=lambda x: x[1]["index"])
    for cat, stats in sorted_cats:
        _, cat_icon = get_hardening_level(stats["index"])
        lines.append(
            f"| {cat} | {cat_icon} {stats['index']}/100 | "
            f"{stats['pass']} | {stats['warn']} | {stats['fail']} |"
        )
    lines.append("")

    lines.append("## Checklist")
    lines.append("| Status | Item | Details | Recommendation | Category |")
    lines.append("| --- | --- | --- | --- | --- |")
    # Sort by status: fail, warn, pass
    status_order = {"fail": 0, "warn": 1, "pass": 2}
    sorted_checks = sorted(
        checks_list, key=lambda c: status_order.get(c.status.lower(), 3)
    )
    for check in sorted_checks:
        icon = _status_icon(check.status)
        status = check.status.upper()
        lines.append(
            f"| {icon} {status} | {check.item} | {check.details} | "
            f"{check.recommendation} | {check.category} |"
        )
    lines.append("")

    lines.append("## Port Scan (lightweight)")
    lines.append("| Port | State | Notes |")
    lines.append("| --- | --- | --- |")
    open_only = [p for p in ports_list if p.open]
    if not open_only:
        msg = "No open ports found (all scanned ports were closed/filtered)"
        lines.append(f"| none | closed/filtered | {msg} |")
    else:
        for port in open_only:
            lines.append(
                f"| {port.port} | open | {port.reason or ''}{_port_service_suffix(port)} |"
            )
    lines.append("")

    if detailed:
        lines.append("## Detailed Security Findings")
        lines.append("")
        lines.append("### Top Processes by CPU/Memory")
        lines.append("```")
        lines.append(detailed.top_processes)
        lines.append("```")
        lines.append("")
        lines.append("### Disk Usage by Directory")
        lines.append("```")
        lines.append(detailed.disk_usage_dirs)
        lines.append("```")
        lines.append("")
        lines.append("### Available Updates")
        lines.append(detailed.available_updates)
        lines.append("")
        lines.append("### Firewall Rules/Status")
        lines.append("```")
        lines.append(detailed.firewall_rules)
        lines.append("```")
        lines.append("")
        lines.append("### SSH Daemon Configuration Check")
        lines.append("```")
        lines.append(detailed.sshd_config_check)
        lines.append("```")
        lines.append("")
        lines.append("### Failed Systemd Units")
        lines.append("```")
        lines.append(detailed.failed_systemd_units or "No failed units")
        lines.append("```")
        lines.append("")
        lines.append("### Sudoers Configuration")
        lines.append("```")
        lines.append(detailed.sudoers_info)
        lines.append("```")
        lines.append("")
        lines.append("### Critical File Permissions")
        lines.append("```")
        lines.append(detailed.critical_file_permissions)
        lines.append("```")
        lines.append("")
        if detailed.rootkit_scan is not None:
            lines.append("### Rkhunter Rootkit Scan")
            lines.append("```")
            lines.append(detailed.rootkit_scan)
            lines.append("```")
            lines.append("")
        if detailed.unused_packages is not None:
            lines.append("### Package Hygiene & Unused Packages")
            lines.append("```")
            lines.append(detailed.unused_packages)
            lines.append("```")
            lines.append("")
        lines.append("### SUID Binaries (recent activity)")
        lines.append("```")
        lines.append(detailed.suid_binaries)
        lines.append("```")
        lines.append("")
        lines.append("### Recent Root Logins")
        lines.append("```")
        lines.append(detailed.root_logins)
        lines.append("```")
        lines.append("")
        lines.append("### Recent Successful SSH Logins (last 7 days)")
        lines.append("```")
        lines.append(detailed.successful_ssh_logins)
        lines.append("```")
        lines.append("")
        lines.append("### Recent Failed SSH Login Attempts (last 7 days)")
        lines.append("```")
        lines.append(detailed.failed_ssh_logins)
        lines.append("```")
        lines.append("")

    lines.append("## Suggested Next Commands")
    lines.append(
        "- Inspect top CPU/mem: `ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head`"
    )
    lines.append("- Disk usage by dir: `sudo du -xhd1 / | sort -h`")
    lines.append(
        "- Pending updates (Debian/Ubuntu): `sudo apt-get update && sudo apt-get upgrade`"
    )
    lines.append("- Firewall (ufw): `sudo ufw status verbose`")
    lines.append(
        "- SSH hardening: edit `/etc/ssh/sshd_config` then `sudo systemctl reload sshd`"
    )
    lines.append("")
    notes = (
        "Notes: Port scan is TCP connect scan on provided/common ports; "
        "results may be filtered by firewalls."
    )
    lines.append(notes)
    return "\n".join(lines)


def render_report_json(
    system: SystemInfo,
    checks: Iterable[CheckResult],
    ports: Iterable[PortStatus],
    detailed: DetailedSecurityInfo | None = None,
) -> str:
    """Render report as JSON for machine-readable output."""
    checks_list = list(checks)
    ports_list = list(ports)
    ts = datetime.now(timezone.utc).isoformat()

    # Calculate hardening index
    hardening = calculate_hardening_index(checks_list)
    level, _ = get_hardening_level(hardening["overall_index"])

    # Build JSON structure
    report: dict[str, Any] = {
        "scan_info": {
            "generated_at": ts,
            "scanner": "Auditless",
            "version": __version__,
        },
        "system": {
            "hostname": system.hostname,
            "os": system.os,
            "kernel": system.kernel,
            "uptime": system.uptime,
            "logged_in_users": system.users,
        },
        "summary": {
            "total_checks": hardening["total_checks"],
            "passed": hardening["passed"],
            "warned": hardening["warned"],
            "failed": hardening["failed"],
            "hardening_index": hardening["overall_index"],
            "hardening_level": level,
        },
        "hardening_by_category": {},
        "checks": [],
        "ports": {
            "scanned": len(ports_list),
            "open": len([p for p in ports_list if p.open]),
            "open_ports": [
                {
                    "port": p.port,
                    "state": "open",
                    "reason": p.reason or "",
                    "service": p.service,
                    "version": p.version,
                    "banner": p.banner,
                }
                for p in ports_list
                if p.open
            ],
        },
    }

    # Add category breakdown
    for cat, stats in hardening["categories"].items():
        cat_level, _ = get_hardening_level(stats["index"])
        report["hardening_by_category"][cat] = {
            "index": stats["index"],
            "level": cat_level,
            "passed": stats["pass"],
            "warned": stats["warn"],
            "failed": stats["fail"],
            "total": stats["total"],
        }

    # Add check results
    for check in checks_list:
        report["checks"].append(
            {
                "test_id": check.test_id,
                "category": check.category,
                "item": check.item,
                "status": check.status,
                "details": check.details,
                "recommendation": check.recommendation,
            }
        )

    # Add detailed info if available
    if detailed:
        report["detailed_findings"] = {
            "suid_binaries": detailed.suid_binaries,
            "root_logins": detailed.root_logins,
            "successful_ssh_logins": detailed.successful_ssh_logins,
            "failed_ssh_logins": detailed.failed_ssh_logins,
            "top_processes": detailed.top_processes,
            "disk_usage_dirs": detailed.disk_usage_dirs,
            "available_updates": detailed.available_updates,
            "firewall_rules": detailed.firewall_rules,
            "sshd_config_check": detailed.sshd_config_check,
            "failed_systemd_units": detailed.failed_systemd_units,
            "sudoers_info": detailed.sudoers_info,
            "critical_file_permissions": detailed.critical_file_permissions,
        }

        if detailed.rootkit_scan:
            report["detailed_findings"]["rootkit_scan"] = detailed.rootkit_scan

        if detailed.unused_packages:
            report["detailed_findings"]["unused_packages"] = detailed.unused_packages

    return json.dumps(report, indent=2, ensure_ascii=False)
