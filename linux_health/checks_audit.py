"""Audit & Accounting Module for Linux Health Security Scanner.

This module implements audit and accounting security checks for process accounting,
auditd, syslog, and authentication logging following Lynis-compatible test patterns.

Test IDs: ACCT-5000 to ACCT-5006
Category: Accounting & Audit
"""

from __future__ import annotations

import re
import time
from typing import List

from .checks import CheckResult, _fail, _pass, _run, _unknown, _warn
from .ssh_client import SSHSession
from .test_ids import CHECK_TEST_IDS


def check_process_accounting(ssh: SSHSession, _password: str = "") -> CheckResult:
    """Check if process accounting is enabled.

    Test ID: ACCT-5000 (Lynis equivalent: ACCT-9622)
    Category: Accounting

    Verifies that process accounting (acct/psacct) is installed and active.
    """
    category = "Accounting"
    test_id = "ACCT-5000"

    # Check if accounting package is installed
    ret, out, _ = _run(
        ssh, "dpkg -l acct psacct 2>/dev/null || rpm -q psacct 2>/dev/null"
    )

    if ret != 0 or not out:
        return _warn(
            "Process Accounting",
            "Process accounting (acct/psacct) not installed",
            "Install process accounting: apt-get install acct OR yum install psacct",
            category,
            test_id,
        )

    # Check if service is active
    ret, out, _ = _run(
        ssh,
        "systemctl is-active acct psacct 2>/dev/null || service acct status 2>/dev/null",
    )

    status = out.strip().lower()

    if status.startswith("active") or status == "running":
        return _pass(
            "Process Accounting",
            "Process accounting is enabled and active",
            "Review accounting logs regularly: lastcomm, sa",
            category,
            test_id,
        )

    return _warn(
        "Process Accounting",
        "Process accounting installed but not running",
        "Enable process accounting: systemctl enable --now acct",
        category,
        test_id,
    )


def check_auditd_service(ssh: SSHSession, _password: str = "") -> CheckResult:
    """Check if auditd service is running.

    Test ID: ACCT-5001 (Lynis equivalent: ACCT-9628)
    Category: Accounting

    Verifies that the Linux Audit daemon (auditd) is installed and running.
    """
    category = "Accounting"
    test_id = "ACCT-5001"

    # Check if auditd is installed
    ret, out, _ = _run(ssh, "which auditd auditctl 2>/dev/null")

    if ret != 0 or not out:
        return _fail(
            "Auditd Service",
            "Auditd not installed",
            "Install auditd: apt-get install auditd OR yum install audit",
            category,
            test_id,
        )

    # Check if auditd service is running
    ret, out, _ = _run(
        ssh,
        "systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null",
    )

    status = out.strip().lower()

    if status.startswith("active") or status == "running":
        return _pass(
            "Auditd Service",
            "Auditd service is running",
            "Configure audit rules and monitor logs",
            category,
            test_id,
        )

    return _fail(
        "Auditd Service",
        "Auditd installed but not running",
        "Start auditd: systemctl enable --now auditd",
        category,
        test_id,
    )


def check_audit_rules_configured(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if audit rules are configured.

    Test ID: ACCT-5002 (Lynis equivalent: ACCT-9630)
    Category: Accounting

    Verifies that auditd has custom audit rules configured for security monitoring.
    """
    category = "Accounting"
    test_id = "ACCT-5002"

    # Check if auditd is installed
    ret, out, _ = _run(ssh, "which auditctl 2>/dev/null")

    if ret != 0:
        return _warn(
            "Audit Rules Configuration",
            "Auditd not installed",
            "Install auditd first: apt-get install auditd OR yum install audit",
            category,
            test_id,
        )

    # Check current audit rules
    ret, out, _ = _run(ssh, "sudo -S auditctl -l 2>/dev/null", password=password)

    if "No rules" in out or not out.strip():
        return _warn(
            "Audit Rules Configuration",
            "No audit rules configured",
            "Configure audit rules in /etc/audit/rules.d/ or /etc/audit/audit.rules",
            category,
            test_id,
        )

    # Count rules
    rule_count = len(
        [line for line in out.split("\n") if line.strip() and not line.startswith("No")]
    )

    if rule_count >= 10:
        return _pass(
            "Audit Rules Configuration",
            f"Audit rules configured ({rule_count} rules active)",
            "Regularly review audit logs: ausearch, aureport",
            category,
            test_id,
        )
    elif rule_count > 0:
        return _warn(
            "Audit Rules Configuration",
            f"Limited audit rules configured ({rule_count} rules)",
            "Add comprehensive audit rules for file access, syscalls, and authentication",
            category,
            test_id,
        )
    else:
        return _fail(
            "Audit Rules Configuration",
            "Audit rules configuration unclear",
            "Verify audit rules: auditctl -l",
            category,
            test_id,
        )


def check_syslog_configured(ssh: SSHSession, _password: str = "") -> CheckResult:
    """Check if syslog service is configured and running.

    Test ID: ACCT-5003 (Lynis equivalent: LOGG-2138)
    Category: Accounting

    Verifies that syslog (rsyslog/syslog-ng) is installed and operational.
    """
    category = "Accounting"
    test_id = "ACCT-5003"

    # Check for syslog implementations
    ret, out, _ = _run(ssh, "which rsyslogd syslog-ng systemd-journald 2>/dev/null")

    if not out:
        return _fail(
            "Syslog Configuration",
            "No syslog service found",
            "Install syslog: apt-get install rsyslog OR yum install rsyslog",
            category,
            test_id,
        )

    syslog_service = (
        "rsyslog"
        if "rsyslogd" in out
        else "syslog-ng" if "syslog-ng" in out else "systemd-journald"
    )

    # Check if service is running
    ret, out, _ = _run(
        ssh,
        f"systemctl is-active {syslog_service} 2>/dev/null || service {syslog_service} status 2>/dev/null",
    )

    status = out.strip().lower()

    if status.startswith("active") or status == "running":
        # Check if logs are being written
        ret, out, _ = _run(
            ssh, "ls -lh /var/log/syslog /var/log/messages 2>/dev/null | head -2"
        )

        if out:
            return _pass(
                "Syslog Configuration",
                f"{syslog_service} is running and logging",
                "Configure log rotation and remote syslog if needed",
                category,
                test_id,
            )
        else:
            return _warn(
                "Syslog Configuration",
                f"{syslog_service} running but no recent log files",
                "Verify syslog configuration and permissions",
                category,
                test_id,
            )

    return _fail(
        "Syslog Configuration",
        f"{syslog_service} not running",
        f"Start syslog service: systemctl enable --now {syslog_service}",
        category,
        test_id,
    )


def check_authentication_logging(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if authentication events are being logged.

    Test ID: ACCT-5004 (Lynis equivalent: AUTH-9328)
    Category: Accounting

    Verifies that authentication attempts are logged to auth.log/secure.
    """
    category = "Accounting"
    test_id = "ACCT-5004"

    # Check for authentication log files
    ret, out, _ = _run(
        ssh, "ls -lh /var/log/auth.log /var/log/secure 2>/dev/null | head -2"
    )

    if not out:
        return _fail(
            "Authentication Logging",
            "No authentication log files found",
            "Configure syslog to log authentication events",
            category,
            test_id,
        )

    # Get most recent log file
    log_file = "/var/log/auth.log" if "auth.log" in out else "/var/log/secure"

    # Check for recent authentication events
    ret, out, _ = _run(
        ssh,
        f"sudo -S tail -20 {log_file} 2>/dev/null | grep -E '(sshd|sudo|su|login)' | head -5",
        password=password,
    )

    if out and len(out.strip().split("\n")) >= 1:
        return _pass(
            "Authentication Logging",
            f"Authentication events being logged to {log_file}",
            "Monitor authentication logs for suspicious activity",
            category,
            test_id,
        )
    else:
        return _warn(
            "Authentication Logging",
            f"Log file exists but no recent authentication events in {log_file}",
            "Verify syslog configuration for auth facility",
            category,
            test_id,
        )


def check_kernel_audit_enabled(ssh: SSHSession, _password: str = "") -> CheckResult:
    """Check if kernel audit subsystem is enabled.

    Test ID: ACCT-5005 (Lynis equivalent: ACCT-9650)
    Category: Accounting

    Verifies that the Linux kernel audit subsystem is enabled via boot parameters.
    """
    category = "Accounting"
    test_id = "ACCT-5005"

    # Check kernel boot parameters
    ret, out, _ = _run(ssh, "cat /proc/cmdline 2>/dev/null")

    if "audit=1" in out:
        return _pass(
            "Kernel Audit Enabled",
            "Kernel audit subsystem is enabled (audit=1)",
            "Ensure auditd service is running to process events",
            category,
            test_id,
        )
    elif "audit=0" in out:
        return _fail(
            "Kernel Audit Enabled",
            "Kernel audit subsystem is explicitly disabled (audit=0)",
            "Enable kernel auditing: Remove audit=0 from GRUB_CMDLINE_LINUX and update-grub",
            category,
            test_id,
        )
    else:
        # Check if audit system is available
        ret, out, _ = _run(ssh, "ls /proc/sys/kernel/audit* 2>/dev/null")

        if out:
            return _warn(
                "Kernel Audit Enabled",
                "Kernel audit available but not explicitly enabled in boot params",
                "Add audit=1 to GRUB_CMDLINE_LINUX in /etc/default/grub and run update-grub",
                category,
                test_id,
            )
        else:
            return _fail(
                "Kernel Audit Enabled",
                "Kernel audit subsystem not available",
                "Recompile kernel with CONFIG_AUDIT or use a kernel with audit support",
                category,
                test_id,
            )


# Stage 2 probe for ACCT-5006. Single read-only shell: rotation status
# freshness, timer evidence, retention directives for the relevant configs,
# and permissions of the current auth/syslog/audit log files.
_LOG_RETENTION_PROBE = (
    "bash -lc '"
    "echo ===STATUS; "
    'stat -c "%Y %n" /var/lib/logrotate/status /var/lib/logrotate.status '
    "2>/dev/null; "
    "echo ===TIMER; "
    "systemctl is-active logrotate.timer 2>/dev/null; "
    "echo ===DIRECTIVES; "
    'for f in /etc/logrotate.d/*; do [ -f "$f" ] || continue; '
    'case "$f" in *syslog*|*auth*|*audit*|*messages*|*secure*) ;; '
    "*) continue;; esac; "
    'echo "FILE:$f"; '
    'grep -hE "^[[:space:]]*(rotate|maxage|compress|create|daily|weekly|'
    'monthly|size)[[:space:]]" "$f" 2>/dev/null; '
    "done; "
    "echo ===LOGS; "
    "ls -ln /var/log/auth.log /var/log/secure /var/log/syslog "
    "/var/log/messages /var/log/audit/audit.log 2>/dev/null; "
    "true'"
)

_STALE_ROTATION_SECONDS = 7 * 24 * 60 * 60


def _probe_sections(output: str) -> dict[str, list[str]]:
    """Split a marker-delimited remote probe into named sections."""
    sections: dict[str, list[str]] = {}
    current = ""
    for line in output.splitlines():
        if line.startswith("==="):
            current = line[3:].strip()
            sections[current] = []
        elif current:
            sections[current].append(line)
    return sections


def _log_retention_gaps(sections: dict[str, list[str]]) -> list[str]:
    """Derive rotation weaknesses from the stage-2 probe sections."""
    gaps: list[str] = []

    # Retention directives: a config that rotates but never expires logs is
    # a disk-fill risk; ``rotate 0`` deletes the current log immediately.
    directives = [line.strip() for line in sections.get("DIRECTIVES", []) if line]
    has_retention = any(
        re.match(r"(rotate|maxage)\b", line, re.IGNORECASE) for line in directives
    )
    if not has_retention:
        gaps.append("no rotate/maxage retention directive in auth/syslog configs")

    for line in directives:
        if re.match(r"rotate\s+0\b", line, re.IGNORECASE) and not any(
            re.match(r"maxage\b", other, re.IGNORECASE) for other in directives
        ):
            gaps.append("rotate 0 deletes the current log with no maxage fallback")
            break

    for line in directives:
        match = re.match(r"create\s+0?([0-7]{3,4})\b", line, re.IGNORECASE)
        if match and int(match.group(1), 8) & 0o002:
            gaps.append(f"world-writable rotation mode in '{line}'")
            break

    # World-writable live log files are a tampering/forgery vector.
    world_writable = []
    for line in sections.get("LOGS", []):
        parts = line.split()
        if (
            len(parts) >= 9
            and parts[0].startswith("-")  # regular file, not a symlink
            and len(parts[0]) >= 10
            and parts[0][8] == "w"
        ):
            world_writable.append(parts[-1])
    if world_writable:
        gaps.append(f"world-writable log files: {', '.join(world_writable[:3])}")

    # Staleness only when a status file exists: absence is not proof of
    # failure (some images rotate via cron without a status file).
    timestamps = []
    for line in sections.get("STATUS", []):
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            timestamps.append(int(parts[0]))
    if timestamps:
        age = time.time() - max(timestamps)
        if age > _STALE_ROTATION_SECONDS:
            gaps.append(f"last rotation status is {age / 86400:.0f} days old")

    return gaps


def check_log_retention_policy(ssh: SSHSession, _password: str = "") -> CheckResult:
    """Check if log retention/rotation is configured.

    Test ID: ACCT-5006 (Lynis equivalent: LOGG-2150)
    Category: Accounting

    Stage 1 verifies logrotate is installed, config exists, and auth/syslog/
    audit logs have a rotation policy. Stage 2 audits the policy itself:
    rotate/maxage retention, world-writable ``create`` modes, world-writable
    live log files, and whether rotation has run recently.
    """
    category = "Accounting"
    test_id = "ACCT-5006"

    # Check if logrotate is installed
    ret, out, _ = _run(ssh, "which logrotate 2>/dev/null")

    if ret != 0:
        return _warn(
            "Log Retention Policy",
            "Logrotate not installed",
            "Install logrotate: apt-get install logrotate OR yum install logrotate",
            category,
            test_id,
        )

    # Check logrotate configuration
    ret, out, _ = _run(
        ssh, "ls /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null | wc -l"
    )

    config_count = int(out.strip()) if out.strip().isdigit() else 0

    if config_count == 0:
        return _fail(
            "Log Retention Policy",
            "No logrotate configuration files found",
            "Configure log rotation in /etc/logrotate.conf and /etc/logrotate.d/",
            category,
            test_id,
        )

    # Check for audit/syslog rotation configs
    ret, out, _ = _run(
        ssh,
        "grep -l -E '(syslog|auth|audit|messages)' /etc/logrotate.d/* 2>/dev/null | head -5",
    )

    if not out:
        return _warn(
            "Log Retention Policy",
            f"Logrotate configured ({config_count} files) but no audit/syslog configs found",
            "Add rotation policies for /var/log/auth.log, /var/log/syslog, /var/log/audit/",
            category,
            test_id,
        )

    configs = [line for line in out.strip().splitlines() if line]
    summary = f"Log rotation configured ({len(configs)} relevant configs)"

    # Stage 2 (item 12): audit the directives, log permissions and rotation
    # status instead of trusting the presence of a config file.
    _, probe_out, _ = _run(ssh, _LOG_RETENTION_PROBE)
    sections = _probe_sections(probe_out)
    if "STATUS" not in sections:
        return _unknown(
            "Log Retention Policy",
            "Log rotation configured but the stage-2 probe could not run "
            "(no bash/stat output)",
            "Verify bash, stat and ls are available; re-run the scan with a "
            "POSIX shell or an account allowed to read /var/log",
            category,
            test_id,
        )
    gaps = _log_retention_gaps(sections)
    timer = " ".join(sections.get("TIMER", [])).strip().lower()

    evidence = []
    if any(
        re.match(r"(rotate|maxage)\b", line.strip(), re.IGNORECASE)
        for line in sections.get("DIRECTIVES", [])
    ):
        evidence.append("retention directives present")
    if timer.startswith("active"):
        evidence.append("logrotate.timer active")

    if gaps:
        parts = [summary] + gaps
        return _warn(
            "Log Retention Policy",
            "; ".join(parts),
            "Rotate auth/syslog/audit logs daily or weekly with rotate >= 4 "
            "and maxage; use a root-owned mode such as create 0640; keep "
            "live logs non-world-writable; confirm logrotate.timer or "
            "cron.daily runs",
            category,
            test_id,
        )

    detail = summary
    if evidence:
        detail += "; " + ", ".join(evidence)
    return _pass(
        "Log Retention Policy",
        detail,
        "Review retention periods: /etc/logrotate.conf",
        category,
        test_id,
    )


def run_all_audit_checks(ssh: SSHSession, password: str = "") -> List[CheckResult]:
    """Run all audit and accounting security checks.

    Returns:
        List of CheckResult objects for all audit/accounting checks.
    """
    checks = [
        check_process_accounting,
        check_auditd_service,
        check_audit_rules_configured,
        check_syslog_configured,
        check_authentication_logging,
        check_kernel_audit_enabled,
        check_log_retention_policy,
    ]

    results = []
    for check in checks:
        try:
            result = check(ssh, password)
            results.append(result)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # Create a failure result if check crashes
            results.append(
                CheckResult(
                    category="Accounting",
                    item=check.__name__.replace("check_", "").replace("_", " ").title(),
                    status="unknown",
                    details=f"Check failed with error (not assessed): {str(e)}",
                    recommendation="Review check implementation and SSH connection",
                    test_id=CHECK_TEST_IDS.get(check.__name__, "ACCT-XXXX"),
                )
            )

    return results
