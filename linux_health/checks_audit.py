"""Audit & Accounting Module for Linux Health Security Scanner.

This module implements audit and accounting security checks for process accounting,
auditd, syslog, and authentication logging following Lynis-compatible test patterns.

Test IDs: ACCT-5000 to ACCT-5006
Category: Accounting & Audit
"""

from __future__ import annotations

from typing import List

from .checks import CheckResult, _fail, _pass, _run, _warn
from .ssh_client import SSHSession


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


def check_log_retention_policy(ssh: SSHSession, _password: str = "") -> CheckResult:
    """Check if log retention/rotation is configured.

    Test ID: ACCT-5006 (Lynis equivalent: LOGG-2150)
    Category: Accounting

    Verifies that log rotation is configured via logrotate.
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

    if out:
        configs = out.strip().split("\n")
        return _pass(
            "Log Retention Policy",
            f"Log rotation configured ({len(configs)} relevant configs)",
            "Review retention periods: /etc/logrotate.conf",
            category,
            test_id,
        )
    else:
        return _warn(
            "Log Retention Policy",
            f"Logrotate configured ({config_count} files) but no audit/syslog configs found",
            "Add rotation policies for /var/log/auth.log, /var/log/syslog, /var/log/audit/",
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
                    status="fail",
                    details=f"Check failed with error: {str(e)}",
                    recommendation="Review check implementation and SSH connection",
                    test_id=(
                        (check.__doc__ or "").split("Test ID: ")[1].split()[0]
                        if "Test ID:" in (check.__doc__ or "")
                        else "ACCT-XXXX"
                    ),
                )
            )

    return results
