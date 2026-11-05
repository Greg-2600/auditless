"""Unit tests for Audit & Accounting Module (checks_audit.py).

Tests all 7 audit/accounting security checks (ACCT-5000 through ACCT-5006) with
pass/warn/fail scenarios and error handling.
"""

# pylint: disable=protected-access,duplicate-code,line-too-long,too-many-lines,too-few-public-methods,redefined-outer-name,import-outside-toplevel,trailing-newlines

from unittest.mock import MagicMock

import pytest

from linux_health.checks import disable_command_cache, reset_command_cache
from linux_health.checks_audit import (
    check_audit_rules_configured,
    check_auditd_service,
    check_authentication_logging,
    check_kernel_audit_enabled,
    check_log_retention_policy,
    check_process_accounting,
    check_syslog_configured,
    run_all_audit_checks,
)


# Disable command caching for tests to ensure fresh mocks
@pytest.fixture(scope="session", autouse=True)
def _disable_cache_for_tests():
    """Disable command cache during testing to prevent stale mock data."""
    disable_command_cache()
    yield
    reset_command_cache()


def mock_ssh_exec(return_values):
    """Helper to create properly structured SSH mock.

    Args:
        return_values: List of tuples (exit_code, stdout_str, stderr_str)

    Returns:
        MagicMock SSH session with properly configured exec_command
    """
    ssh = MagicMock()
    ssh._client = MagicMock()

    responses = []
    for exit_code, stdout_str, stderr_str in return_values:
        stdin = MagicMock(write=MagicMock(), flush=MagicMock(), close=MagicMock())
        stdout = MagicMock(
            read=MagicMock(return_value=stdout_str.encode()),
            channel=MagicMock(
                exit_status_ready=MagicMock(return_value=True),
                recv_exit_status=MagicMock(return_value=exit_code),
            ),
        )
        stderr = MagicMock(read=MagicMock(return_value=stderr_str.encode()))
        responses.append((stdin, stdout, stderr))

    ssh._client.exec_command.side_effect = responses
    return ssh


class TestCheckProcessAccounting:
    """Test check_process_accounting function (ACCT-5000)."""

    def test_process_accounting_not_installed(self):
        """Test when process accounting is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # dpkg -l acct
            ]
        )

        result = check_process_accounting(ssh)

        assert result.status == "warn"
        assert "not installed" in result.details.lower()
        assert result.test_id == "ACCT-5000"
        assert result.category == "Accounting"

    def test_process_accounting_active(self):
        """Test when process accounting is installed and active."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "ii  acct   6.6.4-2  amd64  GNU Accounting utilities",
                    "",
                ),  # dpkg -l
                (0, "active", ""),  # systemctl is-active
            ]
        )

        result = check_process_accounting(ssh)

        assert result.status == "pass"
        assert "active" in result.details.lower()
        assert "lastcomm" in result.recommendation.lower()

    def test_process_accounting_installed_not_running(self):
        """Test when process accounting is installed but not running."""
        ssh = mock_ssh_exec(
            [
                (0, "ii  acct", ""),  # dpkg -l
                (1, "inactive", ""),  # systemctl is-active
            ]
        )

        result = check_process_accounting(ssh)

        assert result.status == "warn"
        assert "not running" in result.details.lower()


class TestCheckAuditdService:
    """Test check_auditd_service function (ACCT-5001)."""

    def test_auditd_not_installed(self):
        """Test when auditd is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which auditd
            ]
        )

        result = check_auditd_service(ssh)

        assert result.status == "fail"
        assert "not installed" in result.details.lower()
        assert result.test_id == "ACCT-5001"

    def test_auditd_running(self):
        """Test when auditd is running."""
        ssh = mock_ssh_exec(
            [
                (0, "/sbin/auditd\n/sbin/auditctl", ""),  # which auditd
                (0, "active", ""),  # systemctl is-active
            ]
        )

        result = check_auditd_service(ssh)

        assert result.status == "pass"
        assert "running" in result.details.lower()

    def test_auditd_installed_not_running(self):
        """Test when auditd is installed but not running."""
        ssh = mock_ssh_exec(
            [
                (0, "/sbin/auditd", ""),  # which auditd
                (1, "inactive", ""),  # systemctl is-active
            ]
        )

        result = check_auditd_service(ssh)

        assert result.status == "fail"
        assert "not running" in result.details.lower()
        assert "start auditd" in result.recommendation.lower()


class TestCheckAuditRulesConfigured:
    """Test check_audit_rules_configured function (ACCT-5002)."""

    def test_auditd_not_installed(self):
        """Test when auditd is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which auditctl
            ]
        )

        result = check_audit_rules_configured(ssh)

        assert result.status == "warn"
        assert "not installed" in result.details.lower()
        assert result.test_id == "ACCT-5002"

    def test_no_audit_rules(self):
        """Test when no audit rules are configured."""
        ssh = mock_ssh_exec(
            [
                (0, "/sbin/auditctl", ""),  # which auditctl
                (0, "No rules", ""),  # auditctl -l
            ]
        )

        result = check_audit_rules_configured(ssh, password="test")

        assert result.status == "warn"
        assert "no audit rules" in result.details.lower()

    def test_comprehensive_audit_rules(self):
        """Test when comprehensive audit rules are configured."""
        rules = "\n".join([f"-w /etc/passwd -p wa -k identity-{i}" for i in range(15)])
        ssh = mock_ssh_exec(
            [
                (0, "/sbin/auditctl", ""),  # which auditctl
                (0, rules, ""),  # auditctl -l (15 rules)
            ]
        )

        result = check_audit_rules_configured(ssh, password="test")

        assert result.status == "pass"
        assert "15 rules" in result.details.lower()

    def test_limited_audit_rules(self):
        """Test when limited audit rules are configured."""
        rules = "-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity"
        ssh = mock_ssh_exec(
            [
                (0, "/sbin/auditctl", ""),  # which auditctl
                (0, rules, ""),  # auditctl -l (2 rules)
            ]
        )

        result = check_audit_rules_configured(ssh, password="test")

        assert result.status == "warn"
        assert "limited" in result.details.lower()
        assert "2 rules" in result.details.lower()


class TestCheckSyslogConfigured:
    """Test check_syslog_configured function (ACCT-5003)."""

    def test_no_syslog_service(self):
        """Test when no syslog service is found."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which rsyslogd
            ]
        )

        result = check_syslog_configured(ssh)

        assert result.status == "fail"
        assert "no syslog" in result.details.lower()
        assert result.test_id == "ACCT-5003"

    def test_rsyslog_running_with_logs(self):
        """Test when rsyslog is running and writing logs."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/rsyslogd", ""),  # which rsyslogd
                (0, "active", ""),  # systemctl is-active rsyslog
                (
                    0,
                    "-rw-r----- 1 syslog adm 123456 Jan 1 12:00 /var/log/syslog",
                    "",
                ),  # ls
            ]
        )

        result = check_syslog_configured(ssh)

        assert result.status == "pass"
        assert "running and logging" in result.details.lower()

    def test_rsyslog_running_no_logs(self):
        """Test when rsyslog is running but no log files found."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/rsyslogd", ""),  # which rsyslogd
                (0, "active", ""),  # systemctl is-active
                (1, "", ""),  # ls /var/log (no files)
            ]
        )

        result = check_syslog_configured(ssh)

        assert result.status == "warn"
        assert "no recent log files" in result.details.lower()

    def test_syslog_not_running(self):
        """Test when syslog is installed but not running."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/rsyslogd", ""),  # which rsyslogd
                (1, "inactive", ""),  # systemctl is-active
            ]
        )

        result = check_syslog_configured(ssh)

        assert result.status == "fail"
        assert "not running" in result.details.lower()


class TestCheckAuthenticationLogging:
    """Test check_authentication_logging function (ACCT-5004)."""

    def test_no_auth_log_files(self):
        """Test when no authentication log files exist."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # ls /var/log/auth.log
            ]
        )

        result = check_authentication_logging(ssh)

        assert result.status == "fail"
        assert "no authentication log" in result.details.lower()
        assert result.test_id == "ACCT-5004"

    def test_auth_log_with_events(self):
        """Test when auth.log exists with recent events."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "-rw-r----- 1 root adm 12345 Jan 1 12:00 /var/log/auth.log",
                    "",
                ),  # ls
                (
                    0,
                    "Jan 1 12:00:01 host sshd[1234]: Accepted password for user\nJan 1 12:01:00 host sudo: user : TTY=pts/0",
                    "",
                ),  # tail
            ]
        )

        result = check_authentication_logging(ssh, password="test")

        assert result.status == "pass"
        assert "being logged" in result.details.lower()

    def test_auth_log_no_recent_events(self):
        """Test when auth.log exists but no recent events."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "-rw-r----- 1 root adm 100 Jan 1 12:00 /var/log/auth.log",
                    "",
                ),  # ls
                (0, "", ""),  # tail (no matching events)
            ]
        )

        result = check_authentication_logging(ssh, password="test")

        assert result.status == "warn"
        assert "no recent authentication events" in result.details.lower()


class TestCheckKernelAuditEnabled:
    """Test check_kernel_audit_enabled function (ACCT-5005)."""

    def test_kernel_audit_enabled(self):
        """Test when kernel audit is enabled via boot parameter."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "BOOT_IMAGE=/vmlinuz root=/dev/sda1 audit=1 quiet",
                    "",
                ),  # cat /proc/cmdline
            ]
        )

        result = check_kernel_audit_enabled(ssh)

        assert result.status == "pass"
        assert "enabled" in result.details.lower()
        assert result.test_id == "ACCT-5005"

    def test_kernel_audit_explicitly_disabled(self):
        """Test when kernel audit is explicitly disabled."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "BOOT_IMAGE=/vmlinuz root=/dev/sda1 audit=0 quiet",
                    "",
                ),  # cat /proc/cmdline
            ]
        )

        result = check_kernel_audit_enabled(ssh)

        assert result.status == "fail"
        assert "disabled" in result.details.lower()

    def test_kernel_audit_available_not_enabled(self):
        """Test when kernel audit is available but not in boot params."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet",
                    "",
                ),  # cat /proc/cmdline (no audit param)
                (0, "/proc/sys/kernel/audit_enabled", ""),  # ls /proc/sys/kernel/audit*
            ]
        )

        result = check_kernel_audit_enabled(ssh)

        assert result.status == "warn"
        assert "not explicitly enabled" in result.details.lower()

    def test_kernel_audit_not_available(self):
        """Test when kernel audit subsystem is not available."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet",
                    "",
                ),  # cat /proc/cmdline
                (1, "", ""),  # ls /proc/sys/kernel/audit* (not found)
            ]
        )

        result = check_kernel_audit_enabled(ssh)

        assert result.status == "fail"
        assert "not available" in result.details.lower()


class TestCheckLogRetentionPolicy:
    """Test check_log_retention_policy function (ACCT-5006)."""

    def test_logrotate_not_installed(self):
        """Test when logrotate is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which logrotate
            ]
        )

        result = check_log_retention_policy(ssh)

        assert result.status == "warn"
        assert "not installed" in result.details.lower()
        assert result.test_id == "ACCT-5006"

    def test_no_logrotate_configs(self):
        """Test when logrotate is installed but no configs found."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/logrotate", ""),  # which logrotate
                (0, "0", ""),  # ls | wc -l (no files)
            ]
        )

        result = check_log_retention_policy(ssh)

        assert result.status == "fail"
        assert "no logrotate configuration" in result.details.lower()

    def test_logrotate_configured_for_audit_logs(self):
        """Test when logrotate has audit/syslog configurations."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/logrotate", ""),  # which logrotate
                (0, "5", ""),  # ls | wc -l (5 config files)
                (0, "/etc/logrotate.d/rsyslog\n/etc/logrotate.d/audit", ""),  # grep
            ]
        )

        result = check_log_retention_policy(ssh)

        assert result.status == "pass"
        assert "configured" in result.details.lower()
        assert "2 relevant configs" in result.details.lower()

    def test_logrotate_configs_without_audit(self):
        """Test when logrotate is configured but no audit/syslog configs."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/logrotate", ""),  # which logrotate
                (0, "3", ""),  # ls | wc -l (3 config files)
                (1, "", ""),  # grep (no matching configs)
            ]
        )

        result = check_log_retention_policy(ssh)

        assert result.status == "warn"
        assert "no audit/syslog configs" in result.details.lower()


class TestRunAllAuditChecks:
    """Test run_all_audit_checks function."""

    def test_all_checks_executed(self):
        """Test that all 7 audit checks are executed."""
        ssh = MagicMock()
        ssh.exec.return_value = (1, "", "")  # Default: not installed

        results = run_all_audit_checks(ssh, password="test")

        assert len(results) == 7
        assert all(isinstance(r.test_id, str) for r in results)
        assert all(r.category == "Accounting" for r in results)

        # Verify test IDs are in expected range
        test_ids = [r.test_id for r in results]
        assert "ACCT-5000" in test_ids
        assert "ACCT-5006" in test_ids

    def test_error_handling_in_checks(self):
        """Test that exceptions in individual checks are caught."""
        ssh = MagicMock()
        ssh.exec.side_effect = Exception("Network error")

        results = run_all_audit_checks(ssh, password="test")

        # Should still return 7 results, all marked unknown (not fail)
        assert len(results) == 7
        assert all(r.status == "unknown" for r in results)
        assert all("error" in r.details.lower() for r in results)

    def test_mixed_check_results(self):
        """Test that different checks can return different statuses."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # acct not installed
                (0, "/sbin/auditd", ""),  # auditd installed
                (0, "active", ""),  # auditd running
                (0, "/sbin/auditctl", ""),  # auditctl exists
                (0, "No rules", ""),  # no audit rules
                (0, "/usr/sbin/rsyslogd", ""),  # rsyslog exists
                (0, "active", ""),  # rsyslog running
                (
                    0,
                    "-rw-r----- 1 syslog adm 123456 Jan 1 12:00 /var/log/syslog",
                    "",
                ),  # log files present
                (
                    0,
                    "-rw-r----- 1 root adm 12345 Jan 1 12:00 /var/log/auth.log",
                    "",
                ),  # auth.log exists
                (0, "sshd[1234]: Accepted", ""),  # auth events
                (0, "audit=1", ""),  # kernel audit enabled
                (0, "/usr/sbin/logrotate", ""),  # logrotate installed
                (0, "5", ""),  # logrotate configs
                (0, "/etc/logrotate.d/rsyslog", ""),  # relevant configs
            ]
        )

        results = run_all_audit_checks(ssh, password="test")

        assert len(results) == 7
        # Should have mix of pass/warn/fail
        statuses = [r.status for r in results]
        assert "pass" in statuses
        assert "warn" in statuses
