"""Unit tests for Filesystem & NFS Security Module (checks_filesystem.py).

Tests all 7 filesystem security checks (NFS-3000, FS-3010 through FS-3014,
and FILE-7525) with pass/warn/fail scenarios and error handling.
"""

# pylint: disable=protected-access,duplicate-code,line-too-long,too-many-lines,too-few-public-methods,redefined-outer-name,import-outside-toplevel,trailing-newlines

from typing import Callable
from unittest.mock import MagicMock

import pytest

from auditless.checks import disable_command_cache, reset_command_cache
from auditless.checks_filesystem import (
    _parse_privileged_probe,
    check_filesystem_integrity_tools,
    check_home_nosuid,
    check_mount_options_security,
    check_nfs_exports_security,
    check_privileged_writable_triage,
    check_tmp_noexec,
    check_var_permissions,
    run_all_filesystem_checks,
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


def _probe_row(
    path: str,
    mode: str,
    package: str = "-",
    owner: str = "root",
    group: str = "root",
) -> str:
    """Build one tab-separated row of canned permission-probe output."""
    return f"{path}\t{mode}\t{owner}\t{group}\t{package}"


@pytest.fixture
def privileged_probe() -> Callable[..., MagicMock]:
    """Build a mocked SSH session from canned permission-probe rows."""

    def _build(rows: list[str], tool: str = "dpkg") -> MagicMock:
        output = f"tool:{tool}\n" + "".join(f"{row}\n" for row in rows)
        return mock_ssh_exec([(0, output, "")])

    return _build


class TestCheckNFSExportsSecurity:
    """Test check_nfs_exports_security function (NFS-3000)."""

    def test_nfs_not_installed(self):
        """Test when NFS server is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which nfsd
            ]
        )

        result = check_nfs_exports_security(ssh)

        assert result.status == "pass"
        assert "not installed" in result.details.lower()
        assert result.test_id == "NFS-3000"
        assert result.category == "Filesystem"

    def test_nfs_installed_no_exports(self):
        """Test when NFS is installed but no exports configured."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/nfsd", ""),  # which nfsd
                (0, "missing", ""),  # test -f /etc/exports
            ]
        )

        result = check_nfs_exports_security(ssh)

        assert result.status == "pass"
        assert "no exports" in result.details.lower()

    def test_world_readable_exports(self):
        """Test when NFS has insecure world-readable exports."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/exportfs", ""),  # which
                (0, "exists", ""),  # test -f
                (0, "/share *(rw,sync,no_subtree_check)", ""),  # grep exports
            ]
        )

        result = check_nfs_exports_security(ssh, password="test")

        assert result.status == "warn"
        assert "world-readable" in result.details.lower()
        assert result.test_id == "NFS-3000"

    def test_secure_exports(self):
        """Test when NFS exports are properly secured."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/nfsd", ""),  # which
                (0, "exists", ""),  # test -f
                (
                    0,
                    "/share 192.168.1.0/24(rw,sync,root_squash,no_subtree_check)",
                    "",
                ),  # exports
            ]
        )

        result = check_nfs_exports_security(ssh, password="test")

        assert result.status == "pass"
        assert "security options" in result.details.lower()


class TestCheckMountOptionsSecurity:
    """Test check_mount_options_security function (FS-3010)."""

    def test_no_filesystems_detected(self):
        """Test when no standard filesystems are found."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # mount | grep
            ]
        )

        result = check_mount_options_security(ssh)

        assert result.status == "warn"
        assert "no standard filesystems" in result.details.lower()
        assert result.test_id == "FS-3010"
        assert result.category == "Storage"

    def test_tmp_without_noexec(self):
        """Test when /tmp is mounted without noexec."""
        ssh = mock_ssh_exec(
            [
                (0, "/dev/sda1 on /tmp type ext4 (rw,relatime)", ""),  # mount
            ]
        )

        result = check_mount_options_security(ssh)

        assert result.status == "fail"
        assert "/tmp" in result.details.lower()
        assert "noexec" in result.details.lower()

    def test_secure_mount_options(self):
        """Test when all filesystems have secure mount options."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "/dev/sda1 on /tmp type ext4 (rw,noexec,nodev,nosuid)\n/dev/sda2 on /home type ext4 (rw,nosuid,nodev)",
                    "",
                ),
            ]
        )

        result = check_mount_options_security(ssh)

        assert result.status == "pass"
        assert "appropriate security options" in result.details.lower()


class TestCheckTmpNoexec:
    """Test check_tmp_noexec function (FS-3011)."""

    def test_tmp_not_separate_partition(self):
        """Test when /tmp is not a separate partition."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # mount | grep ' /tmp '
                (0, "/dev/sda1 on / type ext4 (rw)", ""),  # mount | grep ' / '
            ]
        )

        result = check_tmp_noexec(ssh)

        assert result.status == "warn"
        assert "not a separate partition" in result.details.lower()
        assert result.test_id == "FS-3011"

    def test_tmp_with_noexec(self):
        """Test when /tmp is mounted with noexec."""
        ssh = mock_ssh_exec(
            [
                (0, "/dev/sda2 on /tmp type ext4 (rw,noexec,nodev,nosuid)", ""),
            ]
        )

        result = check_tmp_noexec(ssh)

        assert result.status == "pass"
        assert "noexec" in result.details.lower()

    def test_tmp_without_noexec(self):
        """Test when /tmp lacks noexec option."""
        ssh = mock_ssh_exec(
            [
                (0, "/dev/sda2 on /tmp type ext4 (rw,relatime)", ""),
            ]
        )

        result = check_tmp_noexec(ssh)

        assert result.status == "warn"
        assert "missing noexec" in result.details.lower()


class TestCheckHomeNosuid:
    """Test check_home_nosuid function (FS-3012)."""

    def test_home_not_separate_partition(self):
        """Test when /home is not a separate partition."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # mount | grep ' /home '
            ]
        )

        result = check_home_nosuid(ssh)

        assert result.status == "warn"
        assert "not a separate partition" in result.details.lower()
        assert result.test_id == "FS-3012"

    def test_home_with_nosuid(self):
        """Test when /home is mounted with nosuid."""
        ssh = mock_ssh_exec(
            [
                (0, "/dev/sda3 on /home type ext4 (rw,nosuid,nodev)", ""),
            ]
        )

        result = check_home_nosuid(ssh)

        assert result.status == "pass"
        assert "nosuid" in result.details.lower()

    def test_home_without_nosuid(self):
        """Test when /home lacks nosuid option."""
        ssh = mock_ssh_exec(
            [
                (0, "/dev/sda3 on /home type ext4 (rw,relatime)", ""),
            ]
        )

        result = check_home_nosuid(ssh)

        assert result.status == "warn"
        assert "missing nosuid" in result.details.lower()


class TestCheckVarPermissions:
    """Test check_var_permissions function (FS-3013)."""

    def test_cannot_verify_permissions(self):
        """Test when permissions cannot be verified."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # ls -ld /var
            ]
        )

        result = check_var_permissions(ssh)

        assert result.status == "warn"
        assert "could not verify" in result.details.lower()
        assert result.test_id == "FS-3013"

    def test_world_writable_var_tmp(self):
        """Test when /var/tmp is world-writable without sticky bit."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "drwxr-xr-x 14 root root 4096 Jan  1 12:00 /var\ndrwxrwxrwx  2 root root 4096 Jan  1 12:00 /var/tmp",
                    "",
                ),
            ]
        )

        result = check_var_permissions(ssh)

        assert result.status == "warn"
        assert "world-writable" in result.details.lower()

    def test_secure_var_permissions(self):
        """Test when /var has secure permissions."""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "drwxr-xr-x 14 root root 4096 Jan  1 12:00 /var\ndrwxr-xr-x  8 root root 4096 Jan  1 12:00 /var/log\ndrwxrwxrwt  2 root root 4096 Jan  1 12:00 /var/tmp",
                    "",
                ),
            ]
        )

        result = check_var_permissions(ssh)

        assert result.status == "pass"
        assert "secure" in result.details.lower()


class TestCheckFilesystemIntegrityTools:
    """Test check_filesystem_integrity_tools function (FS-3014)."""

    def test_no_integrity_tools(self):
        """Test when no integrity monitoring tools are installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which aide tripwire
            ]
        )

        result = check_filesystem_integrity_tools(ssh)

        assert result.status == "fail"
        assert "no filesystem integrity" in result.details.lower()
        assert result.test_id == "FS-3014"

    def test_aide_installed_not_initialized(self):
        """Test when AIDE is installed but database not initialized."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/aide", ""),  # which aide
                (0, "missing", ""),  # test -f aide.db
            ]
        )

        result = check_filesystem_integrity_tools(ssh)

        assert result.status == "warn"
        assert "not initialized" in result.details.lower()

    def test_aide_fully_configured(self):
        """Test when AIDE is installed and initialized."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/aide", ""),  # which aide
                (0, "exists", ""),  # test -f aide.db
            ]
        )

        result = check_filesystem_integrity_tools(ssh)

        assert result.status == "pass"
        assert "initialized database" in result.details.lower()

    def test_tripwire_installed(self):
        """Test when Tripwire is installed."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/sbin/tripwire", ""),  # which tripwire
            ]
        )

        result = check_filesystem_integrity_tools(ssh)

        assert result.status == "pass"
        assert "tripwire" in result.details.lower()


class TestCheckPrivilegedWritableTriage:
    """Test check_privileged_writable_triage (FILE-7525)."""

    def test_package_owned_suid_binaries_are_allowlisted(self, privileged_probe):
        """Expected packaged SUID/SGID binaries no longer create noise."""
        rows = [
            _probe_row("/usr/bin/sudo", "4755", "sudo"),
            _probe_row("/usr/bin/passwd", "4755", "passwd"),
            _probe_row("/usr/bin/chfn", "4755", "passwd"),
        ]
        result = check_privileged_writable_triage(privileged_probe(rows))

        assert result.status == "pass"
        assert result.test_id == "FILE-7525"
        assert result.category == "File Permissions"
        assert "3 package-owned SUID/SGID binary(ies) allowlisted" in result.details
        assert "no unpackaged privileged or world-writable files" in result.details

    def test_unpackaged_suid_binary_fails(self, privileged_probe):
        """An SUID binary with no owning package is actionable."""
        rows = [
            _probe_row("/usr/local/bin/backdoor", "4755", owner="alice", group="alice"),
            _probe_row("/usr/bin/sudo", "4755", "sudo"),
        ]
        result = check_privileged_writable_triage(privileged_probe(rows))

        assert result.status == "fail"
        assert "Unpackaged privileged/writable file(s)" in result.details
        assert "/usr/local/bin/backdoor (SUID/SGID 4755 alice:alice)" in result.details
        assert "1 package-owned SUID/SGID binaries allowlisted" in result.details

    def test_unpackaged_world_writable_file_fails(self, privileged_probe):
        """World write outside the package allowlist is a finding."""
        rows = [_probe_row("/etc/cron.d/evil", "0666", owner="alice", group="alice")]
        result = check_privileged_writable_triage(privileged_probe(rows))

        assert result.status == "fail"
        assert "/etc/cron.d/evil (world-writable 0666 alice:alice)" in result.details

    def test_packaged_world_writable_file_warns(self, privileged_probe):
        """Package-owned world-write drift warns instead of failing."""
        rows = [_probe_row("/etc/example.conf", "0666", "coreutils")]
        result = check_privileged_writable_triage(privileged_probe(rows))

        assert result.status == "warn"
        assert "Package-owned world-writable file(s)" in result.details
        assert "package coreutils" in result.details

    def test_sticky_world_writable_file_is_ignored(self, privileged_probe):
        """A sticky world-writable file is not a finding."""
        rows = [_probe_row("/etc/example.tmp", "1666")]
        result = check_privileged_writable_triage(privileged_probe(rows))

        assert result.status == "pass"
        assert "No world-writable or SUID/SGID files" in result.details

    def test_plain_file_is_ignored(self, privileged_probe):
        """A file without dangerous bits never becomes a finding."""
        result = check_privileged_writable_triage(
            privileged_probe([_probe_row("/etc/example.conf", "0644")])
        )

        assert result.status == "pass"
        assert "No world-writable or SUID/SGID files" in result.details

    def test_rpm_ownership_is_supported(self, privileged_probe):
        """RPM hosts use the same allowlist semantics."""
        rows = [_probe_row("/usr/bin/su", "4755", "util-linux")]
        result = check_privileged_writable_triage(privileged_probe(rows, tool="rpm"))

        assert result.status == "pass"
        assert "util-linux" in result.details

    def test_missing_package_tool_is_unknown(self, privileged_probe):
        """Without a package database the allowlist cannot be applied."""
        rows = [_probe_row("/usr/local/bin/backdoor", "4755", owner="alice")]
        result = check_privileged_writable_triage(privileged_probe(rows, tool="none"))

        assert result.status == "unknown"
        assert "allowlist cannot be applied" in result.details
        assert "backdoor" not in result.details

    def test_probe_failure_is_unknown(self):
        """A failed probe never claims a pass."""
        ssh = mock_ssh_exec([(1, "", "Permission denied")])
        result = check_privileged_writable_triage(ssh)

        assert result.status == "unknown"
        assert "Unable to probe file permissions" in result.details

    def test_malformed_rows_are_ignored(self, privileged_probe):
        """Blank, short, non-absolute, and non-octal rows are skipped."""
        rows = [
            "",
            "malformed",
            _probe_row("relative/path", "0666"),
            _probe_row("/etc/bad-mode", "not-octal"),
            _probe_row("/usr/bin/sudo", "4755", "sudo"),
        ]
        result = check_privileged_writable_triage(privileged_probe(rows))

        assert result.status == "pass"
        assert "1 package-owned SUID/SGID binary(ies) allowlisted" in result.details
        assert "bad-mode" not in result.details

    def test_probe_exception_is_unknown(self):
        """Transport failures produce an unknown result with a real test ID."""
        ssh = MagicMock()
        ssh._client.exec_command.side_effect = Exception("Connection lost")
        result = check_privileged_writable_triage(ssh)

        assert result.status == "unknown"
        assert result.test_id == "FILE-7525"
        assert "Error triaging privileged/writable files" in result.details

    def test_parse_probe_reads_tool_and_rows(self):
        """The pure parser keeps the tool marker and valid candidate rows."""
        output = (
            "tool:dpkg\n" + _probe_row("/usr/bin/sudo", "4755", "sudo") + "\nignored\n"
        )
        tool, files = _parse_privileged_probe(output)

        assert tool == "dpkg"
        assert len(files) == 1
        assert files[0].path == "/usr/bin/sudo"
        assert files[0].privileged
        assert files[0].package_owned


def test_privileged_triage_id_is_registered_and_usable() -> None:
    """The new ID is mapped to CIS 6.1 and accepted by profile lint."""
    from auditless.compliance import TEST_CIS
    from auditless.config import lint_profile
    from auditless.test_ids import CHECK_TEST_IDS

    assert CHECK_TEST_IDS["check_privileged_writable_triage"] == "FILE-7525"
    assert ("6.1", "partial") in TEST_CIS["FILE-7525"]
    errors, _ = lint_profile({"skip_tests": ["FILE-7525"]})
    assert not errors


class TestRunAllFilesystemChecks:
    """Test run_all_filesystem_checks function."""

    def test_all_checks_executed(self):
        """Test that all 7 filesystem checks are executed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # Default: not installed/not found
            ]
            * 20
        )  # More than enough for all checks

        results = run_all_filesystem_checks(ssh, password="test")

        assert len(results) == 7
        assert all(isinstance(r.test_id, str) for r in results)

    def test_error_handling_in_checks(self):
        """Test that exceptions in individual checks are caught."""
        ssh = MagicMock()
        ssh._client.exec_command.side_effect = Exception("Connection lost")

        results = run_all_filesystem_checks(ssh, password="test")

        # Should still return 7 results, all marked unknown (not fail)
        assert len(results) == 7
        assert all(r.status == "unknown" for r in results)
        assert all("error" in r.details.lower() for r in results)
