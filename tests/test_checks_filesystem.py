"""Unit tests for Filesystem & NFS Security Module (checks_filesystem.py).

Tests all 6 filesystem security checks (NFS-3000, FS-3010 through FS-3014) with
pass/warn/fail scenarios and error handling.
"""

# pylint: disable=protected-access,duplicate-code,line-too-long,too-many-lines,too-few-public-methods,redefined-outer-name,import-outside-toplevel,trailing-newlines

from unittest.mock import MagicMock

import pytest

from linux_health.checks import disable_command_cache, reset_command_cache
from linux_health.checks_filesystem import (
    check_filesystem_integrity_tools,
    check_home_nosuid,
    check_mount_options_security,
    check_nfs_exports_security,
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


class TestRunAllFilesystemChecks:
    """Test run_all_filesystem_checks function."""

    def test_all_checks_executed(self):
        """Test that all 6 filesystem checks are executed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # Default: not installed/not found
            ]
            * 20
        )  # More than enough for all checks

        results = run_all_filesystem_checks(ssh, password="test")

        assert len(results) == 6
        assert all(isinstance(r.test_id, str) for r in results)

    def test_error_handling_in_checks(self):
        """Test that exceptions in individual checks are caught."""
        ssh = MagicMock()
        ssh._client.exec_command.side_effect = Exception("Connection lost")

        results = run_all_filesystem_checks(ssh, password="test")

        # Should still return 6 results, all marked unknown (not fail)
        assert len(results) == 6
        assert all(r.status == "unknown" for r in results)
        assert all("error" in r.details.lower() for r in results)
