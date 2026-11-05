"""
Unit tests for linux_health.checks_packages module

Tests all package management security checks including:
- PKGS-7300: YUM Security Plugin
- PKGS-7301: APT Security Updates
- PKGS-7302: Repository GPG Keys
- PKGS-7303: Package Signing Enabled
- PKGS-7304: Vulnerable Packages
- PKGS-7305: Package Audit Log
"""

# pylint: disable=protected-access,duplicate-code,line-too-long,too-many-lines,too-few-public-methods,redefined-outer-name,import-outside-toplevel,trailing-newlines

from unittest.mock import MagicMock

import pytest

from linux_health.checks import disable_command_cache, reset_command_cache
from linux_health.checks_packages import (
    check_apt_security_updates,
    check_package_audit_log,
    check_package_signing_enabled,
    check_repository_gpg_keys,
    check_vulnerable_packages,
    check_yum_security_plugin,
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


class TestCheckYumSecurityPlugin:
    """Test PKGS-7300: YUM Security Plugin"""

    def test_yum_not_installed(self):
        """Should pass when YUM/DNF not installed (Debian-based system)"""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "ID=ubuntu\nID_LIKE=debian\n",
                    "",
                ),  # cat os-release (debian family)
                (1, "", ""),  # which yum dnf
            ]
        )
        result = check_yum_security_plugin(ssh, "testpass")
        assert result.status == "pass"
        assert "not a yum/dnf-based system" in result.details.lower()

    def test_yum_security_plugin_present(self):
        """Should pass when yum-plugin-security is installed"""
        ssh = mock_ssh_exec(
            [
                (0, "ID=rhel\nID_LIKE=fedora\n", ""),  # cat os-release (rhel family)
                (0, "/usr/bin/yum", ""),  # which yum dnf
                (0, "yum-plugin-security-1.1.31-54.el7", ""),  # yum list | grep plugin
            ]
        )
        result = check_yum_security_plugin(ssh, "testpass")
        assert result.status == "pass"
        assert "yum security plugin is installed" in result.details.lower()

    def test_dnf_security_features(self):
        """Should pass when DNF is installed (has built-in security features)"""
        ssh = mock_ssh_exec(
            [
                (0, "ID=rhel\nID_LIKE=fedora\n", ""),  # cat os-release (rhel family)
                (0, "/usr/bin/dnf", ""),  # which yum dnf
                (
                    0,
                    "",
                    "",
                ),  # dnf list | grep plugin (not found, will check updateinfo)
                (
                    0,
                    "Last metadata expiration check: 1 day, 2:34:56 ago\nSecurity updates available: 3",
                    "",
                ),  # dnf updateinfo list security
            ]
        )
        result = check_yum_security_plugin(ssh, "testpass")
        assert result.status == "pass"
        assert "dnf security features are functional" in result.details.lower()

    def test_yum_no_security_plugin(self):
        """Should fail when YUM installed but no security plugin"""
        ssh = mock_ssh_exec(
            [
                (0, "ID=rhel\nID_LIKE=fedora\n", ""),  # cat os-release (rhel family)
                (0, "/usr/bin/yum", ""),  # which yum dnf
                (1, "", ""),  # yum list | grep plugin - not found
            ]
        )
        result = check_yum_security_plugin(ssh, "testpass")
        assert result.status == "fail"
        assert "not installed" in result.details.lower()


class TestCheckAptSecurityUpdates:
    """Test PKGS-7301: APT Security Updates"""

    def test_apt_not_installed(self):
        """Should pass when APT not installed (RHEL-based system)"""
        ssh = mock_ssh_exec(
            [
                (0, "ID=rhel\nID_LIKE=fedora\n", ""),  # cat os-release (rhel family)
                (1, "", ""),  # which apt-get
            ]
        )
        result = check_apt_security_updates(ssh, "testpass")
        assert result.status == "pass"
        assert "not an apt-based system" in result.details.lower()

    def test_debian_security_sources_present(self):
        """Should pass when Debian security sources configured"""
        ssh = mock_ssh_exec(
            [
                (0, "ID=debian\n", ""),  # cat os-release (debian family)
                (0, "/usr/bin/apt-get", ""),  # which apt-get apt
                (
                    0,
                    "deb http://security.debian.org bullseye-security main\n"
                    "deb http://security.debian.org bullseye-security/updates main contrib",
                    "",
                ),
            ]
        )
        result = check_apt_security_updates(ssh, "testpass")
        assert result.status == "pass"
        assert "2 entries" in result.details

    def test_ubuntu_security_sources_present(self):
        """Should pass when Ubuntu security sources configured"""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "ID=ubuntu\nID_LIKE=debian\n",
                    "",
                ),  # cat os-release (debian family)
                (0, "/usr/bin/apt-get", ""),  # which apt-get apt
                (
                    0,
                    "deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n"
                    "deb http://security.ubuntu.com/ubuntu jammy-security universe multiverse",
                    "",
                ),
            ]
        )
        result = check_apt_security_updates(ssh, "testpass")
        assert result.status == "pass"
        assert "2 entries" in result.details

    def test_no_security_sources(self):
        """Should fail when APT installed but no security sources"""
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    "ID=ubuntu\nID_LIKE=debian\n",
                    "",
                ),  # cat os-release (debian family)
                (0, "/usr/bin/apt-get", ""),  # which apt-get
                (1, "", ""),  # grep security - nothing found
            ]
        )
        result = check_apt_security_updates(ssh, "testpass")
        assert result.status == "fail"
        assert "no security update sources" in result.details.lower()


class TestCheckRepositoryGpgKeys:
    """Test PKGS-7302: Repository GPG Keys"""

    def test_apt_gpg_keys_modern(self):
        """Should pass when modern APT GPG keys configured"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt-get", ""),  # which apt-get
                (1, "", ""),  # which yum
                (0, "5", ""),  # ls /etc/apt/trusted.gpg.d/*.gpg | wc -l
            ]
        )
        result = check_repository_gpg_keys(ssh, "testpass")
        assert result.status == "pass"
        assert "5 keys" in result.details

    def test_apt_gpg_keys_legacy(self):
        """Should pass when legacy apt-key shows keys"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt-get", ""),  # which apt-get yum dnf
                (0, "8", ""),  # apt-key list | grep -c 'pub'
                (0, "0", ""),  # ls /etc/apt/trusted.gpg.d/ | wc -l
            ]
        )
        result = check_repository_gpg_keys(ssh, "testpass")
        assert result.status == "pass"
        assert "8 keys" in result.details

    def test_yum_gpg_keys(self):
        """Should pass when YUM/DNF GPG keys configured"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/yum", ""),  # which apt-get yum dnf
                (0, "12", ""),  # rpm -q gpg-pubkey | wc -l
            ]
        )
        result = check_repository_gpg_keys(ssh, "testpass")
        assert result.status == "pass"
        assert "12 keys" in result.details

    def test_no_gpg_keys_apt(self):
        """Should fail when APT installed but no GPG keys"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt-get", ""),  # which apt-get
                (1, "", ""),  # which yum
                (0, "0", ""),  # ls /etc/apt/trusted.gpg.d/*.gpg | wc -l
                (0, "0", ""),  # apt-key list | grep -c '^pub'
            ]
        )
        result = check_repository_gpg_keys(ssh, "testpass")
        assert result.status == "fail"
        assert "no repository gpg keys" in result.details.lower()

    def test_no_package_manager(self):
        """Should warn when no package manager found"""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which apt-get yum dnf
            ]
        )
        result = check_repository_gpg_keys(ssh, "testpass")
        assert result.status == "warn"
        assert "no supported package manager" in result.details.lower()


class TestCheckPackageSigningEnabled:
    """Test PKGS-7303: Package Signing Enabled"""

    def test_apt_signature_verification_enabled(self):
        """Should pass when APT signature verification is enforced"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt-get", ""),  # which apt-get
                (1, "", ""),  # which yum
                (0, 'APT::Get::AllowUnauthenticated "false";', ""),  # apt-config dump
            ]
        )
        result = check_package_signing_enabled(ssh, "testpass")
        assert result.status == "pass"
        assert "signature verification is enabled" in result.details.lower()

    def test_apt_default_verification(self):
        """Should pass when APT verification not explicitly disabled"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt-get", ""),  # which apt-get yum dnf
                (1, "", ""),  # apt-config dump - no AllowUnauthenticated setting
            ]
        )
        result = check_package_signing_enabled(ssh, "testpass")
        assert result.status == "pass"
        assert "signature verification is enabled" in result.details.lower()

    def test_yum_gpgcheck_enabled(self):
        """Should pass when YUM gpgcheck is enabled"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/yum", ""),  # which apt-get yum dnf
                (0, "gpgcheck=1", ""),  # grep 'gpgcheck' /etc/yum.conf
            ]
        )
        result = check_package_signing_enabled(ssh, "testpass")
        assert result.status == "pass"
        assert "signature verification is enabled" in result.details.lower()

    def test_yum_gpgcheck_disabled(self):
        """Should fail when YUM gpgcheck is disabled"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/yum", ""),  # which apt-get yum dnf
                (0, "gpgcheck=0", ""),  # grep 'gpgcheck' /etc/yum.conf
            ]
        )
        result = check_package_signing_enabled(ssh, "testpass")
        assert result.status == "fail"
        assert "disabled" in result.details.lower()

    def test_apt_unauthenticated_allowed(self):
        """Should fail when APT allows unauthenticated packages"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt-get", ""),  # which apt-get yum dnf
                (0, 'APT::Get::AllowUnauthenticated "true";', ""),  # apt-config dump
            ]
        )
        result = check_package_signing_enabled(ssh, "testpass")
        assert result.status == "fail"
        assert "unauthenticated" in result.details.lower()


class TestCheckVulnerablePackages:
    """Test PKGS-7304: Vulnerable Packages"""

    def test_apt_no_security_updates(self):
        """Should pass when no APT security updates available"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt-get", ""),  # which apt-get
                (1, "", ""),  # which yum
                (0, "0", ""),  # apt-get -s upgrade | grep -i security | wc -l
            ]
        )
        result = check_vulnerable_packages(ssh, "testpass")
        assert result.status == "pass"
        assert "no security updates" in result.details.lower()

    def test_apt_security_updates_available(self):
        """Should warn when APT security updates available"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt", ""),  # which apt dnf yum | head -1
                (0, "0", ""),  # apt-get update | grep -c 'error'
                (0, "4", ""),  # apt list --upgradable | grep -i 'security' | wc -l
            ]
        )
        result = check_vulnerable_packages(ssh, "testpass")
        assert result.status == "warn"
        assert "4 security updates available" in result.details

    def test_yum_no_security_updates(self):
        """Should pass when no YUM security updates available"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/yum", ""),  # which apt dnf yum | head -1
                (0, "0", ""),  # yum updateinfo list security | grep -c 'security'
            ]
        )
        result = check_vulnerable_packages(ssh, "testpass")
        assert result.status == "pass"
        assert "no security updates" in result.details.lower()

    def test_yum_security_updates_available(self):
        """Should fail when many YUM security updates available"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/yum", ""),  # which apt dnf yum | head -1
                (0, "15", ""),  # yum updateinfo list security | grep -c 'security'
            ]
        )
        result = check_vulnerable_packages(ssh, "testpass")
        assert result.status == "fail"
        assert "15 security updates pending" in result.details

    def test_no_package_manager(self):
        """Should warn when no package manager found"""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which apt dnf yum | head -1
            ]
        )
        result = check_vulnerable_packages(ssh, "testpass")
        assert result.status == "warn"
        assert "cannot determine package manager" in result.details.lower()


class TestCheckPackageAuditLog:
    """Test PKGS-7305: Package Audit Log"""

    def test_apt_logging_enabled(self):
        """Should pass when APT logging is active"""
        ssh = mock_ssh_exec(
            [
                (0, "apt_history", ""),  # test -f /var/log/apt/history.log
                (0, "dpkg_log", ""),  # test -f /var/log/dpkg.log
                (0, "yum_log", ""),  # test -f /var/log/yum.log
                (0, "dnf_log", ""),  # test -f /var/log/dnf.log
                (0, "2", ""),  # find /var/log -mtime -30 | wc -l
            ]
        )
        result = check_package_audit_log(ssh, "testpass")
        assert result.status == "pass"
        assert "apt history" in result.details.lower()
        assert "dpkg log" in result.details.lower()

    def test_apt_history_only(self):
        """Should pass when APT history log exists (dpkg missing)"""
        ssh = mock_ssh_exec(
            [
                (0, "apt_history", ""),  # test -f /var/log/apt/history.log
                (1, "", ""),  # test -f /var/log/dpkg.log
                (1, "", ""),  # test -f /var/log/yum.log
                (1, "", ""),  # test -f /var/log/dnf.log
                (0, "1", ""),  # find /var/log -mtime -30 | wc -l
            ]
        )
        result = check_package_audit_log(ssh, "testpass")
        assert result.status == "pass"
        assert "apt history" in result.details.lower()

    def test_yum_logging_enabled(self):
        """Should pass when YUM logging is active"""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # test -f /var/log/apt/history.log
                (1, "", ""),  # test -f /var/log/dpkg.log
                (0, "yum_log", ""),  # test -f /var/log/yum.log
                (1, "", ""),  # test -f /var/log/dnf.log
                (0, "1", ""),  # find /var/log -mtime -30 | wc -l
            ]
        )
        result = check_package_audit_log(ssh, "testpass")
        assert result.status == "pass"
        assert "yum log" in result.details.lower()

    def test_dnf_logging_enabled(self):
        """Should pass when DNF logging is active"""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # test -f /var/log/apt/history.log
                (1, "", ""),  # test -f /var/log/dpkg.log
                (1, "", ""),  # test -f /var/log/yum.log
                (0, "dnf_log", ""),  # test -f /var/log/dnf.log
                (0, "1", ""),  # find /var/log -mtime -30 | wc -l
            ]
        )
        result = check_package_audit_log(ssh, "testpass")
        assert result.status == "pass"
        assert "dnf log" in result.details.lower()

    def test_apt_no_logging(self):
        """Should warn when APT installed but no logs found"""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/apt-get", ""),  # which apt-get
                (1, "", ""),  # which yum
                (1, "", ""),  # which dnf
                (1, "", ""),  # test -f /var/log/apt/history.log
                (1, "", ""),  # test -f /var/log/dpkg.log
            ]
        )
        result = check_package_audit_log(ssh, "testpass")
        assert result.status == "warn"
        assert "no package manager log files found" in result.details.lower()

    def test_yum_no_logging(self):
        """Should warn when YUM installed but no logs found"""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which apt-get
                (0, "/usr/bin/yum", ""),  # which yum
                (1, "", ""),  # which dnf
                (1, "", ""),  # test -f /var/log/yum.log
            ]
        )
        result = check_package_audit_log(ssh, "testpass")
        assert result.status == "warn"
        assert "no package manager log files found" in result.details.lower()

    def test_no_package_manager(self):
        """Should warn when no package logs found"""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # test -f /var/log/apt/history.log
                (1, "", ""),  # test -f /var/log/dpkg.log
                (1, "", ""),  # test -f /var/log/yum.log
                (1, "", ""),  # test -f /var/log/dnf.log
            ]
        )
        result = check_package_audit_log(ssh, "testpass")
        assert result.status == "warn"
        assert "no package manager log files found" in result.details.lower()
