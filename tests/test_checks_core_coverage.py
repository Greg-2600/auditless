"""Offline coverage for core checks in ``auditless.checks``.

Each test stubs the SSH transport with a ``Mock`` whose ``run`` returns a
scripted ``(code, stdout, stderr)`` tuple, so no host or network access is
required.
"""

from unittest.mock import MagicMock, Mock

import pytest

from auditless import checks


@pytest.fixture(autouse=True)
def _disable_cache():
    """Keep scripted command outputs isolated between tests."""
    checks.disable_command_cache()
    checks.reset_command_cache()
    yield
    checks.enable_command_cache()
    checks.reset_command_cache()


def _ssh(*results):
    ssh = Mock()
    ssh._client = None
    ssh.hostname = "test-host"
    ssh.run = MagicMock(side_effect=list(results))
    return ssh


class TestDiskMemoryLoad:
    def test_disk_usage_branches(self):
        assert checks.check_disk_usage(_ssh((1, "", "df failed"))).status == "warn"
        assert checks.check_disk_usage(_ssh((0, "nonsense", ""))).status == "warn"
        assert checks.check_disk_usage(_ssh((0, "50%", ""))).status == "pass"
        assert checks.check_disk_usage(_ssh((0, "85%", ""))).status == "warn"
        assert checks.check_disk_usage(_ssh((0, "95%", ""))).status == "fail"

    def test_memory_branches(self):
        assert checks.check_memory(_ssh((1, "", "free failed"))).status == "warn"
        assert checks.check_memory(_ssh((0, "1000 nope", ""))).status == "warn"
        assert checks.check_memory(_ssh((0, "1000 50", ""))).status == "fail"
        assert checks.check_memory(_ssh((0, "1000 150", ""))).status == "warn"
        assert checks.check_memory(_ssh((0, "1000 500", ""))).status == "pass"

    def test_load_branches(self):
        assert checks.check_load(_ssh((1, "", "loadavg failed"))).status == "warn"
        assert checks.check_load(_ssh((0, "nope", ""))).status == "warn"
        assert checks.check_load(_ssh((0, "9 9 9", ""))).status == "fail"
        assert checks.check_load(_ssh((0, "1 5 1", ""))).status == "warn"
        assert checks.check_load(_ssh((0, "1 1 1", ""))).status == "pass"


class TestPatchingAndTime:
    def test_updates_branches(self):
        assert checks.check_updates(_ssh((1, "", "failed"))).status == "warn"
        assert checks.check_updates(_ssh((0, "nope", ""))).status == "warn"
        fail_security = checks.check_updates(_ssh((0, "60\n2\n", "")))
        assert fail_security.status == "fail"
        assert "security" in fail_security.details
        assert checks.check_updates(_ssh((0, "60\n0\n", ""))).status == "fail"
        assert checks.check_updates(_ssh((0, "10\n1\n", ""))).status == "fail"
        assert checks.check_updates(_ssh((0, "10\n0\n", ""))).status == "warn"
        assert checks.check_updates(_ssh((0, "0\n0\n", ""))).status == "pass"

    def test_time_sync_branches(self):
        assert checks.check_time_sync(_ssh((1, "", "failed"))).status == "warn"
        assert checks.check_time_sync(_ssh((0, "yes", ""))).status == "pass"
        assert checks.check_time_sync(_ssh((0, "no", ""))).status == "warn"

    def test_reboot_required_flag(self):
        assert (
            checks.check_reboot_required(_ssh((0, "", ""), (0, "", ""))).status
            == "warn"
        )
        assert checks.check_reboot_required(_ssh((1, "", ""))).status == "pass"


class TestAccountsAuthAndProcesses:
    def test_auth_failures_branches(self):
        assert checks.check_auth_failures(_ssh((1, "", "x"))).status == "warn"
        assert checks.check_auth_failures(_ssh((0, "nope", ""))).status == "warn"
        assert checks.check_auth_failures(_ssh((0, "100", ""))).status == "fail"
        assert checks.check_auth_failures(_ssh((0, "25", ""))).status == "warn"
        assert checks.check_auth_failures(_ssh((0, "1", ""))).status == "pass"

    def test_root_logins_branches(self):
        assert checks.check_root_logins(_ssh((1, "", "x"))).status == "warn"
        assert checks.check_root_logins(_ssh((0, "nope", ""))).status == "warn"
        assert checks.check_root_logins(_ssh((0, "2", ""))).status == "warn"
        assert checks.check_root_logins(_ssh((0, "0", ""))).status == "pass"

    def test_suid_files_branches(self):
        assert checks.check_suid_files(_ssh((1, "", "x"))).status == "warn"
        assert checks.check_suid_files(_ssh((0, "nope", ""))).status == "warn"
        assert checks.check_suid_files(_ssh((0, "40", ""))).status == "warn"
        assert checks.check_suid_files(_ssh((0, "5", ""))).status == "pass"

    def test_process_resource_usage_branches(self):
        assert checks.check_process_resource_usage(_ssh((1, "", ""))).status == "pass"
        high_cpu = checks.check_process_resource_usage(
            _ssh((0, "root 95 1 /bin/x|", ""))
        )
        assert high_cpu.status == "warn" and "CPU" in high_cpu.details
        high_mem = checks.check_process_resource_usage(
            _ssh((0, "root 1 95 /bin/x|", ""))
        )
        assert high_mem.status == "warn" and "MEM" in high_mem.details
        ok = checks.check_process_resource_usage(_ssh((0, "root 1 1 /bin/x|", "")))
        assert ok.status == "pass"

    def test_stale_user_accounts_branches(self):
        assert checks.check_stale_user_accounts(_ssh((1, "", ""))).status == "pass"
        assert checks.check_stale_user_accounts(_ssh((0, "", ""))).status == "pass"
        stale = checks.check_stale_user_accounts(
            _ssh((0, "alice Jan 01 2000 10:00:00 +0000\n", ""))
        )
        assert stale.status == "warn" and "alice" in stale.details
        fresh = checks.check_stale_user_accounts(
            _ssh((0, "bob Jan 01 2999 10:00:00 +0000\n", ""))
        )
        assert fresh.status == "pass"


class TestKernelAndPackageChecks:
    def test_boot_loader_password_branches(self):
        assert checks.check_boot_loader_password(_ssh((1, "", ""))).status == "warn"
        assert checks.check_boot_loader_password(_ssh((0, "", ""))).status == "warn"
        result = checks.check_boot_loader_password(
            _ssh((0, 'set superusers="admin"', ""))
        )
        assert result.status == "pass"

    def test_kernel_hardening_branches(self):
        assert checks.check_kernel_hardening(_ssh((1, "", ""))).status == "warn"
        insecure = checks.check_kernel_hardening(
            _ssh((0, "kernel.dmesg_restrict = 0\n", ""))
        )
        assert insecure.status == "warn"
        secure = checks.check_kernel_hardening(
            _ssh((0, "kernel.dmesg_restrict = 1\n", ""))
        )
        assert secure.status == "pass"

    def test_package_manager_security_branches(self):
        assert (
            checks.check_package_manager_security(
                _ssh((0, 'APT::Get::AllowUnauthenticated "true";', ""))
            ).status
            == "warn"
        )
        assert (
            checks.check_package_manager_security(_ssh((0, "gpgcheck=0", ""))).status
            == "warn"
        )
        assert (
            checks.check_package_manager_security(
                _ssh((0, "", ""), (0, "0", ""))
            ).status
            == "warn"
        )
        assert (
            checks.check_package_manager_security(
                _ssh((0, "", ""), (0, "3", ""))
            ).status
            == "pass"
        )
        assert (
            checks.check_package_manager_security(
                _ssh((0, 'APT::Get::AllowUnauthenticated "false";', ""))
            ).status
            == "pass"
        )


class TestLoggingMacAndTools:
    def test_logging_and_auditing_branches(self):
        assert checks.check_logging_and_auditing(_ssh((0, "", ""))).status == "fail"
        assert (
            checks.check_logging_and_auditing(
                _ssh((0, "root 1 rsyslogd", ""), (0, "inactive", ""))
            ).status
            == "warn"
        )
        assert (
            checks.check_logging_and_auditing(
                _ssh((0, "root 1 rsyslogd", ""), (0, "active (running)", ""))
            ).status
            == "pass"
        )
        assert (
            checks.check_logging_and_auditing(
                _ssh((0, "root 1 rsyslogd", ""), (0, "auditd is running", ""))
            ).status
            == "pass"
        )

    def test_selinux_apparmor_branches(self):
        assert (
            checks.check_selinux_apparmor(_ssh((1, "", ""), (1, "", ""))).status
            == "warn"
        )
        assert (
            checks.check_selinux_apparmor(
                _ssh((0, "Permissive", ""), (1, "", ""))
            ).status
            == "warn"
        )
        assert (
            checks.check_selinux_apparmor(
                _ssh((0, "Enforcing", ""), (1, "", ""))
            ).status
            == "pass"
        )
        assert (
            checks.check_selinux_apparmor(_ssh((1, "", ""), (0, "", ""))).status
            == "pass"
        )

    def test_security_tools_branches(self):
        assert checks.check_security_tools(_ssh((0, "", ""))).status == "warn"
        result = checks.check_security_tools(
            _ssh((0, "fail2ban-client\nclamscan\n", ""))
        )
        assert result.status == "pass" and "Fail2ban" in result.details


class TestFilesystemShellAndServices:
    def test_filesystem_mounts_branches(self):
        assert checks.check_filesystem_mounts(_ssh((1, "", ""))).status == "warn"
        insecure = checks.check_filesystem_mounts(
            _ssh((0, "tmpfs on /tmp type tmpfs (rw)\n", ""))
        )
        assert insecure.status == "warn" and "noexec" in insecure.details
        secure = checks.check_filesystem_mounts(
            _ssh(
                (
                    0,
                    "tmpfs on /tmp type tmpfs (rw,noexec,nosuid,nodev)\n"
                    "tmpfs on /var/tmp type tmpfs (rw,noexec)\n"
                    "tmpfs on /dev/shm type tmpfs (rw,noexec,nosuid)\n",
                    "",
                )
            )
        )
        assert secure.status == "pass"

    def test_shell_security_branches(self):
        assert (
            checks.check_shell_security(
                _ssh((0, "0002", ""), (0, "", ""), (0, "", ""))
            ).status
            == "warn"
        )
        assert (
            checks.check_shell_security(
                _ssh((0, "027", ""), (0, "TMOUT=900", ""), (0, "HISTSIZE=1000", ""))
            ).status
            == "pass"
        )

    def test_compiler_presence_branches(self):
        assert checks.check_compiler_presence(_ssh((0, "", ""))).status == "pass"
        assert (
            checks.check_compiler_presence(_ssh((0, "gcc\nmake\n", ""))).status
            == "warn"
        )

    def test_legacy_services_branches(self):
        assert checks.check_legacy_services(_ssh((0, "", ""))).status == "pass"
        assert (
            checks.check_legacy_services(_ssh((0, "root 1 telnetd", ""))).status
            == "fail"
        )


class TestServerChecks:
    def test_web_server_security_branches(self):
        assert checks.check_web_server_security(_ssh((0, "", ""))).status == "pass"
        nginx_ok = checks.check_web_server_security(
            _ssh(
                (0, "nginx", ""),
                (0, "server_tokens off;", ""),
                (0, "LISTEN 0 1 0.0.0.0:443", ""),
            )
        )
        assert nginx_ok.status == "pass"
        nginx_bad = checks.check_web_server_security(
            _ssh((0, "nginx", ""), (0, "server_tokens on;", ""), (0, "", ""))
        )
        assert nginx_bad.status == "warn"
        apache_ok = checks.check_web_server_security(
            _ssh(
                (0, "apache2", ""),
                (0, "ServerTokens Prod", ""),
                (0, "ServerSignature Off", ""),
                (0, "LISTEN 443", ""),
            )
        )
        assert apache_ok.status == "pass"
        apache_bad = checks.check_web_server_security(
            _ssh(
                (0, "httpd", ""),
                (0, "ServerTokens Full", ""),
                (0, "ServerSignature On", ""),
                (0, "", ""),
            )
        )
        assert apache_bad.status == "warn"

    def test_database_security_branches(self):
        assert checks.check_database_security(_ssh((0, "", ""))).status == "pass"
        mysql_ok = checks.check_database_security(
            _ssh((0, "mysqld", ""), (0, "1", ""), (0, "1", ""), (0, "", ""))
        )
        assert mysql_ok.status == "pass"
        mysql_bad = checks.check_database_security(
            _ssh((0, "mysqld", ""), (0, "2", ""), (0, "2", ""), (0, "0.0.0.0:3306", ""))
        )
        assert mysql_bad.status == "warn"
        pg_ok = checks.check_database_security(
            _ssh((0, "postgres", ""), (0, "", ""), (0, "", ""))
        )
        assert pg_ok.status == "pass"
        pg_bad = checks.check_database_security(
            _ssh(
                (0, "postgres", ""),
                (0, "host all all 0.0.0.0/0 trust", ""),
                (0, "", ""),
            )
        )
        assert pg_bad.status == "warn"

    def test_mail_server_security_branches(self):
        assert checks.check_mail_server_security(_ssh((0, "", ""))).status == "pass"
        postfix_ok = checks.check_mail_server_security(
            _ssh(
                (0, "postfix", ""),
                (0, "smtpd_relay_restrictions = reject_unauth_destination", ""),
                (0, "smtpd_use_tls = yes", ""),
                (0, "", ""),
            )
        )
        assert postfix_ok.status == "pass"
        postfix_bad = checks.check_mail_server_security(
            _ssh(
                (0, "postfix", ""),
                (0, "smtpd_relay_restrictions = permit_mynetworks", ""),
                (0, "", ""),
                (0, "0.0.0.0:25", ""),
            )
        )
        assert postfix_bad.status == "warn"

    def test_dns_configuration_branches(self):
        assert checks.check_dns_configuration(_ssh((1, "", ""))).status == "warn"
        dns_bad = checks.check_dns_configuration(
            _ssh((0, "nameserver 8.8.8.8", ""), (0, "0", ""))
        )
        assert dns_bad.status == "warn"
        dns_ok = checks.check_dns_configuration(
            _ssh(
                (0, "nameserver 10.0.0.1\nnameserver 10.0.0.2", ""),
                (0, "1", ""),
            )
        )
        assert dns_ok.status == "pass"


class TestPureParsers:
    def test_directive_value(self):
        out = "#PasswordAuthentication no\nPasswordAuthentication yes\n"
        assert checks._directive_value(out, "PasswordAuthentication") == "yes"
        assert checks._directive_value(out, "PermitRootLogin") is None

    def test_chrony_offset(self):
        assert checks._parse_chrony_offset(
            "System time    0.125000 seconds fast of NTP time"
        ) == pytest.approx(0.125)
        assert checks._parse_chrony_offset(
            "System time    -2.5 seconds slow of NTP time"
        ) == pytest.approx(2.5)
        assert checks._parse_chrony_offset("nothing here") is None

    def test_timesync_offset(self):
        assert checks._parse_timesync_offset("Offset: 2.5ms") == pytest.approx(0.0025)
        assert checks._parse_timesync_offset("  Offset: -100us") == pytest.approx(
            0.0001
        )
        assert checks._parse_timesync_offset("Offset: 3s") == pytest.approx(3.0)
        assert checks._parse_timesync_offset("no offset") is None

    def test_chrony_source_state(self):
        assert checks._chrony_source_state(
            "server a.example iburst nts\npool b.example\n# server c nts\n"
        ) == (True, True)
        assert checks._chrony_source_state("server a.example\n") == (True, False)
        assert checks._chrony_source_state("# server a.example nts\n") == (
            False,
            False,
        )

    def test_pam_option(self):
        text = '# key = ignored\nkey = "value"\nfoo=bar\n'
        assert checks._pam_option(text, "key") == "value"
        assert checks._pam_option(text, "foo") == "bar"
        assert checks._pam_option(text, "missing") is None

    def test_livepatch_active(self):
        assert checks._livepatch_active("enabled: true") is True
        assert checks._livepatch_active("/sys/kernel/livepatch/x/enabled:1") is True
        assert checks._livepatch_active("kpatch_5_1 loaded") is True
        assert checks._livepatch_active("nothing active") is False
