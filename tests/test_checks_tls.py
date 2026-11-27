"""Unit tests for local service TLS certificate expiry checks (TLS-4500)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from auditless.checks import disable_command_cache, reset_command_cache
from auditless.checks_tls import (
    _extract_tls_cert_paths,
    _parse_not_after,
    check_tls_certificate_expiry,
    run_all_tls_checks,
)


@pytest.fixture(scope="session", autouse=True)
def _disable_cache_for_tests():
    """Disable command cache during testing."""
    disable_command_cache()
    yield
    reset_command_cache()


def mock_ssh_exec(return_values):
    """Create a mock SSH session backed by the production .run interface."""
    ssh = MagicMock()
    ssh._client = None
    ssh.hostname = "tls-test"
    ssh.run.side_effect = return_values
    return ssh


def _config_line(path: str, key: str, value: str, line: int = 1) -> str:
    return f"{path}:{line}:{key} = {value}\n"


def _expiry(days: float) -> str:
    when = datetime.now(timezone.utc) + timedelta(days=days)
    return f"notAfter={when.strftime('%b %d %H:%M:%S %Y GMT')}\n"


class TestCheckTlsCertificateExpiry:
    """Tests for check_tls_certificate_expiry."""

    def test_no_referenced_certificates_skips_cleanly(self):
        ssh = mock_ssh_exec([(0, "", "")])

        result = check_tls_certificate_expiry(ssh)

        assert result.status == "pass"
        assert result.test_id == "TLS-4500"
        assert "No TLS certificates" in result.details

    def test_expired_certificate_fails(self):
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    _config_line(
                        "/etc/postfix/main.cf",
                        "smtpd_tls_cert_file",
                        "/etc/postfix/cert.pem",
                    ),
                    "",
                ),
                (0, _expiry(-1), ""),
            ]
        )

        result = check_tls_certificate_expiry(ssh)

        assert result.status == "fail"
        assert result.test_id == "TLS-4500"
        assert "Expired certificate(s)" in result.details
        assert "/etc/postfix/cert.pem" in result.details

    def test_certificate_expiring_within_default_threshold_warns(self):
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    _config_line(
                        "/etc/dovecot/conf.d/10-ssl.conf",
                        "ssl_cert",
                        "</etc/dovecot/cert.pem",
                    ),
                    "",
                ),
                (0, _expiry(10), ""),
            ]
        )

        result = check_tls_certificate_expiry(ssh)

        assert result.status == "warn"
        assert "expiring within 30 days" in result.details
        assert "dovecot" in result.details

    def test_certificate_beyond_threshold_passes(self):
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    _config_line(
                        "/etc/postgresql/15/main/postgresql.conf",
                        "ssl_cert_file",
                        "'/etc/ssl/pg.crt'",
                    ),
                    "",
                ),
                (0, _expiry(90), ""),
            ]
        )

        result = check_tls_certificate_expiry(ssh)

        assert result.status == "pass"
        assert "valid for more than 30 days" in result.details
        assert "postgresql" in result.details

    def test_custom_threshold_changes_verdict(self):
        probe = _config_line(
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "ssl-cert",
            "/etc/mysql/server.crt",
        )
        ssh = mock_ssh_exec(
            [
                (0, probe, ""),
                (0, _expiry(45), ""),
                (0, probe, ""),
                (0, _expiry(45), ""),
            ]
        )

        assert check_tls_certificate_expiry(ssh).status == "pass"
        result = check_tls_certificate_expiry(ssh, warn_days=60)
        assert result.status == "warn"
        assert "expiring within 60 days" in result.details

    def test_multiple_services_are_all_assessed(self):
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    _config_line(
                        "/etc/dovecot/dovecot.conf", "ssl_cert", "</etc/dovecot/c.pem"
                    )
                    + _config_line(
                        "/etc/postgresql/15/main/postgresql.conf",
                        "ssl_cert_file",
                        "/etc/ssl/pg.crt",
                    )
                    + _config_line("/etc/mysql/my.cnf", "ssl-cert", "/etc/mysql/c.pem"),
                    "",
                ),
                (0, _expiry(200), ""),
                (0, _expiry(200), ""),
                (0, _expiry(200), ""),
            ]
        )

        result = check_tls_certificate_expiry(ssh)

        assert result.status == "pass"
        assert "3 local service certificate(s)" in result.details
        assert "dovecot" in result.details
        assert "postgresql" in result.details
        assert "mysql/mariadb" in result.details

    def test_unreadable_reference_is_unknown(self):
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    _config_line(
                        "/etc/nginx/nginx.conf",
                        "ssl_certificate",
                        "/etc/nginx/cert.pem;",
                    ),
                    "",
                ),
                (1, "", "Permission denied"),
            ]
        )

        result = check_tls_certificate_expiry(ssh)

        assert result.status == "unknown"
        assert "/etc/nginx/cert.pem" in result.details

    def test_unreadable_certificate_does_not_hide_valid_one(self):
        ssh = mock_ssh_exec(
            [
                (
                    0,
                    _config_line(
                        "/etc/nginx/nginx.conf",
                        "ssl_certificate",
                        "/etc/nginx/good.pem;",
                    )
                    + _config_line(
                        "/etc/apache2/sites-enabled/default-ssl.conf",
                        "SSLCertificateFile",
                        "/etc/apache2/missing.pem",
                    ),
                    "",
                ),
                (0, _expiry(200), ""),
                (1, "", "No such file"),
            ]
        )

        result = check_tls_certificate_expiry(ssh)

        assert result.status == "pass"
        assert "unreadable: apache /etc/apache2/missing.pem" in result.details

    def test_execution_error_fails(self):
        ssh = mock_ssh_exec([RuntimeError("transport gone")])

        result = check_tls_certificate_expiry(ssh)

        assert result.status == "fail"
        assert "Error checking local service certificate expiry" in result.details


class TestTlsConfigParsing:
    """Tests for certificate reference extraction from config output."""

    def test_common_service_directives_are_extracted(self):
        output = (
            "/etc/postfix/main.cf:10:smtpd_tls_cert_file = "
            "${config_directory}/cert.pem\n"
            "/etc/postfix/main.cf:11:smtpd_tls_chain_files = "
            "${config_directory}/cert.pem, ${config_directory}/key.pem\n"
            "/etc/dovecot/conf.d/10-ssl.conf:5:ssl_cert = "
            "</etc/dovecot/cert.pem\n"
            "/etc/postgresql/15/main/postgresql.conf:100:ssl_cert_file = "
            "'/etc/ssl/pg.crt'\n"
            "/etc/mysql/mysql.conf.d/mysqld.cnf:20:ssl-cert = "
            "/etc/mysql/server.crt\n"
            "/etc/nginx/nginx.conf:30:ssl_certificate /etc/nginx/cert.pem;\n"
            "/etc/apache2/sites-enabled/default-ssl.conf:5:"
            "SSLCertificateFile /etc/apache2/cert.pem\n"
        )

        assert _extract_tls_cert_paths(output) == [
            ("postfix", "/etc/postfix/cert.pem"),
            ("postfix", "/etc/postfix/key.pem"),
            ("dovecot", "/etc/dovecot/cert.pem"),
            ("postgresql", "/etc/ssl/pg.crt"),
            ("mysql/mariadb", "/etc/mysql/server.crt"),
            ("nginx", "/etc/nginx/cert.pem"),
            ("apache", "/etc/apache2/cert.pem"),
        ]

    def test_comments_keys_and_duplicates_are_ignored(self):
        output = (
            "/etc/nginx/nginx.conf:30:ssl_certificate /etc/nginx/cert.pem;\n"
            "/etc/nginx/nginx.conf:31:ssl_certificate_key "
            "/etc/nginx/key.pem;\n"
            "/etc/mysql/my.cnf:5:ssl_key = /etc/mysql/key.pem\n"
            "/etc/postfix/main.cf:9:# smtpd_tls_cert_file = /old.pem\n"
            "/etc/apache2/sites-enabled/default-ssl.conf:6:"
            "SSLCertificateFile /etc/nginx/cert.pem\n"
            "malformed line without a line number\n"
        )

        assert _extract_tls_cert_paths(output) == [("nginx", "/etc/nginx/cert.pem")]

    def test_relative_paths_resolve_against_config_directory(self):
        output = "/etc/dovecot/dovecot.conf:4:ssl_cert = <cert.pem\n"

        assert _extract_tls_cert_paths(output) == [("dovecot", "/etc/dovecot/cert.pem")]

    def test_parse_not_after_rejects_missing_or_bad_values(self):
        assert _parse_not_after("") is None
        assert _parse_not_after("notAfter=not a date") is None
        parsed = _parse_not_after("notAfter=Jan  1 00:00:00 2030 GMT")
        assert parsed is not None
        assert parsed.year == 2030


def test_run_all_tls_checks_returns_one_result():
    ssh = mock_ssh_exec([(0, "", "")])

    results = run_all_tls_checks(ssh, "")

    assert len(results) == 1
    assert results[0].test_id == "TLS-4500"
