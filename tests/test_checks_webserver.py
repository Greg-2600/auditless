"""Unit tests for web server security checks module."""

# pylint: disable=protected-access,duplicate-code,line-too-long,too-many-lines,too-few-public-methods,redefined-outer-name,import-outside-toplevel,trailing-newlines

from unittest.mock import MagicMock

import pytest

from linux_health.checks import disable_command_cache, reset_command_cache
from linux_health.checks_webserver import (
    check_access_controls,
    check_directory_listing_disabled,
    check_http_to_https_redirect,
    check_security_headers,
    check_security_modules_enabled,
    check_ssl_certificate_validity,
    check_ssl_tls_enabled,
    check_web_server_installed,
    run_all_webserver_checks,
)


@pytest.fixture(scope="session", autouse=True)
def _disable_cache_for_tests():
    """Disable command cache during testing."""
    disable_command_cache()
    yield
    reset_command_cache()


def create_mock_ssh(return_values):
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


class TestCheckWebServerInstalled:
    """Tests for check_web_server_installed function."""

    def test_apache_installed(self):
        """Test when Apache is installed."""
        ssh = create_mock_ssh(
            [
                (0, "/usr/sbin/apache2", ""),  # which apache2 httpd
                (0, "Server version: Apache/2.4.52", ""),  # apache2ctl -v
                (1, "", ""),  # which nginx
                (0, "", ""),  # nginx -v (not reached, but safe)
            ]
        )
        result = check_web_server_installed(ssh, "password")
        assert result.status == "pass"
        assert "Apache" in result.details

    def test_nginx_installed(self):
        """Test when Nginx is installed."""
        ssh = create_mock_ssh(
            [
                (1, "", ""),  # which apache2 httpd
                (0, "/usr/sbin/nginx", ""),  # which nginx
                (0, "nginx version: nginx/1.18.0", ""),  # nginx -v
            ]
        )
        result = check_web_server_installed(ssh, "password")
        assert result.status == "pass"
        assert "Nginx" in result.details

    def test_both_installed(self):
        """Test when both Apache and Nginx are installed."""
        ssh = create_mock_ssh(
            [
                (0, "/usr/sbin/apache2", ""),  # which apache2 httpd
                (0, "Server version: Apache/2.4.52", ""),  # apache2ctl -v
                (0, "/usr/sbin/nginx", ""),  # which nginx
                (0, "nginx version: nginx/1.18.0", ""),  # nginx -v
            ]
        )
        result = check_web_server_installed(ssh, "password")
        assert result.status == "pass"
        assert "Apache" in result.details
        assert "Nginx" in result.details

    def test_no_web_server(self):
        """Test when no web server is installed."""
        ssh = create_mock_ssh(
            [
                (1, "", ""),  # which apache2 httpd
                (1, "", ""),  # which nginx
            ]
        )
        result = check_web_server_installed(ssh, "password")
        assert result.status == "warn"


class TestCheckSSLTLSEnabled:
    """Tests for check_ssl_tls_enabled function."""

    def test_nginx_ssl_enabled(self):
        """Test when Nginx has SSL/TLS enabled."""
        ssh = create_mock_ssh(
            [
                (0, "listen 443 ssl;", ""),  # grep for SSL in nginx
                (0, "ssl", ""),  # check SSL module
            ]
        )
        result = check_ssl_tls_enabled(ssh, "password")
        assert result.status in ("pass", "warn")

    def test_apache_ssl_enabled(self):
        """Test when Apache has SSL module enabled."""
        ssh = create_mock_ssh(
            [
                (1, "", ""),  # grep for SSL in nginx
                (0, "ssl_module (shared)", ""),  # apache2ctl -M
            ]
        )
        result = check_ssl_tls_enabled(ssh, "password")
        assert result.status in ("pass", "warn")

    def test_ssl_not_enabled(self):
        """Test when SSL/TLS is not enabled."""
        ssh = create_mock_ssh(
            [
                (1, "", ""),  # grep for SSL in nginx
                (1, "", ""),  # apache2ctl -M fails
            ]
        )
        result = check_ssl_tls_enabled(ssh, "password")
        assert result.status == "fail"


class TestCheckSSLCertificateValidity:
    """Tests for check_ssl_certificate_validity function."""

    def test_valid_certificates(self):
        """Test when valid SSL certificates exist."""
        ssh = create_mock_ssh(
            [
                (0, "/etc/nginx/ssl/cert.pem", ""),  # find certs in nginx
                (0, "Dec 31 23:59:59 2025 GMT", ""),  # openssl x509 enddate
                (0, "/etc/apache2/ssl/cert.pem", ""),  # find certs in apache
                (0, "Dec 31 23:59:59 2025 GMT", ""),  # openssl x509 enddate
            ]
        )
        result = check_ssl_certificate_validity(ssh, "password")
        assert result.status == "pass"

    def test_no_certificates(self):
        """Test when no certificates found."""
        ssh = create_mock_ssh(
            [
                (1, "", ""),  # find certs in nginx fails
                (1, "", ""),  # find certs in apache fails
            ]
        )
        result = check_ssl_certificate_validity(ssh, "password")
        assert result.status == "warn"

    def test_expired_certificate(self):
        """Test with expired certificate."""
        ssh = create_mock_ssh(
            [
                (0, "/etc/nginx/ssl/cert.pem", ""),  # find certs in nginx
                (0, "Jan 1 00:00:00 2019 GMT", ""),  # openssl x509 enddate (old year)
                (0, "/etc/apache2/ssl/cert.pem", ""),  # find certs in apache
                (0, "Jan 1 00:00:00 2019 GMT", ""),  # openssl x509 enddate (old year)
            ]
        )
        result = check_ssl_certificate_validity(ssh, "password")
        assert result.status == "warn"


class TestCheckSecurityHeaders:
    """Tests for check_security_headers function."""

    def test_security_headers_present(self):
        """Test when security headers are configured."""
        ssh = create_mock_ssh(
            [
                (0, "1", ""),  # grep -r wc -l (1 header found in nginx)
                (0, "2", ""),  # grep -r wc -l (2 headers found in apache)
            ]
        )
        result = check_security_headers(ssh, "password")
        assert result.status == "pass"

    def test_security_headers_missing(self):
        """Test when security headers are missing."""
        ssh = create_mock_ssh(
            [
                (0, "0", ""),  # grep -r wc -l (no headers in nginx)
                (0, "0", ""),  # grep -r wc -l (no headers in apache)
            ]
        )
        result = check_security_headers(ssh, "password")
        assert result.status == "warn"


class TestCheckHTTPToHTTPSRedirect:
    """Tests for check_http_to_https_redirect function."""

    def test_redirect_configured(self):
        """Test when HTTP to HTTPS redirect is configured."""
        ssh = create_mock_ssh(
            [
                (0, "1", ""),  # grep wc -l (nginx redirect found)
                (0, "1", ""),  # grep wc -l (apache redirect found)
            ]
        )
        result = check_http_to_https_redirect(ssh, "password")
        assert result.status == "pass"

    def test_redirect_not_configured(self):
        """Test when redirect is not configured."""
        ssh = create_mock_ssh(
            [
                (0, "0", ""),  # grep wc -l (no nginx redirect)
                (0, "0", ""),  # grep wc -l (no apache redirect)
            ]
        )
        result = check_http_to_https_redirect(ssh, "password")
        assert result.status == "warn"


class TestCheckDirectoryListingDisabled:
    """Tests for check_directory_listing_disabled function."""

    def test_directory_listing_disabled(self):
        """Test when directory listing is disabled."""
        ssh = create_mock_ssh(
            [
                (0, "0", ""),  # grep wc -l (no autoindex on in nginx)
                (0, "0", ""),  # grep wc -l (no Indexes in apache)
            ]
        )
        result = check_directory_listing_disabled(ssh, "password")
        assert result.status == "pass"

    def test_directory_listing_enabled(self):
        """Test when directory listing is enabled."""
        ssh = create_mock_ssh(
            [
                (0, "1", ""),  # grep wc -l (autoindex on found)
                (0, "0", ""),  # grep wc -l (no Indexes)
            ]
        )
        result = check_directory_listing_disabled(ssh, "password")
        assert result.status == "warn"


class TestCheckAccessControls:
    """Tests for check_access_controls function."""

    def test_access_controls_configured(self):
        """Test when access controls are configured."""
        ssh = create_mock_ssh(
            [
                (0, "1", ""),  # grep wc -l (nginx auth_basic found)
                (0, "1", ""),  # grep wc -l (nginx allow/deny found)
                (0, "1", ""),  # grep wc -l (apache auth found)
                (0, "1", ""),  # grep wc -l (apache allow found)
            ]
        )
        result = check_access_controls(ssh, "password")
        assert result.status == "pass"

    def test_access_controls_not_configured(self):
        """Test when access controls are missing."""
        ssh = create_mock_ssh(
            [
                (0, "0", ""),  # grep wc -l (no nginx auth)
                (0, "0", ""),  # grep wc -l (no nginx allow/deny)
                (0, "0", ""),  # grep wc -l (no apache auth)
                (0, "0", ""),  # grep wc -l (no apache allow)
            ]
        )
        result = check_access_controls(ssh, "password")
        assert result.status == "warn"  # Implementation returns 'warn' not 'fail'


class TestCheckSecurityModulesEnabled:
    """Tests for check_security_modules_enabled function."""

    def test_security_modules_enabled(self):
        """Test when security modules are enabled."""
        ssh = create_mock_ssh(
            [
                (0, "found", ""),  # test -f apache modsecurity
                (0, "1", ""),  # grep wc -l nginx rate limiting
                (0, "0", ""),  # grep wc -l nginx geoip
                (1, "", ""),  # test -f apache mod_evasive (not found)
            ]
        )
        result = check_security_modules_enabled(ssh, "password")
        assert result.status == "pass"

    def test_security_modules_not_enabled(self):
        """Test when security modules are not enabled."""
        ssh = create_mock_ssh(
            [
                (1, "", ""),  # test -f apache modsecurity (not found)
                (0, "0", ""),  # grep wc -l nginx rate limiting (none)
                (0, "0", ""),  # grep wc -l nginx geoip (none)
                (1, "", ""),  # test -f apache mod_evasive (not found)
            ]
        )
        result = check_security_modules_enabled(ssh, "password")
        assert result.status == "warn"


class TestRunAllWebserverChecks:
    """Tests for run_all_webserver_checks function."""

    def test_run_all_checks(self):
        """Test that run_all_webserver_checks executes all checks."""
        # Provide responses for all checks in order
        ssh = create_mock_ssh(
            [
                # check_web_server_installed (3 _run calls)
                (0, "/usr/sbin/apache2", ""),  # which apache2 httpd
                (0, "Apache/2.4.52", ""),  # apache2ctl -v
                (0, "/usr/sbin/nginx", ""),  # which nginx
                (0, "nginx/1.18.0", ""),  # nginx -v
                # check_ssl_tls_enabled (2 _run calls)
                (0, "listen 443 ssl", ""),  # grep nginx ssl
                (0, "ssl_module (shared)", ""),  # apache2ctl -M
                # check_ssl_certificate_validity (2 find + 2 openssl = 4 calls)
                (0, "/etc/nginx/cert.pem", ""),  # find nginx certs
                (0, "Dec 31 2025 GMT", ""),  # openssl enddate
                (0, "/etc/apache2/cert.pem", ""),  # find apache certs
                (0, "Dec 31 2025 GMT", ""),  # openssl enddate
                # check_security_headers (2 _run calls)
                (0, "2", ""),  # grep nginx headers wc -l
                (0, "3", ""),  # grep apache headers wc -l
                # check_http_to_https_redirect (2 _run calls)
                (0, "1", ""),  # grep nginx redirect wc -l
                (0, "1", ""),  # grep apache redirect wc -l
                # check_directory_listing_disabled (2 _run calls)
                (0, "0", ""),  # grep nginx autoindex wc -l
                (0, "0", ""),  # grep apache Indexes wc -l
                # check_access_controls (4 _run calls)
                (0, "1", ""),  # grep nginx auth_basic wc -l
                (0, "1", ""),  # grep nginx allow/deny wc -l
                (0, "1", ""),  # grep apache auth wc -l
                (0, "1", ""),  # grep apache allow wc -l
                # check_security_modules_enabled (4 _run calls)
                (0, "found", ""),  # test -f modsecurity
                (0, "1", ""),  # grep nginx rate limit wc -l
                (0, "0", ""),  # grep nginx geoip wc -l
                (1, "", ""),  # test -f mod_evasive
            ]
        )
        results = run_all_webserver_checks(ssh, "password")

        assert len(results) == 8
        for result in results:
            assert result.test_id.startswith("HTTP-")
            assert result.status in ("pass", "warn", "fail")
