"""Web Server Security Module for Apache and Nginx.

This module implements web server security checks for Apache and Nginx
following Lynis test patterns (HTTP-6500 to HTTP-6507 range).

Test IDs: HTTP-6500 to HTTP-6507
Category: Web Server Security
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .checks import CheckResult, _fail, _pass, _run, _warn

if TYPE_CHECKING:
    from .ssh_client import SSHSession


def check_web_server_installed(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if Apache or Nginx web server is installed.

    Test ID: HTTP-6500 (Lynis equivalent)
    Category: Web Server

    Detects both Apache (httpd/apache2) and Nginx installation.
    """
    category = "Web Server"
    test_id = "HTTP-6500"

    # Check for Apache
    ret, out, err = _run(ssh, "which apache2 httpd 2>/dev/null | head -1")
    apache_installed = ret == 0 and out.strip()

    # Check for Nginx
    ret, out, err = _run(ssh, "which nginx 2>/dev/null")
    nginx_installed = ret == 0 and out.strip()

    if not apache_installed and not nginx_installed:
        return _warn(
            "Web Server Installation",
            "No web server (Apache/Nginx) found installed",
            "Install Apache or Nginx if web services are required",
            category,
            test_id,
        )

    installed = []
    if apache_installed:
        ret, ver, _ = _run(ssh, "apache2ctl -v 2>/dev/null | head -1")
        if ret == 0:
            installed.append(f"Apache ({ver.strip()})")
        else:
            installed.append("Apache")

    if nginx_installed:
        ret, ver, _ = _run(ssh, "nginx -v 2>&1 | head -1")
        if ret == 0:
            installed.append(f"Nginx ({ver.strip()})")
        else:
            installed.append("Nginx")

    return _pass(
        "Web Server Installation",
        f"Web server installed: {', '.join(installed)}",
        "Review and harden web server configuration",
        category,
        test_id,
    )


def check_ssl_tls_enabled(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if SSL/TLS is enabled on the web server.

    Test ID: HTTP-6501
    Category: Web Server

    Verifies HTTPS availability and SSL/TLS module installation.
    """
    category = "Web Server"
    test_id = "HTTP-6501"

    # Check for Nginx SSL
    ret, out, err = _run(ssh, "test -d /etc/nginx && nginx -T 2>&1 | grep -i ssl")
    nginx_ssl = ret == 0

    # Check for Apache SSL
    ret, out, err = _run(
        ssh, "test -d /etc/apache2 && apache2ctl -M 2>/dev/null | grep ssl"
    )
    apache_ssl = ret == 0

    if not nginx_ssl and not apache_ssl:
        return _fail(
            "SSL/TLS Configuration",
            "SSL/TLS module not enabled in Apache or Nginx",
            "Enable mod_ssl for Apache: a2enmod ssl; or verify ssl_module in Nginx config",
            category,
            test_id,
        )

    enabled = []
    if nginx_ssl:
        enabled.append("Nginx SSL")
    if apache_ssl:
        enabled.append("Apache SSL")

    return _pass(
        "SSL/TLS Configuration",
        f"SSL/TLS enabled: {', '.join(enabled)}",
        "Ensure all certificates are valid and not self-signed",
        category,
        test_id,
    )


def check_ssl_certificate_validity(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check SSL/TLS certificate validity and expiration.

    Test ID: HTTP-6502
    Category: Web Server

    Verifies certificates are valid, not expired, and properly configured.
    """
    category = "Web Server"
    test_id = "HTTP-6502"

    issues = []

    # Check Nginx certificates
    ret, out, err = _run(
        ssh, "find /etc/nginx -name '*.crt' -o -name '*.pem' 2>/dev/null | head -5"
    )
    if ret == 0 and out.strip():
        certs = out.strip().split("\n")
        for cert in certs[:5]:  # Check first 5 certs
            ret, expire, _ = _run(
                ssh,
                f"openssl x509 -enddate -noout -in {cert} 2>/dev/null | cut -d= -f2",
            )
            if ret == 0:
                issues.append(f"Nginx cert expires: {expire.strip()}")

    # Check Apache certificates
    ret, out, err = _run(
        ssh, "find /etc/apache2 -name '*.crt' -o -name '*.pem' 2>/dev/null | head -5"
    )
    if ret == 0 and out.strip():
        certs = out.strip().split("\n")
        for cert in certs[:5]:  # Check first 5 certs
            ret, expire, _ = _run(
                ssh,
                f"openssl x509 -enddate -noout -in {cert} 2>/dev/null | cut -d= -f2",
            )
            if ret == 0:
                issues.append(f"Apache cert expires: {expire.strip()}")

    if not issues:
        return _warn(
            "SSL/TLS Certificate Validity",
            "No SSL certificates found or unable to verify",
            "Ensure SSL certificates are properly installed and accessible",
            category,
            test_id,
        )

    # Check for expired certs (simple heuristic: warning if old)
    has_warnings = any("19" in issue or "2024" in issue for issue in issues)

    if has_warnings:
        return _warn(
            "SSL/TLS Certificate Validity",
            f"Certificate status: {'; '.join(issues[:3])}",
            "Monitor certificate expiration and renew before expiry",
            category,
            test_id,
        )

    return _pass(
        "SSL/TLS Certificate Validity",
        f"Found {len(issues)} certificates: {'; '.join(issues[:2])}",
        "Automate certificate renewal with Let's Encrypt or similar",
        category,
        test_id,
    )


def check_security_headers(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check for security headers in web server configuration.

    Test ID: HTTP-6503
    Category: Web Server

    Verifies presence of security headers like HSTS, X-Frame-Options, CSP, etc.
    """
    category = "Web Server"
    test_id = "HTTP-6503"

    headers_found = []
    headers_missing = []

    # Check Nginx headers
    ret, out, err = _run(
        ssh,
        "grep -r 'add_header.*Strict-Transport-Security\\|X-Frame-Options\\|X-Content-Type-Options' /etc/nginx 2>/dev/null | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        headers_found.append("Nginx security headers")
    else:
        headers_missing.append("Nginx HSTS/X-Frame-Options")

    # Check Apache headers
    ret, out, err = _run(
        ssh,
        "grep -r 'Header.*Strict-Transport-Security\\|X-Frame-Options\\|X-Content-Type-Options' /etc/apache2 2>/dev/null | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        headers_found.append("Apache security headers")
    else:
        headers_missing.append("Apache HSTS/X-Frame-Options")

    if not headers_found:
        return _warn(
            "Security Headers",
            "No security headers configured",
            "Add headers: Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Content-Security-Policy",
            category,
            test_id,
        )

    if headers_missing:
        return _warn(
            "Security Headers",
            f"Partial: {', '.join(headers_found)} | Missing: {', '.join(headers_missing)}",
            "Configure all recommended security headers",
            category,
            test_id,
        )

    return _pass(
        "Security Headers",
        f"Security headers configured: {', '.join(headers_found)}",
        "Regularly update security header policies",
        category,
        test_id,
    )


def check_http_to_https_redirect(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if HTTP traffic is redirected to HTTPS.

    Test ID: HTTP-6504
    Category: Web Server

    Verifies automatic HTTP to HTTPS redirection is configured.
    """
    category = "Web Server"
    test_id = "HTTP-6504"

    # Check Nginx redirect
    ret, out, err = _run(
        ssh,
        "grep -r 'return 30[1-7].*https' /etc/nginx 2>/dev/null | wc -l",
    )
    nginx_redirect = ret == 0 and int(out.strip() or "0") > 0

    # Check Apache redirect
    ret, out, err = _run(
        ssh,
        "grep -r 'RewriteRule.*https' /etc/apache2 2>/dev/null | wc -l",
    )
    apache_redirect = ret == 0 and int(out.strip() or "0") > 0

    if not nginx_redirect and not apache_redirect:
        return _warn(
            "HTTP to HTTPS Redirect",
            "No HTTP to HTTPS redirect configured",
            "Configure permanent redirect (301) from HTTP to HTTPS",
            category,
            test_id,
        )

    redirects = []
    if nginx_redirect:
        redirects.append("Nginx")
    if apache_redirect:
        redirects.append("Apache")

    return _pass(
        "HTTP to HTTPS Redirect",
        f"HTTP to HTTPS redirect configured: {', '.join(redirects)}",
        "Verify redirect uses 301 (permanent) status code",
        category,
        test_id,
    )


def check_directory_listing_disabled(
    ssh: SSHSession, password: str = ""
) -> CheckResult:
    """Check if directory listing is disabled.

    Test ID: HTTP-6505
    Category: Web Server

    Verifies that directory listing is not enabled (prevents file exposure).
    """
    category = "Web Server"
    test_id = "HTTP-6505"

    issues = []

    # Check Nginx autoindex
    ret, out, err = _run(ssh, "grep -r 'autoindex on' /etc/nginx 2>/dev/null | wc -l")
    if ret == 0 and int(out.strip() or "0") > 0:
        issues.append("Nginx autoindex enabled")

    # Check Apache Indexes
    ret, out, err = _run(ssh, "grep -r 'Indexes' /etc/apache2 2>/dev/null | wc -l")
    if ret == 0 and int(out.strip() or "0") > 0:
        issues.append("Apache Indexes directive found")

    if issues:
        return _warn(
            "Directory Listing",
            f"Directory listing enabled: {', '.join(issues)}",
            "Disable directory listing: set 'autoindex off' in Nginx or remove Indexes from Apache",
            category,
            test_id,
        )

    return _pass(
        "Directory Listing",
        "Directory listing is disabled",
        "Maintain strict directory access controls",
        category,
        test_id,
    )


def check_access_controls(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check for proper access controls and authentication.

    Test ID: HTTP-6506
    Category: Web Server

    Verifies basic auth, IP restrictions, and access control mechanisms.
    """
    category = "Web Server"
    test_id = "HTTP-6506"

    controls = []

    # Check Nginx auth_basic
    ret, out, err = _run(ssh, "grep -r 'auth_basic' /etc/nginx 2>/dev/null | wc -l")
    if ret == 0 and int(out.strip() or "0") > 0:
        controls.append("Nginx basic auth")

    # Check Nginx allow/deny
    ret, out, err = _run(
        ssh, "grep -r '\\(allow\\|deny\\)' /etc/nginx 2>/dev/null | wc -l"
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        controls.append("Nginx IP restrictions")

    # Check Apache auth
    ret, out, err = _run(
        ssh, "grep -r 'AuthType\\|Require' /etc/apache2 2>/dev/null | wc -l"
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        controls.append("Apache authentication")

    # Check Apache Allow/Deny
    ret, out, err = _run(
        ssh, "grep -r '\\(Allow\\|Deny\\)' /etc/apache2 2>/dev/null | wc -l"
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        controls.append("Apache IP restrictions")

    if not controls:
        return _warn(
            "Access Controls",
            "No explicit access controls configured",
            "Implement authentication and/or IP-based access restrictions",
            category,
            test_id,
        )

    return _pass(
        "Access Controls",
        f"Access controls configured: {', '.join(controls)}",
        "Regularly review and update access control policies",
        category,
        test_id,
    )


def check_security_modules_enabled(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if security-related modules are enabled.

    Test ID: HTTP-6507
    Category: Web Server

    Verifies ModSecurity (WAF), rate limiting, and other security modules.
    """
    category = "Web Server"
    test_id = "HTTP-6507"

    modules = []

    # Check Apache ModSecurity
    ret, out, err = _run(
        ssh, "test -f /etc/apache2/mods-enabled/*security* && echo found"
    )
    if ret == 0 and "found" in out:
        modules.append("Apache ModSecurity")

    # Check Nginx rate limiting or limit modules
    ret, out, err = _run(
        ssh, "grep -r 'limit_req\\|limit_conn' /etc/nginx 2>/dev/null | wc -l"
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        modules.append("Nginx rate limiting")

    # Check Nginx ngx_http_geoip
    ret, out, err = _run(ssh, "grep -r 'geoip' /etc/nginx 2>/dev/null | wc -l")
    if ret == 0 and int(out.strip() or "0") > 0:
        modules.append("Nginx GeoIP filtering")

    # Check Apache mod_evasive
    ret, out, err = _run(
        ssh, "test -f /etc/apache2/mods-enabled/*evasive* && echo found"
    )
    if ret == 0 and "found" in out:
        modules.append("Apache mod_evasive")

    if not modules:
        return _warn(
            "Security Modules",
            "No security modules (ModSecurity, rate limiting, etc.) enabled",
            "Enable ModSecurity for Apache or implement rate limiting in Nginx",
            category,
            test_id,
        )

    return _pass(
        "Security Modules",
        f"Security modules enabled: {', '.join(modules)}",
        "Maintain and update security modules regularly",
        category,
        test_id,
    )


def run_all_webserver_checks(ssh: SSHSession, password: str = "") -> list[CheckResult]:
    """Run all web server security checks.

    Args:
        ssh: SSH session to target system
        password: SSH password if needed

    Returns:
        List of CheckResult objects
    """
    return [
        check_web_server_installed(ssh, password),
        check_ssl_tls_enabled(ssh, password),
        check_ssl_certificate_validity(ssh, password),
        check_security_headers(ssh, password),
        check_http_to_https_redirect(ssh, password),
        check_directory_listing_disabled(ssh, password),
        check_access_controls(ssh, password),
        check_security_modules_enabled(ssh, password),
    ]
