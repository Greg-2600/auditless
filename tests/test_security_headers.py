"""Browser isolation headers on the Auditless dashboard and API."""

from __future__ import annotations

import urllib.request

REQUIRED_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def _headers(client, path: str) -> dict[str, str]:
    """Fetch raw response headers for a path on the live test server."""
    request = urllib.request.Request(client.base_url + path, method="GET")
    with urllib.request.urlopen(request, timeout=client.timeout) as response:
        return {k: v for k, v in response.headers.items()}


def test_healthz_sets_security_headers(client) -> None:
    """Liveness probe carries the standard isolation headers."""
    headers = {k.lower(): v for k, v in _headers(client, "/healthz").items()}
    for name, value in REQUIRED_HEADERS.items():
        assert headers[name.lower()] == value, name
    assert "camera=()" in headers["permissions-policy"]
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def _directives(csp: str) -> dict[str, list[str]]:
    """Split a CSP header into directive name to source token lists."""
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.split()
        if tokens:
            directives[tokens[0]] = tokens[1:]
    return directives


def test_index_and_docs_set_security_headers(client) -> None:
    """SPA and Swagger UI get the same headers, including a CSP that allows docs assets."""
    for path in ("/", "/docs"):
        headers = {k.lower(): v for k, v in _headers(client, path).items()}
        assert headers["x-frame-options"] == "DENY"
        assert headers["x-content-type-options"] == "nosniff"
        script_sources = _directives(headers["content-security-policy"])["script-src"]
        assert any(
            source == "https://cdn.jsdelivr.net" for source in script_sources
        ), script_sources
