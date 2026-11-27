"""Parity guard: every public API route has an ApiClient method.

The route table is introspected against the client's ``_request`` calls
(parsed from source with ast), so a new endpoint without a matching client
method fails immediately. No HTTP is performed.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

from auditless import dashboard
from auditless.client import ApiClient

# Intentional exclusions: the HTML UI and the interactive API docs.
# /openapi.json *is* covered by ApiClient.openapi_spec().
EXCLUDED_ROUTES = {"/", "/docs", "/docs/oauth2-redirect", "/redoc"}

_PARAM = re.compile(r"\{[^}]+\}")


def _normalize(path: str) -> str:
    return _PARAM.sub("{}", path)


def _constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_path(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("{}")
        return "".join(parts)
    return None


def _is_request_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr == "_request"


def _client_endpoints() -> set[tuple[str, str]]:
    source = Path(inspect.getfile(ApiClient)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    endpoints: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ClassDef) and node.name == "ApiClient"):
            continue
        for func in node.body:
            if not isinstance(func, ast.FunctionDef):
                continue
            for call in ast.walk(func):
                if not isinstance(call, ast.Call) or not _is_request_call(call):
                    continue
                if len(call.args) < 2:
                    continue
                verb = _constant(call.args[0])
                path = _literal_path(call.args[1])
                if verb and path:
                    endpoints.add((verb, _normalize(path)))
    return endpoints


def test_every_route_has_a_client_method() -> None:
    """A newly added route must ship with an ApiClient method on day one."""
    endpoints = _client_endpoints()
    missing: list[str] = []
    for route in dashboard.app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if not path or path in EXCLUDED_ROUTES:
            continue
        for verb in sorted(methods - {"HEAD", "OPTIONS"}):
            if (verb, _normalize(path)) not in endpoints:
                missing.append(f"{verb} {path}")
    assert not missing, "routes without ApiClient methods: " + ", ".join(missing)


def test_exclusions_are_real_routes() -> None:
    """Keep the allowlist honest so it cannot hide a removed route forever."""
    paths = {getattr(route, "path", None) for route in dashboard.app.routes}
    assert EXCLUDED_ROUTES <= paths


class _FakeResponse:
    def __init__(self, body: bytes, content_type: str = "application/json") -> None:
        self._body = body
        self.headers = {"Content-Type": content_type}

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def test_get_stored_report_rendered_uses_http(monkeypatch) -> None:
    """The stored-report re-render method hits the documented endpoint."""
    seen: dict[str, str] = {}

    def fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        return _FakeResponse(b"# rendered", "text/markdown")

    monkeypatch.setattr("auditless.client.urllib.request.urlopen", fake_urlopen)
    api = ApiClient("http://example.test")
    body = api.get_stored_report_rendered("r1", format="md")
    assert body == "# rendered"
    assert seen["method"] == "GET"
    assert seen["url"] == "http://example.test/api/reports/r1/report?format=md"
