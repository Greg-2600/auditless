"""First-party HTTP client for the Auditless API.

Thin stdlib wrapper (urllib, no extra dependencies) over every documented
endpoint. The test suite talks to the app exclusively through this client
so the public API surface stays honest: if the client cannot do it, users
cannot do it either.

Example:
    >>> client = ApiClient("http://127.0.0.1:8080")
    >>> client.health()
    {'status': 'ok'}
    >>> job = client.start_scan(hostname="web-01", username="root",
    ...                         password="s3cr3t")
    >>> done = client.wait_for(job["id"])
    >>> done["report"]["summary"]["hardening_index"]
    82
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class ApiError(Exception):
    """HTTP error from the Auditless API (carries status code and body)."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"API error {status}: {body[:300]}")
        self.status = status
        self.body = body


class ApiClient:
    """Typed client for every Auditless API endpoint."""

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> Any:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ApiError(0, f"refusing non-HTTP(S) URL scheme: {scheme!r}")
        data: bytes | None = None
        headers: dict[str, str] = {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                content_type = response.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    return json.loads(body)
                return body
        except urllib.error.HTTPError as exc:
            raise ApiError(exc.code, exc.read().decode("utf-8", "replace")) from exc

    def health(self) -> dict[str, Any]:
        """Liveness probe (GET /healthz)."""
        result: dict[str, Any] = self._request("GET", "/healthz")
        return result

    def version(self) -> dict[str, Any]:
        """Scanner + API version metadata (GET /api/version)."""
        result: dict[str, Any] = self._request("GET", "/api/version")
        return result

    def openapi_spec(self) -> dict[str, Any]:
        """Machine-readable schema (GET /openapi.json)."""
        result: dict[str, Any] = self._request("GET", "/openapi.json")
        return result

    def list_scans(self) -> list[dict[str, Any]]:
        """Recent scan jobs, newest first (GET /api/scans)."""
        result: list[dict[str, Any]] = self._request("GET", "/api/scans")
        return result

    def start_scan(
        self, hostname: str, username: str, password: str, **options: Any
    ) -> dict[str, Any]:
        """Start a scan; returns the job record (HTTP 201).

        Raises:
            ApiError: 422 when credentials are missing/invalid.
        """
        payload: dict[str, Any] = {
            "hostname": hostname,
            "username": username,
            "password": password,
            **options,
        }
        result: dict[str, Any] = self._request("POST", "/api/scans", payload)
        return result

    def get_scan(self, job_id: str) -> dict[str, Any]:
        """Job status; includes the full report once done."""
        result: dict[str, Any] = self._request("GET", f"/api/scans/{job_id}")
        return result

    def delete_scan(self, job_id: str) -> dict[str, Any]:
        """Forget a job record."""
        result: dict[str, Any] = self._request("DELETE", f"/api/scans/{job_id}")
        return result

    def get_report(
        self, job_id: str, format: str = "json"  # pylint: disable=redefined-builtin
    ) -> Any:
        """Finished report as dict (json) or string (md/text).

        Raises:
            ApiError: 400 for unknown formats, 409 while the scan runs.
        """
        return self._request(
            "GET", f"/api/scans/{job_id}/report", params={"format": format}
        )

    def list_profiles(self) -> list[dict[str, Any]]:
        """Scan profiles discovered on the server (GET /api/profiles)."""
        result: list[dict[str, Any]] = self._request("GET", "/api/profiles")
        return result

    def wait_for(
        self, job_id: str, deadline: float = 30.0, interval: float = 0.3
    ) -> dict[str, Any]:
        """Poll until a job reaches done/error.

        Raises:
            TimeoutError: If the deadline passes first.
        """
        end = time.time() + deadline
        while time.time() < end:
            job = self.get_scan(job_id)
            if job["status"] in ("done", "error"):
                return job
            time.sleep(interval)
        raise TimeoutError(f"scan {job_id} did not finish within {deadline}s")
