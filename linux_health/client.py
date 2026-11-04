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

    def __init__(
        self, base_url: str, timeout: float = 10.0, token: str | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = token

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
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
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
        self,
        hostname: str = "",
        username: str = "",
        password: str = "",
        host_id: str | None = None,
        **options: Any,
    ) -> dict[str, Any]:
        """Start a scan; returns the job record (HTTP 201).

        Either hostname/username/password or host_id (saved host; password
        still per-request unless the host uses stored key auth).

        Raises:
            ApiError: 400/404/422 for bad requests.
        """
        payload: dict[str, Any] = {
            "hostname": hostname,
            "username": username,
            "password": password,
            **options,
        }
        if host_id:
            payload["host_id"] = host_id
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

    def create_host(
        self,
        name: str,
        hostname: str,
        username: str,
        port: int = 22,
        auth: str = "password",
    ) -> dict[str, Any]:
        """Register a host (POST /api/hosts)."""
        result: dict[str, Any] = self._request(
            "POST",
            "/api/hosts",
            {
                "name": name,
                "hostname": hostname,
                "username": username,
                "port": port,
                "auth": auth,
            },
        )
        return result

    def list_hosts(self) -> list[dict[str, Any]]:
        """Saved hosts, metadata only (GET /api/hosts)."""
        result: list[dict[str, Any]] = self._request("GET", "/api/hosts")
        return result

    def get_host(self, host_id: str) -> dict[str, Any]:
        """Fetch one host (GET /api/hosts/{id})."""
        result: dict[str, Any] = self._request("GET", f"/api/hosts/{host_id}")
        return result

    def update_host(self, host_id: str, **fields: Any) -> dict[str, Any]:
        """Partial host update (PATCH /api/hosts/{id})."""
        result: dict[str, Any] = self._request("PATCH", f"/api/hosts/{host_id}", fields)
        return result

    def delete_host(self, host_id: str) -> dict[str, Any]:
        """Delete a host and its key (DELETE /api/hosts/{id})."""
        result: dict[str, Any] = self._request("DELETE", f"/api/hosts/{host_id}")
        return result

    def put_host_key(self, host_id: str, key_text: str) -> dict[str, Any]:
        """Store key bytes (write-only; PUT /api/hosts/{id}/key)."""
        result: dict[str, Any] = self._request(
            "PUT", f"/api/hosts/{host_id}/key", {"key": key_text}
        )
        return result

    def get_host_key(self, host_id: str) -> dict[str, Any]:
        """Key presence only; the key itself is never returned."""
        result: dict[str, Any] = self._request("GET", f"/api/hosts/{host_id}/key")
        return result

    def delete_host_key(self, host_id: str) -> dict[str, Any]:
        """Remove stored key bytes (DELETE /api/hosts/{id}/key)."""
        result: dict[str, Any] = self._request("DELETE", f"/api/hosts/{host_id}/key")
        return result

    def list_reports(
        self, host_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Persisted reports, newest first (GET /api/reports)."""
        params = {"limit": str(limit)}
        if host_id:
            params["host_id"] = host_id
        result: list[dict[str, Any]] = self._request(
            "GET", "/api/reports", params=params
        )
        return result

    def get_stored_report(self, report_id: str) -> dict[str, Any]:
        """Full persisted report (GET /api/reports/{id})."""
        result: dict[str, Any] = self._request("GET", f"/api/reports/{report_id}")
        return result

    def delete_stored_report(self, report_id: str) -> dict[str, Any]:
        """Forget a persisted report (DELETE /api/reports/{id})."""
        result: dict[str, Any] = self._request("DELETE", f"/api/reports/{report_id}")
        return result

    def diff_reports(self, from_id: str, to_id: str) -> dict[str, Any]:
        """Check-by-check progress between two reports (GET /api/diff)."""
        result: dict[str, Any] = self._request(
            "GET", "/api/diff", params={"from_id": from_id, "to_id": to_id}
        )
        return result

    def create_schedule(
        self, host_id: str, name: str, cron: str, **options: Any
    ) -> dict[str, Any]:
        """Create an unattended scan schedule (POST /api/schedules)."""
        payload: dict[str, Any] = {
            "host_id": host_id,
            "name": name,
            "cron": cron,
            **options,
        }
        result: dict[str, Any] = self._request("POST", "/api/schedules", payload)
        return result

    def list_schedules(self) -> list[dict[str, Any]]:
        """Scan schedules, webhook URLs never included (GET /api/schedules)."""
        result: list[dict[str, Any]] = self._request("GET", "/api/schedules")
        return result

    def get_schedule(self, schedule_id: str) -> dict[str, Any]:
        """Fetch one schedule (GET /api/schedules/{id})."""
        result: dict[str, Any] = self._request("GET", f"/api/schedules/{schedule_id}")
        return result

    def update_schedule(self, schedule_id: str, **fields: Any) -> dict[str, Any]:
        """Partial schedule update (PATCH /api/schedules/{id})."""
        result: dict[str, Any] = self._request(
            "PATCH", f"/api/schedules/{schedule_id}", fields
        )
        return result

    def delete_schedule(self, schedule_id: str) -> dict[str, Any]:
        """Remove a schedule (DELETE /api/schedules/{id})."""
        result: dict[str, Any] = self._request(
            "DELETE", f"/api/schedules/{schedule_id}"
        )
        return result

    def run_schedule_now(self, schedule_id: str) -> dict[str, Any]:
        """Trigger a scheduled scan immediately (POST .../run)."""
        result: dict[str, Any] = self._request(
            "POST", f"/api/schedules/{schedule_id}/run"
        )
        return result

    def host_trend(self, host_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Hardening-index history for charting (GET /api/hosts/{id}/trend)."""
        result: list[dict[str, Any]] = self._request(
            "GET", f"/api/hosts/{host_id}/trend", params={"limit": str(limit)}
        )
        return result

    def fleet(self) -> list[dict[str, Any]]:
        """Latest score per saved host (GET /api/fleet)."""
        result: list[dict[str, Any]] = self._request("GET", "/api/fleet")
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
