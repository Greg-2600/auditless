"""Per-IP rate limits on scan-start and token-mint endpoints."""

from __future__ import annotations

import pytest

from auditless import dashboard
from auditless.client import ApiError


def test_token_mint_returns_429_and_retry_after(client, monkeypatch) -> None:
    """The fourth token mint in a tightened window is rejected."""
    monkeypatch.setattr(dashboard, "RATE_LIMIT_MAX", 3)
    monkeypatch.setattr(dashboard, "RATE_LIMIT_WINDOW_SEC", 60.0)
    dashboard.clear_rate_limit()

    for index in range(3):
        created = client.create_token(f"limit-{index}")
        assert "id" in created

    with pytest.raises(ApiError) as excinfo:
        client.create_token("limit-overflow")
    assert excinfo.value.status == 429
    assert "rate limit exceeded" in excinfo.value.body


def test_token_mint_retry_after_header(client, monkeypatch) -> None:
    """429 responses include a Retry-After header of at least one second."""
    import urllib.error
    import urllib.request

    monkeypatch.setattr(dashboard, "RATE_LIMIT_MAX", 2)
    monkeypatch.setattr(dashboard, "RATE_LIMIT_WINDOW_SEC", 60.0)
    dashboard.clear_rate_limit()
    client.create_token("one")
    client.create_token("two")

    request = urllib.request.Request(
        client.base_url + "/api/tokens",
        data=b'{"name": "three"}',
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, timeout=client.timeout)
    assert excinfo.value.code == 429
    retry_after = int(excinfo.value.headers.get("Retry-After", "0"))
    assert retry_after >= 1
    assert retry_after <= 61


def test_healthz_is_not_rate_limited(client, monkeypatch) -> None:
    """Liveness stays available after the token bucket is exhausted."""
    monkeypatch.setattr(dashboard, "RATE_LIMIT_MAX", 1)
    dashboard.clear_rate_limit()
    client.create_token("only")
    with pytest.raises(ApiError) as excinfo:
        client.create_token("blocked")
    assert excinfo.value.status == 429
    assert client.health() == {"status": "ok"}
