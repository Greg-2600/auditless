"""Selenium end-to-end tests against the real dashboard UI (headless Chrome).

These drive the served HTML/JS exactly as a user would: page load, scan
history, fleet table, and report rendering. They are skipped when Selenium
or a Chrome/Chromium browser is unavailable (Selenium Manager downloads
the driver on first use, so network is required once).

Seed data goes through the public HTTP API (ApiClient) with a stubbed
``run_scan`` so no real SSH target is needed; the browser then exercises
the read/render paths.
"""

import os
import shutil
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
import uvicorn

selenium = pytest.importorskip("selenium")

from linux_health import dashboard  # noqa: E402
from linux_health.client import ApiClient  # noqa: E402
from linux_health.dashboard import app  # noqa: E402
from selenium.webdriver import Chrome  # noqa: E402
from selenium.webdriver.chrome.options import Options  # noqa: E402
from selenium.webdriver.common.by import By  # noqa: E402
from selenium.webdriver.support import expected_conditions as EC  # noqa: E402
from selenium.webdriver.support.ui import WebDriverWait  # noqa: E402

WAIT_SECONDS = 15.0


def _canned_report() -> dict[str, Any]:
    """Minimal report shaped like render_report_json output."""
    return {
        "scan_info": {"scanner": "selenium-test"},
        "system": {
            "hostname": "web-01",
            "os": "TestOS",
            "kernel": "1.0",
            "uptime": "1d",
        },
        "summary": {
            "total_checks": 2,
            "passed": 1,
            "warned": 0,
            "failed": 1,
            "hardening_index": 50,
            "hardening_level": "POOR",
        },
        "hardening_by_category": {
            "Network": {
                "index": 50,
                "level": "POOR",
                "passed": 1,
                "warned": 0,
                "failed": 1,
                "total": 2,
            }
        },
        "checks": [
            {
                "test_id": "FIRE-4512",
                "category": "Network",
                "item": "Firewall",
                "status": "fail",
                "details": "off",
                "recommendation": "enable it",
            },
            {
                "test_id": "STOR-6310",
                "category": "Storage",
                "item": "Disk",
                "status": "pass",
                "details": "fine",
                "recommendation": "none",
            },
        ],
        "ports": {"scanned": 1, "open": 1, "open_ports": [{"port": 22}]},
    }


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _chrome_binary() -> str | None:
    """Locate a Chrome/Chromium binary, or None when absent."""
    for candidate in ("google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(candidate)
        if found:
            return found
    mac_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if os.path.exists(mac_path):
        return mac_path
    return None


@pytest.fixture()
def server(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[str, ApiClient]]:
    """Live uvicorn dashboard + API client, isolated per test."""
    monkeypatch.setenv("AUDITLESS_DATA_DIR", str(tmp_path / "data"))
    dashboard.reset_store()
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()
    port = _free_port()
    instance = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=instance.run, daemon=True)
    thread.start()
    api = ApiClient(f"http://127.0.0.1:{port}", timeout=30.0)
    end = time.time() + 15
    while time.time() < end:
        try:
            api.health()
            break
        except Exception:  # server still booting
            time.sleep(0.1)
    else:
        raise AssertionError("test server did not start")
    yield f"http://127.0.0.1:{port}", api
    instance.should_exit = True
    thread.join(timeout=10)
    dashboard.reset_store()
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()


@pytest.fixture()
def driver() -> Iterator[Chrome]:
    """Headless Chrome, or skip when no browser is available."""
    binary = _chrome_binary()
    if binary is None:
        pytest.skip("no Chrome/Chromium binary found")
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    try:
        browser = Chrome(options=options)
    except Exception as exc:  # e.g. driver download without network
        pytest.skip(f"could not start Chrome: {exc}")
    yield browser
    browser.quit()


def _assert_no_severe_console_errors(browser: Chrome) -> None:
    """Fail on page JS errors (e.g. inline-script syntax breaks all panels)."""
    severe: list[str] = [
        str(entry.get("message", ""))
        for entry in browser.get_log("browser")
        if entry.get("level") == "SEVERE"
    ]
    assert severe == [], f"browser console errors: {severe}"


def _seed_done_scan(api: ApiClient, monkeypatch: pytest.MonkeyPatch) -> str:
    """Stub run_scan, run one scan to done, return its job id."""

    def fake_run_scan(params: dict[str, Any]) -> dict[str, Any]:
        params["password"] = None  # mirror run_scan scrubbing
        return _canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    job = api.start_scan(hostname="web-01", username="root", password="pw")
    done = api.wait_for(job["id"])
    assert done["status"] == "done"
    return str(job["id"])


def test_index_loads_with_empty_state(
    driver: Chrome, server: tuple[str, ApiClient]
) -> None:
    """Landing page renders brand, scan form, and empty-state panels."""
    base_url, _api = server
    driver.get(base_url + "/")
    assert "Auditless" in driver.title
    assert driver.find_element(By.TAG_NAME, "h1").text == "Auditless"
    assert driver.find_element(By.ID, "go").is_displayed()
    wait = WebDriverWait(driver, WAIT_SECONDS)
    wait.until(EC.text_to_be_present_in_element((By.ID, "hist"), "no scans yet"))
    wait.until(EC.text_to_be_present_in_element((By.ID, "fleet"), "no saved hosts yet"))
    _assert_no_severe_console_errors(driver)


def test_scan_history_link_renders_report(
    driver: Chrome, server: tuple[str, ApiClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A finished scan appears in history; clicking it renders the report."""
    base_url, api = server
    _seed_done_scan(api, monkeypatch)
    driver.get(base_url + "/")
    wait = WebDriverWait(driver, WAIT_SECONDS)
    wait.until(EC.text_to_be_present_in_element((By.ID, "hist"), "web-01"))
    wait.until(EC.text_to_be_present_in_element((By.ID, "hist"), "50/100"))
    driver.find_element(By.CSS_SELECTOR, "#hist a").click()
    wait.until(EC.text_to_be_present_in_element((By.ID, "result"), "FIRE-4512"))
    result_text = driver.find_element(By.ID, "result").text
    assert "50/100" in result_text
    assert "Firewall" in result_text


def test_fleet_table_shows_saved_host(
    driver: Chrome, server: tuple[str, ApiClient]
) -> None:
    """Hosts created via the API appear in the UI fleet table."""
    base_url, api = server
    api.create_host("selenium-host", "10.9.9.9", "operator", auth="password")
    driver.get(base_url + "/")
    wait = WebDriverWait(driver, WAIT_SECONDS)
    wait.until(EC.text_to_be_present_in_element((By.ID, "fleet"), "selenium-host"))
    fleet_text = driver.find_element(By.ID, "fleet").text
    assert "10.9.9.9" in fleet_text
