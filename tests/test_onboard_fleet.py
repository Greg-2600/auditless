"""Tests for the ops/onboard_fleet.py helper (public API only)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "ops" / "onboard_fleet.py"


@pytest.fixture()
def helper() -> Any:
    """Import the script as a module without making ops/ a package."""
    spec = importlib.util.spec_from_file_location("onboard_fleet", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeClient:
    """Minimal in-memory stand-in for ApiClient."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.hosts: list[dict[str, Any]] = []
        self.scans: list[dict[str, Any]] = []

    def health(self) -> dict[str, str]:
        return {"status": "ok"}

    def list_hosts(self) -> list[dict[str, Any]]:
        return list(self.hosts)

    def create_host(
        self,
        name: str,
        hostname: str,
        username: str,
        port: int = 22,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        host = {
            "id": f"h{len(self.hosts) + 1}",
            "name": name,
            "hostname": hostname,
            "username": username,
            "port": port,
        }
        self.hosts.append(host)
        return host

    def start_scan(
        self,
        hostname: str = "",
        username: str = "",
        password: str = "",
        host_id: str | None = None,
        **options: Any,
    ) -> dict[str, Any]:
        job = {
            "id": f"j{len(self.scans) + 1}",
            "hostname": hostname,
            "username": username,
            "password": password,
            "host_id": host_id,
            "options": options,
        }
        self.scans.append(job)
        return {"id": job["id"]}

    def wait_for(
        self, job_id: str, deadline: float = 30.0, interval: float = 0.3
    ) -> dict[str, Any]:
        return {
            "id": job_id,
            "status": "done",
            "report": {
                "summary": {
                    "hardening_index": 70,
                    "passed": 5,
                    "warned": 2,
                    "failed": 1,
                    "unknown": 0,
                }
            },
        }


@pytest.fixture()
def fake_client(monkeypatch: pytest.MonkeyPatch, helper: Any) -> FakeClient:
    client = FakeClient()
    monkeypatch.setattr(helper, "ApiClient", lambda *_a, **_k: client)
    return client


TSV = (
    "name\thostname\tport\tusername\tpassword\tnotes\n"
    "web-01\t192.0.2.10\t22\toperator\t\tweb\n"
    "db-01\t192.0.2.20\t2222\toperator\t\tdb\n"
)


def _inventory(tmp_path: Path, text: str = TSV, name: str = "hosts.tsv") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_read_inventory_tsv_and_csv(helper: Any, tmp_path: Path) -> None:
    rows = helper.read_inventory(_inventory(tmp_path))
    assert [row["name"] for row in rows] == ["web-01", "db-01"]
    assert rows[1]["port"] == "2222"
    assert rows[0]["port"] == "22"

    csv = _inventory(
        tmp_path,
        "name,hostname,username\nedge-01,192.0.2.30,root\n",
        "hosts.csv",
    )
    rows = helper.read_inventory(csv)
    assert rows == [
        {"name": "edge-01", "hostname": "192.0.2.30", "username": "root", "port": "22"}
    ]


def test_read_inventory_rejects_empty_file(helper: Any, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="empty"):
        helper.read_inventory(_inventory(tmp_path, "", "empty.tsv"))


def test_password_precedence(
    helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "pw"
    secret_file.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("AUDITLESS_FLEET_PASSWORD", "from-env")
    args = helper.parse_args(["--password-file", str(secret_file)])
    row = {"password": ""}

    assert helper.read_password(args, row) == "from-file"
    assert (
        helper.read_password(helper.parse_args(["--password", "from-arg"]), row)
        == "from-arg"
    )
    assert helper.read_password(helper.parse_args([]), row) == "from-env"
    assert helper.read_password(args, {"password": "from-row"}) == "from-row"


def test_register_only_is_idempotent(
    helper: Any,
    fake_client: FakeClient,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inv = _inventory(tmp_path)
    argv = ["--inventory", str(inv), "--register-only"]
    assert helper.main(argv) == 0
    assert helper.main(argv) == 0

    out = capsys.readouterr().out
    assert "already" in out
    assert [host["hostname"] for host in fake_client.hosts] == [
        "192.0.2.10",
        "192.0.2.20",
    ]
    assert fake_client.scans == []


def test_scan_only_writes_summary_without_password(
    helper: Any, fake_client: FakeClient, tmp_path: Path
) -> None:
    inv = _inventory(tmp_path)
    out = tmp_path / "summary.json"
    assert (
        helper.main(
            [
                "--inventory",
                str(inv),
                "--scan-only",
                "--password",
                "SENTINEL-PW",
                "--out",
                str(out),
            ]
        )
        == 0
    )

    assert len(fake_client.scans) == 2
    assert all(scan["password"] == "SENTINEL-PW" for scan in fake_client.scans)
    payload = out.read_text(encoding="utf-8")
    assert "SENTINEL-PW" not in payload
    rows = json.loads(payload)
    assert [row["hardening_index"] for row in rows] == [70, 70]
    assert rows[0]["name"] == "web-01"


def test_name_filter_and_missing_username_skip(
    helper: Any,
    fake_client: FakeClient,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inv = _inventory(
        tmp_path,
        "name,hostname,username\nweb-01,192.0.2.10,operator\nghost,192.0.2.99,\n",
        "hosts.csv",
    )
    assert (
        helper.main(["--inventory", str(inv), "--register-only", "--name", "web-01"])
        == 0
    )
    assert [host["name"] for host in fake_client.hosts] == ["web-01"]

    assert helper.main(["--inventory", str(inv), "--register-only"]) == 0
    out = capsys.readouterr().out
    assert "set the username column first" in out
    # web-01 is matched idempotently; ghost has no username and is skipped.
    assert [host["name"] for host in fake_client.hosts] == ["web-01"]


def test_conflicting_modes_rejected(helper: Any) -> None:
    assert helper.main(["--register-only", "--scan-only"]) == 2
