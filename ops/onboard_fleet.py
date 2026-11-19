#!/usr/bin/env python3
"""Onboard a fleet of SSH hosts into a running Auditless server.

The inventory is a TSV/CSV with these columns (header required):

    name      unique label shown in the dashboard (e.g. prod-web-01)
    hostname  IP or DNS name
    port      SSH port (default 22)
    username  SSH user
    password  SSH password (optional if --password/--password-file given)
    notes     free-form (optional)

Examples:
    # Register hosts and run one baseline scan each
    python ops/onboard_fleet.py --inventory inventory.tsv

    # Register only (scan later from the UI)
    python ops/onboard_fleet.py --inventory inventory.tsv --register-only

    # Scan an already-registered subset
    python ops/onboard_fleet.py --inventory inventory.tsv \
        --scan-only --name web-01 --name db-01

    # Shared credentials for every row
    python ops/onboard_fleet.py --inventory inventory.tsv \
        --password-file ~/.auditless-fleet-password

The script talks to the public API only (linux_health.client.ApiClient), so
anything it can do is a supported operation. Passwords are held in memory for
the request; they are never written to the inventory, output, or server store.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ruff: noqa: E402  (sys.path is prepared above)
# pylint: disable=import-error
from linux_health.client import ApiClient, ApiError

# pylint: enable=import-error

DEFAULT_API = "http://127.0.0.1:8080"
DEFAULT_INVENTORY = ROOT / "ops" / "fleet.tsv"
REQUIRED = ("name", "hostname")


def read_inventory(path: Path) -> list[dict[str, str]]:
    """Read TSV/CSV rows, normalising headers and defaults."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        raise ValueError(f"{path}: inventory is empty (a header row is required)")
    delimiter = "\t" if "\t" in lines[0] else ","
    rows: list[dict[str, str]] = []
    for raw in csv.DictReader(text.splitlines(), delimiter=delimiter):
        row = {str(k).strip().lower(): (v or "").strip() for k, v in raw.items()}
        if not any(row.values()):
            continue
        missing = [key for key in REQUIRED if not row.get(key)]
        if missing:
            raise ValueError(f"{path}: row {row} is missing {', '.join(missing)}")
        row.setdefault("port", "22")
        row["port"] = row["port"] or "22"
        rows.append(row)
    return rows


def read_password(args: argparse.Namespace, row: dict[str, str]) -> str:
    """Per-row password, else shared --password/--password-file/env."""
    if row.get("password"):
        return row["password"]
    if args.password:
        return str(args.password)
    if args.password_file:
        return Path(args.password_file).read_text(encoding="utf-8").rstrip("\n")
    return os.environ.get("AUDITLESS_FLEET_PASSWORD", "")


def find_host(client: ApiClient, row: dict[str, str]) -> dict[str, Any] | None:
    """Match an existing saved host by hostname + username."""
    for host in client.list_hosts():
        if host["hostname"] == row["hostname"] and host["username"] == row["username"]:
            return host
    return None


def register(client: ApiClient, row: dict[str, str]) -> tuple[str, bool]:
    """Create the host if absent. Returns (host_id, created)."""
    existing = find_host(client, row)
    if existing:
        return str(existing["id"]), False
    host = client.create_host(
        name=row["name"],
        hostname=row["hostname"],
        username=row["username"],
        port=int(row["port"]),
    )
    return str(host["id"]), True


def scan(
    client: ApiClient, row: dict[str, str], password: str, timeout: float
) -> dict[str, Any]:
    """Run one baseline scan and return a summary row."""
    started = time.time()
    job = client.start_scan(
        hostname=row["hostname"],
        username=row["username"],
        password=password,
        port=int(row["port"]),
        command_timeout=90.0,
    )
    done = client.wait_for(job["id"], deadline=timeout)
    elapsed = round(time.time() - started, 1)
    report = done.get("report") or {}
    summary = report.get("summary") or {}
    return {
        "name": row["name"],
        "hostname": row["hostname"],
        "port": int(row["port"]),
        "status": done.get("status"),
        "hardening_index": summary.get("hardening_index"),
        "passed": summary.get("passed"),
        "warned": summary.get("warned"),
        "failed": summary.get("failed"),
        "unknown": summary.get("unknown"),
        "seconds": elapsed,
        "scan_id": job["id"],
        "error": done.get("error") or "",
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default=os.environ.get("AUDITLESS_API", DEFAULT_API))
    parser.add_argument("--token", default=os.environ.get("AUDITLESS_TOKEN", ""))
    parser.add_argument(
        "--inventory", type=Path, default=DEFAULT_INVENTORY, help="TSV/CSV inventory"
    )
    parser.add_argument(
        "--password", default="", help="Shared SSH password (prefer --password-file)"
    )
    parser.add_argument("--password-file", default="", help="File holding one password")
    parser.add_argument(
        "--register-only", action="store_true", help="Save hosts, skip scanning"
    )
    parser.add_argument(
        "--scan-only", action="store_true", help="Scan saved hosts, skip registration"
    )
    parser.add_argument(
        "--name",
        action="append",
        default=[],
        help="Only rows with this name (repeatable)",
    )
    parser.add_argument(
        "--timeout", type=float, default=300.0, help="Per-scan ceiling in seconds"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Summary JSON path (default: ops/baseline-<timestamp>.json)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point: register, scan, summarise."""
    args = parse_args(argv or sys.argv[1:])
    if args.register_only and args.scan_only:
        print("choose at most one of --register-only / --scan-only", file=sys.stderr)
        return 2

    rows = read_inventory(args.inventory)
    if args.name:
        wanted = set(args.name)
        rows = [row for row in rows if row["name"] in wanted]
    if not rows:
        print("no inventory rows selected", file=sys.stderr)
        return 2

    client = ApiClient(args.api, timeout=30.0, token=args.token or None)
    try:
        client.health()
    except (ApiError, OSError) as exc:
        print(f"server not reachable at {args.api}: {exc}", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = []
    failures = 0
    skipped = 0
    print(f"{'name':<18} {'host':<15} {'result':<10} {'index':>5}  detail")
    print("-" * 78)

    for row in rows:
        if not row.get("username"):
            skipped += 1
            print(
                f"{row['name']:<18} {row['hostname']:<15} "
                f"{'skip':<10} {'-':>5}  set the username column first"
            )
            continue
        password = read_password(args, row)
        host_id, created = ("", False)
        try:
            if not args.scan_only:
                host_id, created = register(client, row)
            if args.register_only:
                print(
                    f"{row['name']:<18} {row['hostname']:<15} "
                    f"{'saved' if created else 'already':<10} {'-':>5}"
                )
                continue
            if not password:
                raise ValueError("no password (set column, --password-file or env)")
            result = scan(client, row, password, args.timeout)
            results.append(result)
            index = result["hardening_index"]
            detail = (
                f"P{result['passed']} W{result['warned']} F{result['failed']} "
                f"U{result['unknown']} {result['seconds']}s"
            )
            if result["status"] != "done":
                failures += 1
                detail = result["error"] or "error"
            print(
                f"{row['name']:<18} {row['hostname']:<15} "
                f"{result['status']:<10} {str(index):>5}  {detail}"
            )
        except (ApiError, ValueError, TimeoutError, OSError) as exc:
            failures += 1
            results.append(
                {
                    "name": row["name"],
                    "hostname": row["hostname"],
                    "status": "error",
                    "error": str(exc),
                }
            )
            print(
                f"{row['name']:<18} {row['hostname']:<15} {'error':<10} "
                f"{'-':>5}  {exc}"
            )

    if results:
        out = args.out or (
            ROOT / "ops" / f"baseline-{time.strftime('%Y%m%d-%H%M%S')}.json"
        )
        out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"\nsummary: {out}")
    attempted = len(rows) - skipped
    print(f"done: {attempted - failures}/{attempted} ok, {skipped} skipped")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
