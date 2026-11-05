#!/usr/bin/env python3
"""Fleet benchmark: sequential scans vs one parallel fleet call.

Boots N throwaway OpenSSH servers + the app image on one Docker network,
times N sequential POST /api/scans against a single POST /api/fleet/scan,
and prints the speedup. Manual use (not CI)::

    python scripts/bench_fleet.py [targets=3]

Requires a working docker daemon + ssh-keygen. Tears everything down.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from linux_health.client import ApiClient  # noqa: E402

SSH_IMAGE = "lscr.io/linuxserver/openssh-server:latest"
NETWORK = "auditless-bench-net"
APP = "auditless-bench-app"


def docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=True)


def main(targets: int = 3) -> None:
    workdir = Path(tempfile.mkdtemp(prefix="bench-"))
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "bench",
            "-f",
            str(workdir / "key"),
        ],
        check=True,
        capture_output=True,
    )
    pub = (workdir / "key.pub").read_text().strip()
    names = [f"auditless-bench-{i}" for i in range(targets)]
    docker("network", "create", NETWORK)
    try:
        docker("pull", SSH_IMAGE)
        for name in names:
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                NETWORK,
                "-e",
                "USER_NAME=tester",
                "-e",
                "USER_PASSWORD=benchpw",
                "-e",
                "PASSWORD_ACCESS=true",
                "-e",
                f"PUBLIC_KEY={pub}",
                SSH_IMAGE,
            )
        docker("build", "-t", "auditless:bench", ".")
        docker(
            "run",
            "-d",
            "--name",
            APP,
            "--network",
            NETWORK,
            "-p",
            "127.0.0.1:18088:8080",
            "-e",
            "AUDITLESS_DATA_DIR=/app/data",
            "auditless:bench",
            "--serve",
            "--serve-host",
            "0.0.0.0",
        )
        api = ApiClient("http://127.0.0.1:18088", timeout=60.0)
        end = time.time() + 120
        while time.time() < end:
            try:
                api.health()
                break
            except Exception:
                time.sleep(1)
        hosts = [
            api.create_host(f"bench-{i}", name, "tester", port=2222, auth="password")
            for i, name in enumerate(names)
        ]
        ids = [h["id"] for h in hosts]

        start = time.time()
        for hid in ids:
            job = api.start_scan(host_id=hid, password="benchpw")
            done = api.wait_for(job["id"], deadline=600, interval=5.0)
            assert done["status"] == "done", done.get("error")
        sequential = time.time() - start

        start = time.time()
        launched = api.fleet_scan(
            host_ids=ids, password="benchpw", max_concurrent=targets
        )
        assert len(launched["jobs"]) == targets
        for entry in launched["jobs"]:
            done = api.wait_for(entry["job_id"], deadline=600, interval=5.0)
            assert done["status"] == "done", done.get("error")
        parallel = time.time() - start

        print(f"targets:    {targets}")
        print(f"sequential: {sequential:.1f}s")
        print(f"parallel:   {parallel:.1f}s")
        print(f"speedup:    {sequential / max(parallel, 0.01):.1f}x")
    finally:
        docker("rm", "-f", APP, *names)
        docker("network", "rm", NETWORK)


if __name__ == "__main__":
    main(int(sys.argv[1])) if len(sys.argv) > 1 else main()
