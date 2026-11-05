"""Wall-time benchmark: sequential vs parallel core-check suite.

Uses a latency-injecting fake SSH session (no network) over the REAL
55-thunk suite, so the comparison isolates orchestration overhead from
target speed. Stdlib only.

    .venv/bin/python scripts/bench_checks.py [--latency 0.05] [--jobs 8]
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from linux_health.checks import (  # noqa: E402
    disable_command_cache,
    run_all_checks,
    run_all_checks_parallel,
)
from linux_health.ssh_client import SSHSession  # noqa: E402


class LatencySSH(SSHSession):
    """Fake session: every remote command costs `latency` seconds."""

    def __init__(self, latency: float) -> None:
        super().__init__("bench", "bench", "")
        self.latency = latency
        self.calls = 0

    def run(self, command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        time.sleep(self.latency)
        self.calls += 1
        return 0, "test output", ""


def _time(fn: object, *args: object, repeats: int = 3) -> float:
    samples: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        result = fn(*args)  # type: ignore[operator]
        samples.append(time.perf_counter() - start)
        assert result, "suite returned no results"
    return statistics.median(samples)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--latency", type=float, default=0.05)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()

    disable_command_cache()  # measure execution, not cache hits
    seq = _time(run_all_checks, LatencySSH(args.latency), repeats=args.repeats)
    par = _time(
        run_all_checks_parallel,
        LatencySSH(args.latency),
        "",
        args.jobs,
        repeats=args.repeats,
    )
    total = len(run_all_checks(LatencySSH(0.0)))
    print(f"checks in suite : {total}")
    print(f"per-call latency: {args.latency * 1000:.0f}ms (simulated RTT)")
    print(f"sequential      : {seq:.2f}s")
    print(f"parallel({args.jobs})   : {par:.2f}s")
    print(f"speedup         : {seq / par:.1f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
