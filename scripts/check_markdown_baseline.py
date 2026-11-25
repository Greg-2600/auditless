"""Check markdownlint results against the checked in baseline."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / ".markdownlint-baseline.json"
FINDING = re.compile(
    r"^(?P<file>[^:\r\n]+):(?P<line>\d+)(?::(?P<column>\d+))? "
    r"error (?P<rule>MD\d{3})/"
)

Finding = tuple[str, str, int]


def parse_findings(output: str) -> set[Finding]:
    findings: set[Finding] = set()
    for line in output.splitlines():
        match = FINDING.match(line)
        if match:
            findings.add((match.group("file"), match.group("rule"), int(match.group("line"))))
    return findings


def load_baseline(path: pathlib.Path = BASELINE) -> set[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        (file_name, rule, line)
        for file_name, rules in data["findings"].items()
        for rule, lines in rules.items()
        for line in lines
    }


def write_baseline(findings: Iterable[Finding], path: pathlib.Path = BASELINE) -> None:
    grouped: dict[str, dict[str, list[int]]] = {}
    for file_name, rule, line in sorted(findings):
        grouped.setdefault(file_name, {}).setdefault(rule, []).append(line)
    payload = {"version": 1, "findings": grouped}
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="rewrite the baseline")
    options = parser.parse_args()

    result = subprocess.run(
        ["markdownlint-cli2"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode == 2:
        return 2

    current = parse_findings(result.stdout + result.stderr)
    if options.update:
        write_baseline(current)
        print(f"Baseline updated with {len(current)} findings")
        return 0

    baseline = load_baseline()
    resolved = baseline - current
    new = current - baseline
    if resolved:
        print(f"{len(resolved)} baseline findings resolved, refresh the baseline")
    for file_name, rule, line in sorted(new):
        print(f"NEW {file_name}:{line} {rule}", file=sys.stderr)
    if new:
        print(f"{len(new)} new markdownlint findings", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
