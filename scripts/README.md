# 🛠️ Development & Testing Scripts

This directory contains utility scripts for Auditless development and testing.

## Scripts Overview

> **Note:** test IDs are now attached at runtime by the `CHECK_TEST_IDS`
> registry (`linux_health/test_ids.py`); no source patching is needed.

**Requirements:** Python 3.11+

### test_json_output.py
**Purpose:** Testing script for validating JSON output format and structure compliance.

**Usage:**
```bash
python scripts/test_json_output.py [options]
```

**Features:**
- Validate JSON output structure
- Test JSON schema compliance
- Verify required fields
- Performance testing
- For development/QA purposes only

**Requirements:** Python 3.11+

### bench_checks.py
**Purpose:** Hermetic core-suite benchmark + CI performance gate (stdlib only).

**Usage:**
```bash
# Manual timing with simulated 50ms RTT
.venv/bin/python scripts/bench_checks.py --latency 0.05 --jobs 8

# CI gate: fail unless parallel speedup reaches 2.0x
.venv/bin/python scripts/bench_checks.py --check 2.0
```

The gate asserts the sequential/parallel **ratio**, not absolute
seconds, so results are comparable across machines (no rotting
baseline, no shared-runner flake). It catches orchestration
regressions (serialized pools, per-scan serial overhead); deliberate
workload growth (more checks) is versioned, not gated.

### bench_fleet.py
**Purpose:** Manual fleet benchmark (sequential vs parallel fleet scans).

**Usage:**
```bash
python scripts/bench_fleet.py [targets=3]
```

Stays **manual**: it boots throwaway containers and pulls registry
images, which is too heavy and flaky for a per-PR gate. Run it
locally before fleet-scale changes; the per-PR gate is
`bench_checks.py --check` (above).

## Running During Development

```bash
# Run all development tests
python scripts/test_json_output.py
```

## Integration with Main Tests

These scripts are supplementary to the main test suite located in `/tests/`. For comprehensive testing, see:
- **Unit Tests:** `pytest tests/`
- **Code Quality:** `black --check linux_health/` and `ruff check linux_health/`
- **Coverage:** `pytest tests/ --cov=linux_health`

## Contributing

When adding new scripts:
1. Add docstrings explaining purpose and usage
2. Include error handling
3. Add to this README
4. Ensure compatibility with Python 3.11+
5. Follow Black and Pylint standards

For contribution guidelines, see [../.github/CONTRIBUTING.md](../.github/CONTRIBUTING.md)

---

**Note:** These scripts are development tools and are not required for normal operation of Auditless.

