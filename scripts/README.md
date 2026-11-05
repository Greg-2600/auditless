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

