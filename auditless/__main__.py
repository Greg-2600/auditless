"""CLI entry point for Auditless Security Scanner.

Provides the main execution interface when the package is run as a module:
    python -m auditless <hostname> <username> <password> [options]

See cli.py for argument parsing and orchestration logic.
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
