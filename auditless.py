"""Import alias for the :mod:`linux_health` package (canonical product name).

``auditless`` is the distribution and product name; ``linux_health`` remains
the import package through v3.x. This shim makes both spellings resolve to
the *same* module objects (no state duplication):

    import auditless
    auditless.cli is linux_health.cli  # same object

    from auditless import dashboard  # also shared

    python -m auditless --help  # same CLI as python -m linux_health

Submodule access is lazy via PEP 562 and cached in :data:`sys.modules`.
Only ``import auditless`` / attribute access / ``from`` imports are
supported — plain ``import auditless.cli`` does not resolve (the shim is a
module, not a package). The full package rename is slated for v4.0
(ROADMAP item 200).
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType

import linux_health

__all__ = ["__version__"]
__version__: str = linux_health.__version__


def __getattr__(name: str) -> ModuleType:
    """Lazily alias ``linux_health.<name>`` as ``auditless.<name>``.

    Dunder lookups raise :class:`AttributeError` so ``hasattr`` checks for
    ``__path__``/``__all__`` behave (the shim is a module, not a package).
    Unknown submodules surface as :class:`AttributeError`, not
    :class:`ModuleNotFoundError`, to match attribute-access semantics.
    """
    if name.startswith("__") and name.endswith("__"):
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        target = importlib.import_module(f"linux_health.{name}")
    except ModuleNotFoundError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    setattr(sys.modules[__name__], name, target)
    sys.modules[f"{__name__}.{name}"] = target
    return target


def __dir__() -> list[str]:
    """Advertise the alias plus everything the wrapped package offers."""
    return sorted(set(__all__) | set(dir(linux_health)))


if __name__ == "__main__":
    from linux_health.cli import main

    raise SystemExit(main())
