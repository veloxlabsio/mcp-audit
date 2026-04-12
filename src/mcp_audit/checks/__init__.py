"""Registry of all mcp-scan checks.

Individual check modules register themselves via ``register``. The runner
iterates over ``REGISTRY`` to execute a scan.

Check modules are auto-discovered: any .py file in the ``checks/`` directory
(except ``__init__.py`` and ``base.py``) is imported at load time so its
``@register`` decorators fire. This means adding a new check file is all you
need to do — no manual import required.
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from mcp_audit.checks.base import Category, Check, CheckResult, Finding, Severity

REGISTRY: list[type[Check]] = []


def register(cls: type[Check]) -> type[Check]:
    """Decorator: add a Check subclass to the global registry."""
    if not cls.id:
        raise ValueError(f"{cls.__name__} is missing a check id")
    if any(existing.id == cls.id for existing in REGISTRY):
        raise ValueError(f"Duplicate check id: {cls.id}")
    REGISTRY.append(cls)
    return cls


def all_checks() -> list[type[Check]]:
    return list(REGISTRY)


# ── Auto-discover check modules ────────────────────────────────────────────
# Import every .py in this package except __init__ and base.
_CHECKS_DIR = Path(__file__).parent
_SKIP = {"__init__", "base"}

for _finder, _module_name, _is_pkg in pkgutil.iter_modules([str(_CHECKS_DIR)]):
    if _module_name in _SKIP:
        continue
    importlib.import_module(f"mcp_audit.checks.{_module_name}")


__all__ = [
    "REGISTRY",
    "register",
    "all_checks",
    "Check",
    "CheckResult",
    "Finding",
    "Severity",
    "Category",
]
