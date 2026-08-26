"""Optional concrete execution helpers (Unicorn)."""

from __future__ import annotations


def unicorn_available() -> bool:
    try:
        import unicorn  # noqa: F401

        return True
    except ImportError:
        return False


try:
    from argus.concrete.runner import ConcreteResult, UnicornRunner, concrete_run
    from argus.concrete.concolic import ConcolicSeed, concrete_until_branch, parse_stdin_hint
except Exception:  # pragma: no cover
    ConcreteResult = None  # type: ignore
    UnicornRunner = None  # type: ignore
    concrete_run = None  # type: ignore
    ConcolicSeed = None  # type: ignore
    concrete_until_branch = None  # type: ignore
    parse_stdin_hint = None  # type: ignore

__all__ = [
    "unicorn_available",
    "UnicornRunner",
    "ConcreteResult",
    "concrete_run",
    "ConcolicSeed",
    "concrete_until_branch",
    "parse_stdin_hint",
]
