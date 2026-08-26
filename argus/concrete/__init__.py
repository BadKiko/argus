"""Optional concrete execution helpers.

Unicorn-backed concrete/concolic runners can plug in here later.
v1 ships symbolic Engine only; this module keeps the package layout stable.
"""

from __future__ import annotations


def unicorn_available() -> bool:
    try:
        import unicorn  # noqa: F401

        return True
    except ImportError:
        return False
