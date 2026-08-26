"""Argus — certified hybrid deobfuscation toolkit (LLM-intent + prove + patch)."""

__version__ = "0.1.0"
__author__ = "k.zhukov"
__license__ = "MIT"

from argus.ask import AskResult, Hint, PatchKind, Want, ask

__all__ = [
    "__version__",
    "ask",
    "Hint",
    "Want",
    "PatchKind",
    "AskResult",
]
