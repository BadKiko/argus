"""Argus — certified hybrid deobfuscation toolkit (LLM-intent + prove + patch)."""

__version__ = "0.2.0"
__author__ = "k.zhukov"
__license__ = "MIT"

from argus.ask import AskResult, Hint, PatchKind, Want, ask, TOOL_SCHEMA
from argus.nl import ai, parse_prompt

__all__ = [
    "__version__",
    "ask",
    "ai",
    "parse_prompt",
    "Hint",
    "Want",
    "PatchKind",
    "AskResult",
    "TOOL_SCHEMA",
]
