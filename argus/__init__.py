"""Argus — certified hybrid deobfuscation toolkit (LLM-intent + prove + patch)."""

__version__ = "0.5.0"
__author__ = "k.zhukov"
__license__ = "MIT"

from argus.ask import AskResult, Hint, PatchKind, Want, ask, TOOL_SCHEMA
from argus.nl import parse_prompt

__all__ = [
    "__version__",
    "ask",
    "parse_prompt",
    "Hint",
    "Want",
    "PatchKind",
    "AskResult",
    "TOOL_SCHEMA",
]
