"""Format memory hints for agent prompt injection."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from argus.memory.client import MemoryClient, memory_enabled
from argus.memory.features import extract_binary_features


def _query_text(binary: str, prompt: str, discover: Optional[dict] = None) -> str:
    feats = extract_binary_features(binary, discover=discover)
    kinds = []
    if any(w in prompt.lower() for w in ("unlock", "license", "лиценз", "trial")):
        kinds.append("gate_transform")
    kinds_str = ",".join(kinds) or "general"
    return (
        f"format={feats['format']} arch={feats['arch']} protection={feats['protection']} "
        f"task={prompt[:200]} kinds={kinds_str}"
    )


def retrieve_hints(
    binary: str,
    prompt: str,
    *,
    discover: Optional[dict] = None,
    k: int = 5,
) -> str:
    if not memory_enabled():
        return ""
    client = MemoryClient()
    if not client.available:
        return ""
    feats = extract_binary_features(binary, discover=discover)
    hints = client.search_hints(
        _query_text(binary, prompt, discover=discover),
        k=k,
        filters={"format": feats["format"]} if feats["format"] in ("elf", "pe") else {},
    )
    if not hints:
        return ""
    lines = [
        "Prior experience (similar cases — hints only, verify yourself):",
    ]
    for h in hints[:5]:
        score = h.get("score", 0)
        outcome = h.get("outcome", "?")
        summary = h.get("summary") or ""
        vlevel = h.get("verification_level", "UNKNOWN")
        lines.append(f"  [{score:.2f} {outcome} {vlevel}] {summary}")
    return "\n".join(lines)
