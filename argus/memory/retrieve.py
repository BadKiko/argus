"""Format memory hints for agent prompt injection."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from argus.memory.client import MemoryClient, memory_enabled
from argus.memory.features import extract_binary_features


def _format_tool_path(strategies: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for s in strategies[:10]:
        tool = str(s.get("tool") or "").replace("argus_", "")
        if not tool:
            continue
        ok = s.get("ok")
        tag = "ok" if ok is True else ("fail" if ok is False else "?")
        parts.append(f"{tool}({tag})")
    return " → ".join(parts)


def _query_text(binary: str, prompt: str, discover: Optional[dict] = None) -> str:
    feats = extract_binary_features(binary, discover=discover)
    try:
        from argus.llm.intent import task_signals

        sig = task_signals(prompt, binary=binary, discover=discover)
        kinds = [k for k, v in sig.items() if float(v or 0) >= 0.35]
    except Exception:
        kinds = []
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
        "Prior experience (similar cases — investigation paths, not ground truth):",
    ]
    for h in hints[:5]:
        score = h.get("score", 0)
        outcome = h.get("outcome", "?")
        vlevel = h.get("verification_level", "UNKNOWN")
        strategies = h.get("strategies") or []
        path = _format_tool_path(strategies)
        summary = h.get("summary") or ""
        if path:
            lines.append(f"  [{score:.2f} {outcome} {vlevel}] path: {path}")
        elif summary:
            lines.append(f"  [{score:.2f} {outcome} {vlevel}] {summary}")
        else:
            lines.append(f"  [{score:.2f} {outcome} {vlevel}] (no path recorded)")
    return "\n".join(lines)
