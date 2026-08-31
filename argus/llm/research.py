from __future__ import annotations

"""Research phase: when tasks are open, give the model a structured rethink brief."""

import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


def tasks_all_done(tasks, tool_trace: List[Dict[str, Any]], *, binary: Optional[str] = None) -> bool:
    from argus.llm.tasks import _evaluate_tasks

    statuses = _evaluate_tasks(tasks, tool_trace, binary=binary)
    return bool(statuses) and all(s.status == "done" for s in statuses)


def _tool_failures(trace: List[Dict[str, Any]], limit: int = 8) -> List[str]:
    out: List[str] = []
    for entry in reversed(trace):
        payload = entry.get("result")
        if not isinstance(payload, dict):
            try:
                payload = json.loads(entry.get("result_preview") or "{}")
            except json.JSONDecodeError:
                payload = {}
        if payload.get("ok") is False:
            tool = (entry.get("tool") or "?").replace("argus_", "")
            summary = str(payload.get("summary") or payload.get("error") or "fail")[:100]
            out.append(f"{tool}: {summary}")
        if len(out) >= limit:
            break
    return list(reversed(out))


def _tools_tried(trace: List[Dict[str, Any]]) -> List[str]:
    seen: List[str] = []
    for entry in trace:
        t = (entry.get("tool") or "").replace("argus_", "")
        if t and t not in seen:
            seen.append(t)
    return seen[-12:]


def _web_hints(query: str, *, max_chars: int = 900) -> str:
    if not query.strip():
        return ""
    try:
        url = "https://html.duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""
    snippets = re.findall(r'class="result__snippet"[^>]*>([^<]+)', html)
    if not snippets:
        return ""
    lines = [s.strip() for s in snippets[:4] if s.strip()]
    text = "\n".join(f"- {ln}" for ln in lines)
    return text[:max_chars]


def build_research_brief(
    user_prompt: str,
    tasks,
    tool_trace: List[Dict[str, Any]],
    *,
    binary: Optional[str] = None,
    original_binary: Optional[str] = None,
    discover: Optional[dict] = None,
    research_round: int = 1,
) -> str:
    from argus.llm.tasks import _evaluate_tasks

    statuses = _evaluate_tasks(tasks, tool_trace, binary=binary or original_binary)
    open_tasks = [s for s in statuses if s.status != "done"]
    failures = _tool_failures(tool_trace)
    tried = _tools_tried(tool_trace)

    lines: List[str] = [
        f"RESEARCH PHASE (round {research_round}) — tasks still open; continue with tools.",
        "Model prose alone does not complete tasks — tool verify required.",
    ]
    if original_binary and binary and original_binary != binary:
        lines.append(f"Work copy (patch ONLY this): {binary}")
        lines.append(f"Original (READ-ONLY, never patch): {original_binary}")
    elif binary:
        lines.append(f"Binary: {binary}")

    try:
        from argus.llm.intent import format_task_signals

        lines.append(format_task_signals(user_prompt, binary=original_binary or binary, discover=discover))
    except Exception:
        pass

    lines.append("")
    lines.append("Open tasks:")
    for s in open_tasks:
        lines.append(f"  {s.task.id}. «{s.task.text}» → {s.status}: {s.detail}")
        if s.explanation:
            for part in s.explanation.split("\n"):
                lines.append(f"     → {part}")

    if failures:
        lines.append("")
        lines.append("Последние ошибки tools:")
        for f in failures:
            lines.append(f"  • {f}")

    if tried:
        lines.append("")
        lines.append("Tools already tried: " + ", ".join(tried))

    slice_len = 0
    for entry in tool_trace:
        if entry.get("tool") not in ("argus_slice", "argus_investigate"):
            continue
        raw = entry.get("result")
        payload = raw if isinstance(raw, dict) else {}
        if not payload:
            try:
                payload = json.loads(entry.get("result_preview") or "{}")
            except json.JSONDecodeError:
                payload = {}
        plan = payload.get("patch_plan") or (payload.get("evidence") or {}).get("patch_plan") or []
        if isinstance(plan, list):
            slice_len = max(slice_len, len(plan))

    lines.append("")
    lines.append("Evidence gaps (pick next experiment):")
    if "investigate" not in tried:
        lines.append("  • no investigate yet — observations may help")
    if "find" not in tried:
        lines.append("  • no find yet — need query/needle from task")
    if slice_len == 0:
        lines.append(f"  • patch_plan empty (max_len={slice_len})")
    if failures:
        lines.append("  • prior tool failures — try different anchor or diagnose_failure")

    base = Path(original_binary or binary or "").name
    web_q = f"{base} crackme reverse engineering {user_prompt[:60]}"
    web = _web_hints(web_q)
    if web:
        lines.append("")
        lines.append("Web hints (не ground truth, проверяй tools):")
        lines.append(web)

    return "\n".join(lines)


def run_research_tool(
    binary: str,
    query: str,
    *,
    original_binary: Optional[str] = None,
) -> Dict[str, Any]:
    """Lightweight research: analyze + find + optional web."""
    from argus.llm.tools import dispatch_tool

    parts: List[str] = []
    web = _web_hints(query)
    if web:
        parts.append("web:\n" + web)

    for tool, args in (
        ("argus_analyze", {"binary": binary}),
        ("argus_find", {"binary": binary, "query": query[:80]}),
    ):
        try:
            raw = dispatch_tool(tool, args)
            payload = json.loads(raw)
            parts.append(f"{tool}: {payload.get('summary') or raw[:200]}")
            nh = payload.get("next_hint")
            if nh:
                parts.append(f"  hint: {nh[:200]}")
        except Exception as e:
            parts.append(f"{tool}: error {e}")

    return {
        "ok": True,
        "summary": f"research ok query={query[:60]!r}",
        "evidence": {"query": query, "original_binary": original_binary, "sections": parts},
        "next_hint": "Use findings in next tool call; do not stop until task evidence done.",
    }
