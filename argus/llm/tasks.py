from __future__ import annotations

"""Free-form multi-ask tasks: split prompt + finalize from tool evidence (no GoalKind)."""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class UserTask:
    id: int
    text: str


@dataclass
class TaskStatus:
    task: UserTask
    status: str  # done | failed | incomplete
    detail: str = ""


# Stronger connectors that always start a new task when they appear mid-prompt
_CONN_RX = re.compile(
    r"\s+(?:и\s+ещ[её]|а\s+также|плюс|,?\s*and\s+also|,\s*plus)\s+",
    re.IGNORECASE,
)

_TO_RX = re.compile(r"(?:^|\s)чтобы\s+", re.IGNORECASE)

# UI-ish wording → weak logic patch may count toward done
_UI_HINT_RX = re.compile(
    r"(заголов|title|тем[аыу]|theme|строк|надпис|текст|label|напиш|переимен|"
    r"rename|ui\b|окно)",
    re.IGNORECASE,
)

_UNLOCK_HINT_RX = re.compile(
    r"(unlock|license|лиценз|активац|register|unregistered|trial|serial|"
    r"убери\s+про|remove\s+licen|bypass\s+licen|crack)",
    re.IGNORECASE,
)


def split_user_tasks(prompt: str) -> List[UserTask]:
    """
    Deterministic free-form split. No taxonomy — only clause separators.
    If unsure / single clause → one task = whole prompt.
    """
    text = (prompt or "").strip()
    if not text:
        return []

    parts: List[str] = []
    # First split on explicit connectors
    chunks = _CONN_RX.split(text)
    for chunk in chunks:
        chunk = chunk.strip(" \t,.")
        if not chunk:
            continue
        # Secondary: multiple «чтобы …» clauses (skip leading empty)
        sub = _TO_RX.split(chunk)
        if len(sub) > 2:
            # first piece may be preamble ("убери X") keep it; rest are "чтобы"-bodies
            head = sub[0].strip()
            if head:
                parts.append(head)
            for body in sub[1:]:
                body = body.strip(" \t,.")
                if body:
                    parts.append("чтобы " + body)
        else:
            parts.append(chunk)

    # Dedup / drop tiny fragments
    cleaned: List[str] = []
    for p in parts:
        p = re.sub(r"\s+", " ", p).strip()
        if len(p) < 3:
            continue
        if cleaned and p.lower() == cleaned[-1].lower():
            continue
        cleaned.append(p)

    if len(cleaned) <= 1:
        return [UserTask(id=1, text=text)]

    return [UserTask(id=i + 1, text=t) for i, t in enumerate(cleaned)]


def format_tasks_block(tasks: List[UserTask]) -> str:
    if not tasks:
        return ""
    lines = [
        "TASKS (address each; bind every tool call with for_task=<id>; "
        "never invent success — runtime finalizes status):"
    ]
    for t in tasks:
        lines.append(f"{t.id}. {t.text}")
    return "\n".join(lines)


def open_tasks_hint(tasks: List[UserTask], tool_trace: List[Dict[str, Any]]) -> str:
    statuses = _evaluate_tasks(tasks, tool_trace)
    open_ids = [s.task.id for s in statuses if s.status != "done"]
    if not open_ids:
        return "All TASKS have tool evidence marked done. Stop and let runtime finalize."
    return (
        f"Still open: {', '.join(str(i) for i in open_ids)} — "
        "bind for_task; do not claim finished."
    )


def _parse_result(entry: Dict[str, Any]) -> Dict[str, Any]:
    raw = entry.get("result")
    if isinstance(raw, dict):
        return raw
    preview = entry.get("result_preview") or entry.get("result_json")
    if isinstance(preview, dict):
        return preview
    if isinstance(preview, str):
        try:
            return json.loads(preview)
        except json.JSONDecodeError:
            # truncated JSON — best effort
            m = re.search(r'"ok"\s*:\s*(true|false)', preview)
            ok = m.group(1) == "true" if m else None
            ft = None
            m2 = re.search(r'"for_task"\s*:\s*(\d+)', preview)
            if m2:
                ft = int(m2.group(1))
            weak = "weak_ui_xref" in preview and "true" in preview
            verify_ok = None
            if '"verify"' in preview:
                if re.search(r'"verify"[^}]*"ok"\s*:\s*true', preview, re.S):
                    verify_ok = True
                elif re.search(r'"verify"[^}]*"ok"\s*:\s*false', preview, re.S):
                    verify_ok = False
            out: Dict[str, Any] = {}
            if ok is not None:
                out["ok"] = ok
            if ft is not None:
                out["for_task"] = ft
            if weak:
                out.setdefault("evidence", {})["weak_ui_xref"] = True
            if verify_ok is not None:
                out["verify"] = {"ok": verify_ok, "kind": "bytes_contains"}
            out["_truncated"] = True
            return out
    return {}


def _task_id_from_entry(entry: Dict[str, Any], payload: Dict[str, Any]) -> Optional[int]:
    args = entry.get("args") or {}
    if args.get("for_task") is not None:
        try:
            return int(args["for_task"])
        except (TypeError, ValueError):
            pass
    if payload.get("for_task") is not None:
        try:
            return int(payload["for_task"])
        except (TypeError, ValueError):
            pass
    return None


def _is_logic_patch(entry: Dict[str, Any]) -> bool:
    if entry.get("tool") == "argus_unlock_apply":
        return False  # handled via unlock_bytes verify
    if entry.get("tool") != "argus_patch":
        return False
    kind = (entry.get("args") or {}).get("kind") or ""
    return kind in (
        "force_branch",
        "ret_imm",
        "nop_bytes",
        "skip_check",
        "always_true",
        "always_false",
        "nop_prompts",
    )


def _is_unlock_apply(entry: Dict[str, Any]) -> bool:
    return entry.get("tool") == "argus_unlock_apply"


def _is_replace_patch(entry: Dict[str, Any]) -> bool:
    return entry.get("tool") == "argus_patch" and (entry.get("args") or {}).get("kind") == "replace_string"


def _evaluate_tasks(
    tasks: List[UserTask],
    tool_trace: List[Dict[str, Any]],
) -> List[TaskStatus]:
    events: Dict[int, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {t.id: [] for t in tasks}

    for entry in tool_trace:
        payload = _parse_result(entry)
        tid = _task_id_from_entry(entry, payload)
        if tid is None or tid not in events:
            continue
        events[tid].append((entry, payload))

    out: List[TaskStatus] = []
    for t in tasks:
        evs = events.get(t.id) or []
        if not evs:
            out.append(
                TaskStatus(
                    task=t,
                    status="incomplete",
                    detail="нет tool evidence с for_task",
                )
            )
            continue

        had_fail = False
        fail_detail = ""
        had_attempted_logic = False
        had_weak_only = True
        had_verified_replace = False
        had_unlock_ok = False
        had_unlock_fail = False
        last_ok_detail = ""

        for entry, payload in evs:
            ok = payload.get("ok")
            summary = str(payload.get("summary") or "")
            evidence = payload.get("evidence") or {}
            verify = payload.get("verify") or {}
            weak = bool(evidence.get("weak_ui_xref"))

            if ok is False:
                had_fail = True
                fail_detail = summary or str(payload.get("error") or "tool failed")
                if _is_unlock_apply(entry):
                    had_unlock_fail = True
                continue

            if ok is not True:
                continue

            if _is_unlock_apply(entry):
                vok = verify.get("ok")
                vkind = verify.get("kind") or ""
                if vok is True and vkind in ("unlock_bytes", ""):
                    had_unlock_ok = True
                    last_ok_detail = verify.get("detail") or "unlock_bytes verified"
                elif vok is False:
                    had_unlock_fail = True
                    fail_detail = verify.get("detail") or "unlock_bytes verify failed"
                else:
                    # ok tool but no verify — incomplete
                    had_unlock_fail = True
                    fail_detail = "unlock_apply without unlock_bytes ok"
                continue

            if _is_replace_patch(entry):
                vok = verify.get("ok")
                if vok is True:
                    had_verified_replace = True
                    last_ok_detail = "replace_string verified"
                elif vok is False:
                    had_fail = True
                    fail_detail = verify.get("detail") or "replace verify failed"
                continue

            if _is_logic_patch(entry):
                had_attempted_logic = True
                if weak:
                    last_ok_detail = "weak UI xref logic patch"
                else:
                    had_weak_only = False
                    last_ok_detail = summary or "logic patch attempted (no verify)"
                continue

            if not weak:
                had_weak_only = False
            last_ok_detail = summary or entry.get("tool") or "ok"

        ui_ok = bool(_UI_HINT_RX.search(t.text))
        unlock_task = bool(_UNLOCK_HINT_RX.search(t.text))

        if had_unlock_ok:
            out.append(TaskStatus(task=t, status="done", detail=last_ok_detail or "unlock_bytes ok"))
            continue

        if unlock_task and (had_unlock_fail or had_attempted_logic):
            out.append(
                TaskStatus(
                    task=t,
                    status="incomplete",
                    detail=fail_detail or last_ok_detail or "need argus_unlock_apply verify.ok",
                )
            )
            continue

        if had_verified_replace:
            out.append(TaskStatus(task=t, status="done", detail=last_ok_detail or "replace verified"))
            continue

        if had_attempted_logic:
            if had_weak_only and not ui_ok:
                out.append(
                    TaskStatus(
                        task=t,
                        status="incomplete",
                        detail="только weak UI xref / logic without verify",
                    )
                )
                continue
            out.append(
                TaskStatus(
                    task=t,
                    status="incomplete",
                    detail=last_ok_detail or "logic patch attempted (no verify)",
                )
            )
            continue

        if had_fail and not had_verified_replace:
            out.append(TaskStatus(task=t, status="failed", detail=fail_detail))
            continue

        out.append(
            TaskStatus(
                task=t,
                status="incomplete",
                detail=last_ok_detail or "нет достаточного verify",
            )
        )

    return out


def finalize_agent(
    tasks: List[UserTask],
    tool_trace: List[Dict[str, Any]],
    model_answer: str = "",
    *,
    steps: int = 0,
    provider: str = "openai",
    raw_messages: Optional[List[Dict[str, Any]]] = None,
) -> "AgentResult":
    from argus.llm.agent import AgentResult

    if not tasks:
        # no split — treat whole run as incomplete unless replace verified somewhere
        answer = (model_answer or "").strip() or "(empty)"
        return AgentResult(
            ok=False,
            answer=answer + "\n\n[finalize: no TASKS checklist]",
            steps=steps,
            provider=provider,
            tool_trace=tool_trace,
            raw_messages=raw_messages or [],
        )

    statuses = _evaluate_tasks(tasks, tool_trace)
    patched = None
    for entry in reversed(tool_trace):
        payload = _parse_result(entry)
        if payload.get("patched_path"):
            patched = payload["patched_path"]
            break
        args = entry.get("args") or {}
        if args.get("output"):
            patched = args["output"]
            break

    lines = ["Задачи:"]
    for s in statuses:
        lines.append(f"{s.task.id}. «{s.task.text}» → {s.status} — {s.detail}")
    all_done = all(s.status == "done" for s in statuses)
    if all_done:
        lines.append("Итог: все задачи закрыты evidence.")
    else:
        lines.append("Итог: частичный / неполный результат (статус по tool evidence, не по тексту модели).")
    if patched:
        lines.append(f"Файл: {patched}")
    ma = (model_answer or "").strip()
    if ma and ma not in ("(empty model response)",):
        # appendix only — must not look like success status
        lines.append("")
        lines.append("Модель (игнор для status): " + ma[:500])

    return AgentResult(
        ok=all_done,
        answer="\n".join(lines),
        steps=steps,
        provider=provider,
        tool_trace=tool_trace,
        raw_messages=raw_messages or [],
        task_statuses=[{"id": s.task.id, "text": s.task.text, "status": s.status, "detail": s.detail} for s in statuses],
    )
