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
    explanation: str = ""


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

_GATE_HINT_RX = re.compile(
    r"(unlock|license|лиценз|активац|register|unregistered|trial|serial|"
    r"убери\s+про|remove\s+licen|bypass\s+licen|crack)",
    re.IGNORECASE,
)


def _is_bypass_password_task(text: str) -> bool:
    from argus.llm.intent import is_bypass_password_task

    return is_bypass_password_task(text)


def _patched_path_from_trace(tool_trace: List[Dict[str, Any]]) -> Optional[str]:
    from pathlib import Path

    for entry in reversed(tool_trace):
        payload = _parse_result(entry)
        path = payload.get("patched_path")
        if path and Path(path).is_file():
            return str(path)
        args = entry.get("args") or {}
        out = args.get("output")
        if out and Path(out).is_file():
            return str(out)
    return None


def _behavior_verify_patched(path: str) -> Optional[Dict[str, Any]]:
    try:
        from argus.apply_plan import verify_patch_behavior

        return verify_patch_behavior(path)
    except Exception:
        return None


def _tool_failures_for_task(
    tool_trace: List[Dict[str, Any]],
    task_id: int,
) -> List[str]:
    out: List[str] = []
    for entry in tool_trace:
        payload = _parse_result(entry)
        tid = _task_id_from_entry(entry, payload)
        if tid is not None and tid != task_id:
            continue
        if payload.get("ok") is False:
            tool = (entry.get("tool") or "?").replace("argus_", "")
            summary = str(payload.get("summary") or payload.get("error") or "fail")[:120]
            out.append(f"{tool}: {summary}")
    return out


def _build_task_explanation(
    task: UserTask,
    status: str,
    detail: str,
    tool_trace: List[Dict[str, Any]],
    *,
    binary: Optional[str] = None,
    had_logic_patch: bool = False,
    patched_path: Optional[str] = None,
) -> str:
    if status == "done":
        return ""

    lines: List[str] = []
    failures = _tool_failures_for_task(tool_trace, task.id)
    if failures:
        lines.append("tool_failures: " + "; ".join(failures[:4]))

    if detail:
        lines.append(f"verify_evidence: {detail}")

    if had_logic_patch and patched_path:
        bv = _behavior_verify_patched(patched_path)
        if bv and bv.get("ran"):
            lines.append(
                f"behavior_smoke: ok={bv.get('ok')} method={bv.get('method')} "
                f"detail={str(bv.get('detail') or '')[:100]}"
            )
            preview = (bv.get("stdout_preview") or "")[:100]
            if preview:
                lines.append(f"stdout_preview: {preview!r}")

    if status == "incomplete" and not lines:
        lines.append("incomplete: no verify evidence in tool trace yet")

    return "\n".join(lines[:6])


def split_user_tasks(prompt: str) -> List[UserTask]:
    """
    Deterministic free-form split. No taxonomy — only clause separators.
    If unsure / single clause → one task = whole prompt.
    """
    text = (prompt or "").strip()
    marker = "USER FEEDBACK (previous attempt failed):"
    if marker in text:
        text = text.split(marker, 1)[0].strip()
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
    binary = _binary_from_trace(tool_trace)
    statuses = _evaluate_tasks(tasks, tool_trace, binary=binary)
    open_ids = [s.task.id for s in statuses if s.status != "done"]
    if not open_ids:
        task_text = tasks[0].text if tasks else ""
        try:
            from argus.llm.verification_hints import verification_gap_hint

            vgap = verification_gap_hint(tool_trace, task_text)
            if vgap:
                return (
                    "TASK STATUS: runtime would finalize, but verification_gap remains:\n"
                    + vgap
                    + "\nDo NOT stop — apply remaining corrective_patch / cover error sinks."
                )
        except Exception:
            pass
        return "All TASKS have tool evidence marked done. Stop and let runtime finalize."

    lines: List[str] = [
        f"TASK STATUS: open={open_ids}",
    ]
    for s in statuses:
        if s.status != "done":
            lines.append(f"  task {s.task.id}: {s.status} — {s.detail}")

    last_failure = None
    for entry in reversed(tool_trace[-5:]):
        res = _parse_result(entry)
        if res.get("ok") is False:
            last_failure = entry
            break
    if last_failure:
        f_res = _parse_result(last_failure)
        lines.append(
            f"last_failure: tool={last_failure.get('tool')} "
            f"summary={str(f_res.get('summary') or '')[:120]}"
        )
        verify = f_res.get("verify") or {}
        if verify:
            lines.append(
                f"verify: kind={verify.get('kind')} ok={verify.get('ok')} "
                f"detail={str(verify.get('detail') or '')[:80]}"
            )

    slice_len = _max_slice_plan_len(tool_trace)
    lines.append(f"evidence: max_slice_plan_len={slice_len} tool_calls={len(tool_trace)}")

    try:
        from argus.llm.autopilot import recovery_hints_from_trace
        from argus.llm.session import investigation_hint
        from argus.llm.verification_hints import verification_gap_hint

        task_text = tasks[0].text if tasks else ""
        rec = recovery_hints_from_trace(
            tool_trace, binary=binary or "", user_prompt=task_text, discover=None
        )
        if rec:
            lines.append(rec)
        inv = investigation_hint()
        if inv:
            lines.append(inv)
        vgap = verification_gap_hint(tool_trace, task_text)
        if vgap:
            lines.append(vgap)
    except Exception:
        pass

    return "\n".join(lines)


def _max_slice_plan_len(tool_trace: List[Dict[str, Any]]) -> int:
    best = 0
    for entry in tool_trace:
        if entry.get("tool") not in ("argus_slice", "argus_investigate"):
            continue
        payload = _parse_result(entry)
        plan = payload.get("patch_plan")
        if plan is None:
            plan = (payload.get("evidence") or {}).get("patch_plan") or []
        if isinstance(plan, list):
            best = max(best, len(plan))
    return best


def _fauxware_loop_pattern(tool_trace: List[Dict[str, Any]]) -> bool:
    """slice plan=0 → logic patch → apply_plan."""
    saw_empty_slice = False
    saw_logic_patch = False
    for entry in tool_trace:
        tool = entry.get("tool")
        if tool in ("argus_slice", "argus_investigate"):
            payload = _parse_result(entry)
            plan = payload.get("patch_plan") or (payload.get("evidence") or {}).get("patch_plan") or []
            if isinstance(plan, list) and len(plan) == 0:
                saw_empty_slice = True
        elif tool == "argus_patch" and _is_logic_patch(entry):
            saw_logic_patch = True
        elif tool == "argus_apply_plan" and saw_empty_slice and saw_logic_patch:
            return True
    return False


def _slice_plan_in_trace(
    tool_trace: List[Dict[str, Any]],
    *,
    task_id: Optional[int] = None,
) -> Tuple[bool, int]:
    """True if trace contains argus_slice or argus_investigate with non-empty patch_plan (optionally same for_task)."""
    best = 0
    for entry in tool_trace:
        if entry.get("tool") not in ("argus_slice", "argus_investigate"):
            continue
        if task_id is not None:
            payload = _parse_result(entry)
            tid = _task_id_from_entry(entry, payload)
            if tid is not None and tid != task_id:
                continue
        payload = _parse_result(entry)
        plan = payload.get("patch_plan")
        if plan is None:
            plan = (payload.get("evidence") or {}).get("patch_plan")
        if not plan and isinstance(payload.get("slice"), dict):
            plan = payload["slice"].get("patch_plan")
        if isinstance(plan, list):
            best = max(best, len(plan))
    return best > 0, best


def _bytes_ok_from_apply(payload: Dict[str, Any]) -> bool:
    verify = payload.get("verify") or {}
    pb = verify.get("patch_bytes") or {}
    if pb.get("ok") is True:
        return True
    applied = payload.get("applied") or []
    return bool(applied) and all(a.get("ok") for a in applied)


def _patch_verify_ok(payload: Dict[str, Any], *, gate_task: bool = False) -> bool:
    verify = payload.get("verify") or {}
    if verify.get("ok") is True:
        kind = verify.get("kind") or ""
        behavior = verify.get("patch_behavior") or {}
        disasm = verify.get("patch_disasm") or {}
        if disasm.get("ok") is True:
            return True
        if kind == "patch_composite":
            if behavior.get("needs_oracle") and (verify.get("patch_bytes") or {}).get("ok"):
                return True
            if behavior.get("ran") and behavior.get("ok") is not True:
                if not behavior.get("needs_oracle"):
                    return False
            if gate_task and (behavior.get("skipped") or not behavior.get("ran")):
                plan_source = payload.get("plan_source") or (payload.get("evidence") or {}).get("plan_source")
                if plan_source == "diagnose":
                    return bool((verify.get("patch_bytes") or {}).get("ok"))
                return False
            bytes_v = verify.get("patch_bytes") or {}
            return bytes_v.get("ok") is True
        if gate_task and kind == "patch_bytes":
            plan_source = payload.get("plan_source") or (payload.get("evidence") or {}).get("plan_source")
            if plan_source == "diagnose":
                return True
            return False
        return kind in ("patch_bytes", "patch_composite", "")
    if gate_task and _bytes_ok_from_apply(payload):
        ps = payload.get("plan_source") or (payload.get("evidence") or {}).get("plan_source")
        if ps == "diagnose":
            return True
    return False


def _plan_sourced_apply(payload: Dict[str, Any]) -> bool:
    ps = payload.get("plan_source")
    if ps is None:
        ps = (payload.get("evidence") or {}).get("plan_source")
    if ps in ("slice", "investigate", "diagnose"):
        return True
    if ps == "rejected_model":
        return False
    slen = payload.get("slice_plan_len")
    if slen is None:
        slen = (payload.get("evidence") or {}).get("slice_plan_len")
    try:
        return int(slen or 0) > 0
    except (TypeError, ValueError):
        return False


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
    if entry.get("tool") == "argus_apply_plan":
        return False  # handled via patch_bytes verify
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


def _is_apply_plan(entry: Dict[str, Any]) -> bool:
    return entry.get("tool") == "argus_apply_plan"


def _is_gui_oracle(entry: Dict[str, Any]) -> bool:
    return entry.get("tool") == "argus_gui_oracle"


def _gui_oracle_ok(payload: Dict[str, Any]) -> bool:
    verify = payload.get("verify") or {}
    if verify.get("ok") is True:
        return True
    return payload.get("ok") is True and verify.get("ok") is not False


def _is_replace_patch(entry: Dict[str, Any]) -> bool:
    return entry.get("tool") == "argus_patch" and (entry.get("args") or {}).get("kind") == "replace_string"


def _binary_from_trace(tool_trace: List[Dict[str, Any]]) -> Optional[str]:
    for entry in tool_trace:
        args = entry.get("args") or {}
        if args.get("binary"):
            return str(args["binary"])
    return None


def _password_answer(payload: Dict[str, Any]) -> Optional[str]:
    for key in ("answer", "stdin", "password"):
        val = payload.get(key)
        if val:
            text = str(val).strip()
            if text:
                return text
    evidence = payload.get("evidence") or {}
    for key in ("stdin", "password"):
        val = evidence.get(key)
        if val:
            text = str(val).strip()
            if text:
                return text
    return None


def _is_password_tool(entry: Dict[str, Any]) -> bool:
    return entry.get("tool") in ("argus_ai", "argus_solve")


def _patched_path_from_evs(evs: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> Optional[str]:
    from pathlib import Path

    for entry, payload in reversed(evs):
        path = payload.get("patched_path")
        if path and Path(path).is_file():
            return str(path)
        args = entry.get("args") or {}
        out = args.get("output")
        if out and Path(out).is_file():
            return str(out)
    return None


def _emit_task_status(
    task: UserTask,
    status: str,
    detail: str,
    evs: List[Tuple[Dict[str, Any], Dict[str, Any]]],
    tool_trace: List[Dict[str, Any]],
    *,
    binary: Optional[str] = None,
    had_logic_patch: bool = False,
) -> TaskStatus:
    patched = _patched_path_from_evs(evs) or _patched_path_from_trace(tool_trace)
    explanation = _build_task_explanation(
        task,
        status,
        detail,
        tool_trace,
        binary=binary,
        had_logic_patch=had_logic_patch,
        patched_path=patched,
    )
    return TaskStatus(task=task, status=status, detail=detail, explanation=explanation)


def _evaluate_tasks(
    tasks: List[UserTask],
    tool_trace: List[Dict[str, Any]],
    *,
    binary: Optional[str] = None,
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
        ui_ok = bool(_UI_HINT_RX.search(t.text))
        gate_task = bool(_GATE_HINT_RX.search(t.text))
        if not evs:
            out.append(
                _emit_task_status(
                    t,
                    "incomplete",
                    "нет tool evidence с for_task",
                    evs,
                    tool_trace,
                    binary=binary,
                )
            )
            continue

        had_fail = False
        fail_detail = ""
        had_attempted_logic = False
        had_weak_only = True
        had_verified_replace = False
        had_patch_ok = False
        had_patch_fail = False
        had_password_ok = False
        password_detail = ""
        last_ok_detail = ""
        had_gui_oracle_ok = False
        gui_oracle_detail = ""

        for entry, payload in evs:
            ok = payload.get("ok")
            summary = str(payload.get("summary") or "")
            evidence = payload.get("evidence") or {}
            verify = payload.get("verify") or {}
            weak = bool(evidence.get("weak_ui_xref"))

            if ok is False:
                had_fail = True
                fail_detail = summary or str(payload.get("error") or "tool failed")
                if _is_apply_plan(entry):
                    had_patch_fail = True
                continue

            if ok is not True:
                continue

            if _is_apply_plan(entry):
                vok = _patch_verify_ok(payload, gate_task=gate_task)
                plan_ok = _plan_sourced_apply(payload)
                had_slice_plan, _ = _slice_plan_in_trace(tool_trace, task_id=t.id)
                had_diagnose_plan = plan_ok and (payload.get("plan_source") == "diagnose")
                if vok and plan_ok and (had_slice_plan or had_diagnose_plan):
                    had_patch_ok = True
                    verify = payload.get("verify") or {}
                    last_ok_detail = verify.get("detail") or "patch verified"
                elif _bytes_ok_from_apply(payload) and had_diagnose_plan:
                    had_patch_ok = True
                    last_ok_detail = "diagnose patch bytes ok"
                elif not vok or not plan_ok or not (had_slice_plan or had_diagnose_plan):
                    had_patch_fail = True
                    if not (had_slice_plan or had_diagnose_plan) or not plan_ok:
                        fail_detail = fail_detail or "need slice or diagnose patch_plan before apply_plan"
                    elif not vok:
                        verify = payload.get("verify") or {}
                        fail_detail = verify.get("detail") or "patch verify failed"
                    else:
                        fail_detail = fail_detail or "apply_plan without verified plan"
                else:
                    had_patch_fail = True
                    fail_detail = "apply_plan without patch_bytes ok"
                continue

            if _is_gui_oracle(entry) and _gui_oracle_ok(payload):
                had_gui_oracle_ok = True
                verify = payload.get("verify") or {}
                gui_oracle_detail = str(verify.get("detail") or payload.get("summary") or "gui launch oracle ok")
                last_ok_detail = gui_oracle_detail
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

            if _is_password_tool(entry):
                pw = _password_answer(payload)
                if pw:
                    had_password_ok = True
                    password_detail = pw
                    last_ok_detail = pw
                continue

            if not weak:
                had_weak_only = False
            last_ok_detail = summary or entry.get("tool") or "ok"

        from argus.llm.intent import TaskKind, classify_task_intent, is_bypass_license_task

        task_intent = classify_task_intent(t.text, binary=binary)
        if gate_task:
            bypass_task = is_bypass_license_task(t.text)
        else:
            bypass_task = _is_bypass_password_task(t.text)

        if task_intent == TaskKind.PASSWORD and gate_task:
            if had_patch_ok:
                had_patch_ok = False
                had_patch_fail = True
                fail_detail = "password crackme — use want=password, not apply_plan"
            elif had_attempted_logic and not had_verified_replace:
                fail_detail = fail_detail or "password binary — patch authenticate or use argus_ai password"

        patched_path = _patched_path_from_evs(evs) or _patched_path_from_trace(tool_trace)

        if had_password_ok and task_intent == TaskKind.PASSWORD and not bypass_task:
            out.append(
                _emit_task_status(
                    t,
                    "done",
                    password_detail or last_ok_detail or "password found",
                    evs,
                    tool_trace,
                    binary=binary,
                )
            )
            continue

        if had_attempted_logic and bypass_task and patched_path and not gate_task:
            bv = _behavior_verify_patched(patched_path)
            if bv and bv.get("ok"):
                preview = (bv.get("stdout_preview") or "").strip().replace("\n", " ")[:80]
                detail = f"bypass ok — {preview or bv.get('detail') or 'behavior verified'}"
                out.append(
                    _emit_task_status(
                        t, "done", detail, evs, tool_trace, binary=binary, had_logic_patch=True
                    )
                )
                continue

        if gate_task and had_patch_ok:
            from argus.llm.verification_hints import gate_outcome_verified

            outcome_ok, outcome_detail = gate_outcome_verified(tool_trace, t.text)
            if had_gui_oracle_ok and outcome_ok:
                out.append(
                    _emit_task_status(
                        t,
                        "done",
                        gui_oracle_detail or last_ok_detail or "patch + gui launch oracle ok",
                        evs,
                        tool_trace,
                        binary=binary,
                    )
                )
                continue
            if had_gui_oracle_ok and not outcome_ok:
                out.append(
                    _emit_task_status(
                        t,
                        "incomplete",
                        (outcome_detail or "launch oracle ok but outcome-change unproven")
                        + " — apply remaining diagnose corrective_patch / cover error sinks",
                        evs,
                        tool_trace,
                        binary=binary,
                    )
                )
                continue
            out.append(
                _emit_task_status(
                    t,
                    "incomplete",
                    last_ok_detail
                    + " — need argus_gui_oracle(reject_texts=...) on patched binary",
                    evs,
                    tool_trace,
                    binary=binary,
                    had_logic_patch=had_attempted_logic,
                )
            )
            continue

        if had_patch_ok:
            out.append(
                _emit_task_status(
                    t, "done", last_ok_detail or "patch_bytes ok", evs, tool_trace, binary=binary
                )
            )
            continue

        if gate_task and (had_patch_fail or had_attempted_logic):
            detail = fail_detail or last_ok_detail or "need argus_apply_plan verify.ok"
            if had_attempted_logic and not had_patch_ok:
                detail = detail or "freestyle logic patch — not patch_plan; use argus_slice + apply_plan"
            if not had_gui_oracle_ok:
                detail = (detail + "; then argus_gui_oracle on patched exe").strip("; ")
            out.append(
                _emit_task_status(
                    t,
                    "incomplete",
                    detail,
                    evs,
                    tool_trace,
                    binary=binary,
                    had_logic_patch=had_attempted_logic,
                )
            )
            continue

        if had_verified_replace:
            out.append(
                _emit_task_status(
                    t,
                    "done",
                    last_ok_detail or "replace verified",
                    evs,
                    tool_trace,
                    binary=binary,
                )
            )
            continue

        if had_attempted_logic:
            if had_weak_only and not ui_ok:
                out.append(
                    _emit_task_status(
                        t,
                        "incomplete",
                        "только weak UI xref / logic without verify",
                        evs,
                        tool_trace,
                        binary=binary,
                        had_logic_patch=True,
                    )
                )
                continue
            out.append(
                _emit_task_status(
                    t,
                    "incomplete",
                    last_ok_detail or "logic patch attempted (no verify)",
                    evs,
                    tool_trace,
                    binary=binary,
                    had_logic_patch=True,
                )
            )
            continue

        if had_fail and not had_verified_replace:
            out.append(
                _emit_task_status(t, "failed", fail_detail, evs, tool_trace, binary=binary)
            )
            continue

        out.append(
            _emit_task_status(
                t,
                "incomplete",
                last_ok_detail or "нет достаточного verify",
                evs,
                tool_trace,
                binary=binary,
                had_logic_patch=had_attempted_logic,
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
    binary: Optional[str] = None,
    user_prompt: str = "",
    discover: Optional[dict] = None,
    store_memory: bool = True,
    planner: str = "llm",
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

    statuses = _evaluate_tasks(tasks, tool_trace, binary=binary)
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

    task_status_list = [
        {
            "id": s.task.id,
            "text": s.task.text,
            "status": s.status,
            "detail": s.detail,
            "explanation": s.explanation,
        }
        for s in statuses
    ]

    if not all_done:
        expl_lines = [s.explanation for s in statuses if s.explanation]
        if expl_lines:
            lines.append("")
            lines.append("Почему не готово:")
            for ex in expl_lines:
                for part in ex.split("\n"):
                    lines.append(f"  • {part}")

    if binary and tool_trace and store_memory:
        try:
            from argus.memory import store_session_case

            task_text = user_prompt or (tasks[0].text if tasks else "")
            store_session_case(
                binary,
                task_text,
                tool_trace,
                task_status_list,
                discover=discover,
                steps=steps,
                planner=planner,
            )
        except Exception:
            pass

    return AgentResult(
        ok=all_done,
        answer="\n".join(lines),
        steps=steps,
        provider=provider,
        tool_trace=tool_trace,
        raw_messages=raw_messages or [],
        task_statuses=task_status_list,
        patched_path=patched,
        binary=binary,
        planner=planner,
    )
