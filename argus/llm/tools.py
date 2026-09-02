from __future__ import annotations

"""MCP-style tools the LLM can call — each maps to real Argus pipelines."""

import json
from typing import Any, Dict, List, Optional


_FOR_TASK_PROP = {
    "for_task": {
        "type": "integer",
        "description": "TASKS checklist id this call addresses (required when TASKS were listed)",
    }
}


def openai_tool(name: str, description: str, properties: dict, required: Optional[List[str]] = None) -> dict:
    props = {**properties, **_FOR_TASK_PROP}
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": props,
                "required": required or [],
            },
        },
    }


# Model-facing surface. Old names still dispatch (tests / aliases).
ARGUS_TOOLS: List[dict] = [
    openai_tool(
        "argus_look",
        "What is this file: format, size, host vs payload, siblings, linked modules. "
        "Call when the path is missing or execution is unclear. Pass for_task.",
        {
            "binary": {"type": "string", "description": "Primary path if known"},
            "prompt": {"type": "string", "description": "User task (may contain paths)"},
            "root": {"type": "string", "description": "Directory to scan"},
        },
        [],
    ),
    openai_tool(
        "argus_find",
        "Search strings/symbols in the file you name (ELF, PE, asar, js, zip). "
        "query= nouns from the USER TASK, not the product filename. "
        "On a hit: argus_diagnose(error_text=verbatim preview). Hits include inner= for archives.",
        {
            "binary": {"type": "string", "description": "Any module: exe, .so, .asar, .js"},
            "query": {"type": "string", "description": "Phrase from the user task"},
            "string_addr": {
                "type": "string",
                "description": "Optional: map callers of this string VA (atlas phase 2)",
            },
        },
        ["binary"],
    ),
    openai_tool(
        "argus_peek",
        "Inspect code at an address: native disasm, or a source WINDOW inside asar/js/zip. "
        "Pass for_task.",
        {
            "binary": {"type": "string"},
            "addr": {"type": "string", "description": "VA to disassemble"},
            "function": {"type": "string", "description": "Symbol or 0xVA to lift/CFG"},
            "count": {"type": "integer", "description": "Disasm instruction count (default 25)"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_diagnose",
        "Native: observed string/crash → CFG patch_plan. "
        "Payload: locates the site and returns a source WINDOW (any language). "
        "Prefer error_text= verbatim find/runtime preview. Pass for_task.",
        {
            "binary": {"type": "string"},
            "error_text": {"type": "string", "description": "Verbatim UI/stdout/find preview"},
            "crash_code": {"type": "string"},
            "last_patch_addr": {"type": "string"},
            "query": {"type": "string", "description": "Scan phrase when no verbatim text yet"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_apply",
        "Native: apply diagnose/slice plan (omit steps=); do not invent force_branch VAs. "
        "Payload: steps=[{kind:replace_string, inner, old, new}] from the diagnose match/window "
        "(old substring of window; new may be longer). Pass for_task.",
        {
            "binary": {"type": "string"},
            "output": {"type": "string"},
            "max_steps": {"type": "integer"},
            "steps": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Native: only from diagnose/slice. Payload: replace_string from window.",
            },
        },
        ["binary"],
    ),
    openai_tool(
        "argus_run",
        "Launch the work copy and observe: stdout for CLI, windows for GUI. "
        "Pass reject_texts= fragments that must disappear. Pass for_task.",
        {
            "binary": {"type": "string"},
            "reject_texts": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Fragments that must NOT appear after launch",
            },
            "main_window_hint": {"type": "string"},
            "cwd": {"type": "string"},
            "settle_s": {"type": "number"},
            "timeout": {"type": "integer", "description": "CLI capture timeout (default 15)"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_exec",
        "Run short Python to probe something Argus did not cover. "
        "Do not unpack asar/zip or reinvent strings; find already searches inner files. "
        "Do not patch from here. Pass for_task.",
        {
            "binary": {"type": "string"},
            "code": {"type": "string"},
            "language": {"type": "string", "enum": ["python", "shell"]},
            "timeout": {"type": "integer"},
            "save_as": {"type": "string"},
        },
        ["binary", "code"],
    ),
]


# Internal handler names → names the model is allowed to call.
_MODEL_TOOL_REWRITES = (
    ("argus_diagnose_failure", "argus_diagnose"),
    ("argus_apply_plan", "argus_apply"),
    ("argus_gui_oracle", "argus_run"),
    ("argus_decision_flow", "argus_peek"),
    ("argus_sandbox_test", "argus_run"),
    ("argus_state_flags", "argus_peek"),
    ("argus_investigate", "argus_look"),
    ("argus_discover", "argus_look"),
    ("argus_analyze", "argus_look"),
    ("argus_disasm", "argus_peek"),
    ("argus_xrefs", "argus_find"),
    ("argus_atlas", "argus_find"),
    ("argus_slice", "argus_diagnose"),
    ("argus_research", "argus_look"),
    ("argus_deobf", "argus_peek"),
    ("argus_detect", "argus_look"),
    ("argus_lift", "argus_peek"),
    ("argus_cfg", "argus_peek"),
    ("argus_ai", "argus_find"),
    ("argus_solve", "argus_find"),
    ("argus_patch", "argus_apply"),
)


def public_tool_name(name: str) -> str:
    for old, new in _MODEL_TOOL_REWRITES:
        if name == old:
            return new
    return name


def _rewrite_tool_text(text: str) -> str:
    out = text
    for old, new in _MODEL_TOOL_REWRITES:
        out = out.replace(old, new)
    return out


def _rewrite_model_facing_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Hints in tool JSON must name the 8 public tools, not internal handlers."""
    if isinstance(payload.get("next_hint"), str):
        payload["next_hint"] = _rewrite_tool_text(payload["next_hint"])
    if isinstance(payload.get("summary"), str):
        payload["summary"] = _rewrite_tool_text(payload["summary"])
    if isinstance(payload.get("suggested_next_tool"), str):
        payload["suggested_next_tool"] = public_tool_name(payload["suggested_next_tool"])
    if isinstance(payload.get("tool"), str):
        payload["tool"] = public_tool_name(payload["tool"])
    for list_key in ("observations", "next_errors", "hypotheses"):
        items = payload.get(list_key)
        if isinstance(items, list):
            payload[list_key] = [_rewrite_tool_text(x) if isinstance(x, str) else x for x in items]
    hints = payload.get("hints")
    if isinstance(hints, dict):
        st = hints.get("suggested_tools")
        if isinstance(st, list):
            rewritten: List[Any] = []
            seen = set()
            for item in st:
                if isinstance(item, str):
                    name = public_tool_name(item)
                    if name not in seen:
                        seen.add(name)
                        rewritten.append(name)
                elif isinstance(item, dict):
                    row = dict(item)
                    row["tool"] = public_tool_name(str(row.get("tool") or ""))
                    if isinstance(row.get("reason"), str):
                        row["reason"] = _rewrite_tool_text(row["reason"])
                    if row["tool"] not in seen:
                        seen.add(row["tool"])
                        rewritten.append(row)
            hints["suggested_tools"] = rewritten
    return payload


def _canonicalize_tool(name: str, arguments: Dict[str, Any]) -> str:
    """Map the small model surface onto existing handlers."""
    if name == "argus_apply":
        return "argus_apply_plan"
    if name == "argus_run" and (
        arguments.get("reject_texts") or arguments.get("main_window_hint")
    ):
        return "argus_gui_oracle"
    if name == "argus_find" and arguments.get("string_addr"):
        return "argus_atlas"
    if name == "argus_peek":
        if arguments.get("addr"):
            return "argus_disasm"
        if arguments.get("function"):
            return "argus_lift"
        return "argus_cfg"
    if name == "argus_diagnose":
        if arguments.get("error_text") or arguments.get("crash_code"):
            return "argus_diagnose_failure"
        return "argus_slice"
    if name == "argus_solve":
        if arguments.get("deobf") and not arguments.get("find"):
            return "argus_deobf"
        if arguments.get("prompt") and not arguments.get("find"):
            return "argus_ai"
        return "argus_solve"
    return name


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return obj.decode("latin1", errors="replace")
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def _truncate(obj: Any, limit: int = 16000) -> str:
    """Serialize tool result; if oversized, shrink payload so JSON stays valid."""
    if isinstance(obj, str):
        if len(obj) <= limit:
            return obj
        return json.dumps(
            {"ok": False, "summary": "truncated", "note": obj[: max(0, limit - 80)], "limits": {"chars": len(obj)}},
            ensure_ascii=False,
        )
    payload = _json_safe(obj)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if len(text) <= limit:
        return text

    slim = dict(payload) if isinstance(payload, dict) else {"ok": True, "data": payload}
    # Always preserve patch_plan
    plan = slim.get("patch_plan")
    if not plan and isinstance(slim.get("evidence"), dict):
        plan = slim["evidence"].get("patch_plan")
    if not plan and isinstance(slim.get("slice"), dict):
        plan = slim["slice"].get("patch_plan")

    for key in (
        "find",
        "analyze",
        "xref_previews",
        "string_hits",
        "hits",
        "gate_candidates",
        "patch_candidates",
        "applied",
        "suggested_stubs",
        "gate_symbols",
        "jumps",
        "strings",
        "hops",
        "modules",
        "observations",
        "callers",
        "edges",
    ):
        if key in slim:
            if isinstance(slim[key], list):
                cap = 40 if key == "jumps" else 12 if key in ("strings", "hops", "modules", "observations") else 3
                slim[key] = slim[key][:cap]
            elif isinstance(slim[key], dict):
                sub_sum = slim[key].get("summary")
                slim[key] = {"summary": sub_sum} if sub_sum else {"truncated": True}

    if plan:
        slim["patch_plan"] = plan

    text = json.dumps(slim, ensure_ascii=False, indent=2)
    if len(text) <= limit:
        slim.setdefault("limits", {})
        if isinstance(slim["limits"], dict):
            slim["limits"]["truncated"] = True
        return json.dumps(slim, ensure_ascii=False, indent=2)

    minimal: Dict[str, Any] = {
        "ok": bool(slim.get("ok", True)),
        "summary": str(slim.get("summary") or "")[:500],
        "next_hint": str(slim.get("next_hint") or "")[:800],
        "observations": (slim.get("observations") or [])[:5],
        "suggested_next_tool": slim.get("suggested_next_tool"),
        "limits": {"truncated": True, "original_chars": len(json.dumps(payload))},
    }
    for keep in (
        "verify",
        "patched_path",
        "patched_paths",
        "sandbox",
        "plan_source",
        "applied",
        "phase",
        "string_addr",
        "suggested_string_addr",
        "query",
    ):
        if keep in slim and slim[keep] is not None:
            minimal[keep] = slim[keep]
    for keep_list, n in (("jumps", 40), ("strings", 16), ("hops", 8), ("observations", 16), ("callers", 12)):
        if isinstance(slim.get(keep_list), list):
            minimal[keep_list] = slim[keep_list][:n]
    if plan:
        minimal["patch_plan"] = plan
        minimal.setdefault("evidence", {})["patch_plan"] = plan
    return json.dumps(minimal, ensure_ascii=False, indent=2)

def _batch_hints(
    plan: List[Dict[str, Any]],
    hints: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from argus.llm.autopilot import suggest_patch_batches

    merged = dict(hints or {})
    if plan:
        batches = suggest_patch_batches(plan)
        merged["suggested_batches"] = batches.get("suggested_batches") or []
        merged["full_plan_len"] = len(batches.get("full_plan") or plan)
    return merged


def _envelope(
    *,
    ok: bool = True,
    summary: str = "",
    evidence: Optional[dict] = None,
    limits: Optional[dict] = None,
    next_hint: str = "",
    result: Optional[Any] = None,
    **extra: Any,
) -> str:
    if result is not None:
        from argus.llm.tool_result import ToolResult

        if isinstance(result, ToolResult):
            payload = result.to_dict()
            payload.update(extra)
            return _truncate(_rewrite_model_facing_payload(payload))
    payload: Dict[str, Any] = {
        "ok": ok,
        "summary": summary,
        "evidence": evidence or {},
        "limits": limits or {},
        "next_hint": next_hint,
    }
    if extra.get("observations") is None and evidence:
        obs = evidence.get("observations")
        if obs:
            payload["observations"] = obs
    payload.update(extra)
    return _truncate(_rewrite_model_facing_payload(payload))


def _parse_for_task(arguments: Dict[str, Any]) -> Optional[int]:
    raw = arguments.get("for_task")
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _inject_task_fields(
    env: str,
    *,
    for_task: Optional[int],
    verify: Optional[dict] = None,
    evidence_extra: Optional[dict] = None,
    warning: str = "",
) -> str:
    try:
        payload = json.loads(env) if isinstance(env, str) else dict(env)
    except json.JSONDecodeError:
        payload = {"ok": False, "summary": env, "evidence": {}}
    if for_task is not None:
        payload["for_task"] = for_task
    elif warning:
        payload["for_task_warning"] = warning
    ev = dict(payload.get("evidence") or {})
    if evidence_extra:
        ev.update(evidence_extra)
    payload["evidence"] = ev
    if verify is not None:
        payload["verify"] = verify
    elif "verify" not in payload:
        payload["verify"] = {"kind": "none", "ok": None}
    payload = _rewrite_model_facing_payload(payload)
    return _truncate(payload)


def _verify_replace_string(patched_path: Optional[str], new: Optional[str]) -> dict:
    if not patched_path or new is None:
        return {"kind": "bytes_contains", "ok": False, "detail": "missing path/new"}
    try:
        data = open(patched_path, "rb").read()
        needle = new.encode("utf-8", errors="replace")
        # trailing spaces in new are intentional pad — also accept rstrip match window
        ok = needle in data or needle.rstrip() in data
        return {
            "kind": "bytes_contains",
            "ok": bool(ok),
            "detail": f"new={new[:40]!r} found={ok}",
        }
    except OSError as e:
        return {"kind": "bytes_contains", "ok": False, "detail": str(e)}


def _weak_ui_xref_at(path: str, addr: Optional[int]) -> bool:
    """Best-effort: local patch hints near addr tagged ui_label_only (no full-binary find)."""
    if addr is None:
        return False
    try:
        from argus.binary import load_binary
        from argus.find import suggest_patches_near

        img = load_binary(path)
        for c in suggest_patches_near(img, addr)[:16]:
            try:
                ca = int(str(c.get("addr")), 0)
            except (TypeError, ValueError):
                continue
            if ca == addr and c.get("ui_label_only"):
                return True
            # same site ±0: reason text
            if ca == addr and "ui_label" in str(c.get("reason") or "").lower():
                return True
    except Exception:
        return False
    return False


def dispatch_tool(name: str, arguments: Dict[str, Any]) -> str:
    """Execute one Argus tool; return JSON/text for the model."""
    from argus.llm.session import get_session, record_gate_scan_result

    arguments = dict(arguments or {})
    sess = get_session()
    if sess.work_binary and sess.original_binary:
        from argus.llm.workspace import (
            assert_not_install_write,
            assert_not_original_target,
            rewrite_tool_paths,
        )

        arguments = rewrite_tool_paths(
            arguments,
            work_binary=sess.work_binary,
            original_binary=sess.original_binary,
        )
        if name in (
            "argus_patch",
            "argus_apply_plan",
            "argus_apply",
            "argus_deobf",
            "argus_exec",
            "argus_run",
        ):
            for key in ("binary", "output", "patch", "save_as"):
                err = assert_not_original_target(arguments.get(key), sess.original_binary)
                if err:
                    return _inject_task_fields(
                        _envelope(ok=False, summary=err, evidence={"error": "original_protected"}),
                        for_task=_parse_for_task(arguments),
                    )
                err2 = assert_not_install_write(arguments.get(key), sess.original_binary)
                if err2 and key in ("output", "patch", "save_as"):
                    return _inject_task_fields(
                        _envelope(ok=False, summary=err2, evidence={"error": "install_protected"}),
                        for_task=_parse_for_task(arguments),
                    )

    name = _canonicalize_tool(name, arguments)

    for_task = _parse_for_task(arguments)
    missing_task_warn = "" if for_task is not None else "missing for_task — runtime will not count this toward TASK done"

    sess = get_session()
    if (
        sess.strict_plan
        and name == "argus_apply_plan"
        and arguments.get("steps")
        and sess.last_patch_plan_len == 0
        and not sess.verified_plans
    ):
        from argus.llm.session import text_replace_grounded, text_replace_reject_reason

        if not text_replace_grounded(arguments.get("steps")):
            why = text_replace_reject_reason(arguments.get("steps"))
            site = sess.last_text_site or {}
            raw = _envelope(
                ok=False,
                summary=f"blocked: {why}" if why else "blocked: custom steps after empty patch_plan",
                evidence={
                    "error": "strict_plan",
                    "plan_source": "rejected_model",
                    "slice_plan_len": 0,
                    "why": why,
                },
                verify={"kind": "patch_bytes", "ok": False, "detail": why or "steps not from patch_plan"},
                next_hint=(
                    f"{why} — copy match= from last argus_diagnose into old=; new may be longer (archive rebuild)."
                    if site.get("window") or site.get("match")
                    else (
                        "Native: argus_diagnose then argus_apply without steps=. "
                        "Payload: pass replace_string old= from the diagnose window."
                    )
                ),
                tool=name,
            )
            return _inject_task_fields(raw, for_task=for_task, warning=missing_task_warn)

    if name == "argus_patch":
        kind = (arguments.get("kind") or "").strip()
        logic_kinds = {
            "ret_imm",
            "force_branch",
            "skip_check",
            "nop_bytes",
            "always_true",
            "always_false",
            "nop_prompts",
        }
        need_plan_kinds = {"ret_imm", "force_branch", "nop_bytes", "skip_check"}
        from argus.llm.session import has_session_plan, logic_patch_count, note_logic_patch_addr

        addr_key = str(arguments.get("addr") or "").strip()
        if kind in need_plan_kinds and logic_patch_count(addr_key) >= 2:
            note_logic_patch_addr(addr_key)
            raw = _envelope(
                ok=False,
                summary=f"blocked: same addr {addr_key or '?'} patched repeatedly — stop freestyle",
                evidence={"error": "patch_loop", "addr": addr_key},
                next_hint=(
                    "argus_diagnose_failure(error_text=verbatim find/runtime preview) then "
                    "argus_apply_plan from corrective_patch. Do not flip taken= on the same VA."
                ),
                tool=name,
            )
            return _inject_task_fields(raw, for_task=for_task, warning=missing_task_warn)
        if kind in logic_kinds and sess.last_slice_patch_plan:
            raw = _envelope(
                ok=False,
                summary=(
                    "blocked: freestyle logic patch while session patch_plan exists "
                    f"(plan_len={len(sess.last_slice_patch_plan)})"
                ),
                evidence={
                    "error": "freestyle_blocked",
                    "slice_plan_len": len(sess.last_slice_patch_plan),
                    "hint_step": sess.last_slice_patch_plan[0],
                },
                verify={"kind": "patch_bytes", "ok": False, "detail": "use argus_apply_plan without steps="},
                next_hint=(
                    "argus_apply_plan with only binary= applies next batch from session slice plan. "
                    "Do NOT argus_patch force_branch/ret_imm when patch_plan exists."
                ),
                tool=name,
            )
            return _inject_task_fields(raw, for_task=for_task, warning=missing_task_warn)
        if kind in need_plan_kinds and not has_session_plan():
            if addr_key:
                note_logic_patch_addr(addr_key)
            raw = _envelope(
                ok=False,
                summary="blocked: freestyle logic patch without diagnose/slice plan",
                evidence={"error": "freestyle_blocked", "kind": kind, "addr": addr_key or None},
                next_hint=(
                    "argus_find/atlas with task nouns → argus_diagnose_failure(error_text=verbatim preview) "
                    "→ argus_apply_plan. Do not invent force_branch polarity."
                ),
                tool=name,
            )
            return _inject_task_fields(raw, for_task=for_task, warning=missing_task_warn)

    try:
        raw = _dispatch_tool_inner(name, arguments)
        from argus.llm.session import record_tool_call

        record_tool_call(name)
    except OSError as e:
        err = str(e)
        if e.errno == 26 or "Text file busy" in err or "ETXTBSY" in err:
            raw = _envelope(
                ok=False,
                summary="Text file busy (ETXTBSY): target binary is running — quit the app, then retry patch",
                evidence={"error": err, "errno": getattr(e, "errno", None)},
                next_hint="close the running program and patch again",
                error=err,
                tool=name,
            )
        else:
            raw = _envelope(ok=False, summary=err, evidence={"error": err, "tool": name}, error=err, tool=name)
    except Exception as e:
        raw = _envelope(ok=False, summary=str(e), evidence={"error": str(e), "tool": name}, error=str(e), tool=name)

    verify = None
    evidence_extra: Dict[str, Any] = {}
    if name == "argus_patch":
        kind = arguments.get("kind")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}
        if kind == "replace_string" and payload.get("ok"):
            verify = _verify_replace_string(
                payload.get("patched_path") or arguments.get("output"),
                arguments.get("new") if "new" in arguments else arguments.get("new_string"),
            )
        elif kind in (
            "ret_imm",
            "force_branch",
            "skip_check",
            "nop_bytes",
            "always_true",
            "always_false",
            "nop_prompts",
        ):
            verify = {"kind": "none", "ok": None, "detail": "logic patch — no auto verify"}
            addr = _parse_addr(arguments.get("addr"))
            if _weak_ui_xref_at(arguments.get("binary") or "", addr):
                evidence_extra["weak_ui_xref"] = True
            evidence_extra["blocks_gate_done"] = True
            evidence_extra["reason"] = "freestyle logic patch — not patch_plan"

    return _inject_task_fields(
        raw,
        for_task=for_task,
        verify=verify,
        evidence_extra=evidence_extra or None,
        warning=missing_task_warn,
    )


def _dispatch_tool_inner(name: str, arguments: Dict[str, Any]) -> str:
    """Execute one Argus tool; return JSON/text for the model."""
    # Discover and exec may run without a known binary; everything else needs a file on disk
    if name.startswith("argus_") and name not in ("argus_discover", "argus_exec", "argus_look"):
        err = _require_binary(arguments)
        if err is not None:
            return err

    if name == "argus_look":
        from argus.payload import build_target_brief, classify_path, format_brief_text

        disc_args = {
            "prompt": arguments.get("prompt") or "",
            "root": arguments.get("root"),
            "binary": arguments.get("binary"),
            "for_task": arguments.get("for_task"),
        }
        disc_raw = _dispatch_tool_inner("argus_discover", disc_args)
        try:
            disc = json.loads(disc_raw)
        except json.JSONDecodeError:
            disc = {"ok": False, "summary": disc_raw[:400]}
        binary = arguments.get("binary") or disc.get("primary")
        brief = disc.get("brief") if isinstance(disc.get("brief"), dict) else None
        cls = {}
        if binary:
            try:
                cls = classify_path(binary)
            except Exception:
                cls = {}
            if not brief:
                try:
                    brief = build_target_brief(binary, install_dir=arguments.get("root"))
                except Exception:
                    brief = None
        extra = {}
        if binary and cls.get("magic") in ("elf", "pe"):
            ana_raw = _dispatch_tool_inner(
                "argus_analyze", {"binary": binary, "for_task": arguments.get("for_task")}
            )
            try:
                extra = json.loads(ana_raw)
            except json.JSONDecodeError:
                extra = {}
        summary = disc.get("summary") or extra.get("summary") or "look"
        if cls:
            summary = (
                f"{cls.get('magic')}/{cls.get('execution')} "
                f"payload_ir={cls.get('payload_ir')} size={cls.get('size')}"
            )
        return _envelope(
            ok=bool(disc.get("ok") or extra.get("ok") or binary),
            summary=str(summary),
            evidence={
                "brief": brief,
                "classify": cls,
                "primary": binary,
                "linked": disc.get("linked") or [],
                "candidates": disc.get("candidates") or [],
                "analyze": extra.get("evidence") if extra else {},
            },
            observations=[format_brief_text(brief)] if brief else [],
            next_hint=(
                disc.get("next_hint")
                or "argus_find(binary= payload or primary, query= task nouns)"
            ),
            brief=brief,
            primary=binary,
            linked=disc.get("linked") or [],
        )

    if name == "argus_run":
        import subprocess
        from pathlib import Path

        miss = _require_binary(arguments)
        if miss:
            return miss
        bin_path = Path(arguments["binary"])
        timeout = min(max(int(arguments.get("timeout") or 15), 1), 120)
        try:
            proc = subprocess.run(
                [str(bin_path)],
                capture_output=True,
                timeout=timeout,
                cwd=arguments.get("cwd") or str(bin_path.parent),
            )
            stdout = (proc.stdout or b"").decode("utf-8", errors="replace")[:4000]
            stderr = (proc.stderr or b"").decode("utf-8", errors="replace")[:2000]
            return _envelope(
                ok=True,
                summary=f"exit={proc.returncode} stdout={len(stdout)}B",
                evidence={
                    "returncode": proc.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                },
                next_hint=(
                    "argus_diagnose(error_text=verbatim stdout/stderr line) "
                    "or argus_run(reject_texts=[...]) for GUI"
                ),
                observations=[stdout[:200] or stderr[:200] or f"exit {proc.returncode}"],
            )
        except subprocess.TimeoutExpired:
            return _envelope(
                ok=True,
                summary=f"still running after {timeout}s (likely GUI) — pass reject_texts=",
                evidence={"timeout": True},
                next_hint="argus_run(reject_texts=[observed fragment])",
            )
        except OSError as e:
            return _envelope(ok=False, summary=str(e), evidence={"error": str(e)})

    if name == "argus_investigate":
        from argus.llm.investigate import run_investigate
        from argus.llm.session import get_session as _gs, record_investigate

        _sess = _gs()
        payload = run_investigate(
            arguments["binary"],
            arguments.get("query") or "",
            original_binary=_sess.original_binary or None,
            task_text=arguments.get("task") or _sess.user_task_text or arguments.get("query") or "",
        )
        record_investigate(arguments["binary"], payload)
        slice_d = payload.get("slice") or {}
        patch_plan = slice_d.get("patch_plan") or []
        evidence = dict(payload.get("evidence") or {})
        if patch_plan:
            evidence["patch_plan"] = patch_plan
        hints = dict(payload.get("hints") or {})
        hints = _batch_hints(patch_plan, hints)
        from argus.llm.tool_result import ToolResult

        result = ToolResult(
            ok=True,
            summary=str(payload.get("summary") or ""),
            observations=list(payload.get("observations") or []),
            evidence={
                **evidence,
                "analyze": payload.get("analyze"),
                "find": payload.get("find"),
                "slice": slice_d,
                "xref_previews": payload.get("xref_previews") or [],
                "hypotheses": payload.get("hypotheses") or [],
            },
            hints=hints,
            next_hint=str(payload.get("next_hint") or ""),
            verify={"kind": "none", "ok": None},
            extra={
                "patch_plan": patch_plan,
                "plan_source": "slice",
                "intent": payload.get("intent"),
            },
        )
        return _truncate(result.to_dict(), limit=16000)

    if name == "argus_research":
        from argus.llm.research import run_research_tool
        from argus.llm.session import get_session as _gs

        _sess = _gs()
        payload = run_research_tool(
            arguments["binary"],
            arguments.get("query") or "",
            original_binary=_sess.original_binary or None,
        )
        return _envelope(
            ok=bool(payload.get("ok")),
            summary=str(payload.get("summary") or "research"),
            evidence=payload.get("evidence") or {},
            next_hint=payload.get("next_hint") or "",
        )

    if name == "argus_ai":
        from argus.nl import ai

        r = ai(arguments["binary"], arguments["prompt"], output=arguments.get("output"))
        return _ask_to_envelope(r)

    if name == "argus_analyze":
        from argus.binary import load_binary
        from argus.deobf import detect_protection

        miss = _require_binary(arguments)
        if miss:
            return _inject_task_fields(miss, for_task=_parse_for_task(arguments))
        img = load_binary(arguments["binary"])
        prot = detect_protection(img)
        commercial = None
        try:
            from argus.deobf.commercial import analyze_commercial

            comm = analyze_commercial(img)
            if comm.tier == "commercial":
                commercial = comm.to_dict()
        except Exception:
            pass
        funcs = [
            {"name": s.name, "addr": hex(s.addr), "size": s.size}
            for s in sorted(img.symbols.values(), key=lambda x: x.addr)
            if s.is_function and not s.is_import and s.addr
        ][:40]
        ev = {
                "fmt": img.fmt,
                "arch": img.arch,
                "entry": hex(img.entry),
                "sections": len(img.sections),
                "protection": prot.to_dict(),
                "functions": funcs,
            }
        if commercial:
            ev["commercial"] = commercial
        nh = "argus_find(query= task nouns) or argus_investigate — then diagnose_failure on a hit preview, do not lift _start"
        if commercial:
            nh = commercial.get("next_hint") or nh
        return _envelope(
            ok=True,
            summary=f"{img.fmt}/{img.arch} entry={hex(img.entry)} prot={prot.kind}",
            evidence=ev,
            next_hint=nh,
            fmt=img.fmt,
            arch=img.arch,
            entry=hex(img.entry),
            sections=len(img.sections),
            protection=prot.to_dict(),
            functions=funcs,
        )

    if name == "argus_detect":
        from argus.binary import load_binary
        from argus.deobf import detect_protection

        prot = detect_protection(load_binary(arguments["binary"]))
        return _envelope(
            ok=True,
            summary=f"protection={prot.kind}",
            evidence=prot.to_dict(),
            **prot.to_dict(),
        )

    if name == "argus_find":
        from argus.find import find_in_binary
        from argus.llm.tool_result import ToolResult

        found = find_in_binary(arguments["binary"], arguments.get("query"))
        hints = found.get("hints")
        observations = found.get("observations") or []
        if not observations and found.get("next_hint"):
            observations = [found["next_hint"][:200]]
        result = ToolResult(
            ok=found.get("ok", True),
            summary=str(found.get("summary") or ""),
            observations=observations,
            evidence={
                "suggested_stubs": found.get("suggested_stubs") or [],
                "gate_symbols": (found.get("gate_symbols") or [])[:12],
                "gate_candidates": (found.get("gate_candidates") or [])[:10],
                "patch_candidates": (found.get("patch_candidates") or [])[:8],
                "reject_ui_candidates": (found.get("evidence") or {}).get("reject_ui_candidates")
                or (hints or {}).get("reject_ui_candidates")
                or [],
                "stripped_like": found.get("stripped_like"),
                "hits": [
                    {
                        k: h.get(k)
                        for k in ("addr", "kind", "preview", "score", "nearby_fn", "inner")
                        if h.get(k) is not None
                    }
                    for h in (found.get("hits") or [])[:10]
                ],
                "entry": (found.get("evidence") or {}).get("entry"),
                "fmt": (found.get("evidence") or {}).get("fmt"),
            },
            hints=hints,
            next_hint=str(found.get("next_hint") or ""),
            verify={"kind": "none", "ok": None},
            extra={
                "gate_symbols": (found.get("gate_symbols") or [])[:12],
                "gate_candidates": (found.get("gate_candidates") or [])[:10],
                "patch_candidates": (found.get("patch_candidates") or [])[:8],
                "suggested_stubs": found.get("suggested_stubs") or [],
                "stripped_like": found.get("stripped_like"),
                "hits": [
                    {
                        k: h.get(k)
                        for k in ("addr", "kind", "preview", "score", "nearby_fn", "inner")
                        if h.get(k) is not None
                    }
                    | ({"text": h.get("preview")} if h.get("preview") else {})
                    for h in (found.get("hits") or [])[:10]
                ],
            },
        )
        return _envelope(result=result)

    if name == "argus_xrefs":
        from argus.binary import load_binary
        from argus.disasm.cfg import disassemble_at
        from argus.find import find_string_xrefs, suggest_patches_near

        img = load_binary(arguments["binary"])
        addr = _parse_addr(arguments.get("addr"))
        if addr is None:
            return _envelope(ok=False, summary="addr required", evidence={"error": "bad addr"})
        xrefs = find_string_xrefs(img, addr)
        for xr in xrefs:
            try:
                site = int(xr.get("addr", "0"), 0)
            except (TypeError, ValueError):
                continue
            insns = disassemble_at(img, site, max_insns=3)
            xr["disasm"] = [
                f"{i.address:#x}: {i.mnemonic} {i.op_str}".strip() for i in insns
            ]
        cands: list = []
        for xr in xrefs[:6]:
            cands.extend(suggest_patches_near(img, int(xr["addr"], 0)))
        hint_tools = []
        if cands:
            hint_tools.append(
                {
                    "tool": "argus_decision_flow",
                    "reason": f"{len(cands)} patch_candidates near xrefs",
                    "confidence": 0.6,
                }
            )
        return _envelope(
            ok=True,
            summary=f"xrefs={len(xrefs)} candidates={len(cands)}",
            evidence={"addr": hex(addr), "xrefs": xrefs, "patch_candidates": cands[:12]},
            observations=[f"xrefs={len(xrefs)} with 3-insn disasm at each site"],
            hints={"suggested_tools": hint_tools} if hint_tools else None,
            next_hint=f"xrefs={len(xrefs)} patch_candidates={len(cands)}",
            xrefs=xrefs,
            patch_candidates=cands[:12],
        )

    if name == "argus_solve":
        from argus.deobf import solve_after_deobf
        from argus.symbolic import solve_binary

        path = arguments["binary"]
        find_s = arguments.get("find")
        find_b = find_s.encode("utf-8", errors="replace") if find_s else None
        if arguments.get("deobf"):
            res = solve_after_deobf(path, find=find_b)
        else:
            res = solve_binary(path, find=find_b)
        stdin = None if res.stdin is None else res.stdin.decode("latin1", errors="replace")
        return _envelope(
            ok=bool(res.success),
            summary=f"solve success={res.success} stdin={stdin!r}" if res.success else f"solve fail: {res.message}",
            evidence={
                "success": res.success,
                "stdin": stdin,
                "message": res.message,
                "paths": res.paths_explored,
            },
            success=res.success,
            stdin=stdin,
            message=res.message,
            paths=res.paths_explored,
        )

    if name == "argus_deobf":
        from argus.deobf import deobf_and_patch, recover_cff
        from argus.binary import load_binary
        from argus.disasm import build_function_cfg

        path = arguments["binary"]
        fn = arguments.get("function") or "main"
        img = load_binary(path)
        if fn not in img.symbols and "main" in img.symbols:
            fn = "main"
        if arguments.get("patch"):
            result = deobf_and_patch(path, fn, arguments["patch"])
            d = result.to_dict()
            return _envelope(
                ok=True,
                summary=f"deobf patched → {arguments['patch']}",
                evidence=d,
                next_hint=f"patched file at {arguments['patch']}",
                **d,
            )
        cfg = build_function_cfg(img, fn)
        d = recover_cff(cfg).to_dict()
        return _envelope(ok=True, summary=f"cff recover {fn}", evidence=d, **d)

    if name == "argus_lift":
        from argus.ask import Hint, Want, ask

        entry = _parse_addr(arguments.get("entry"))
        r = ask(
            arguments["binary"],
            Hint(
                want=Want.LIFT,
                function=arguments.get("function"),
                entry=entry,
                query=arguments.get("query"),
                note=arguments.get("query") or "llm tool lift",
            ),
        )
        return _ask_to_envelope(r)

    if name == "argus_patch":
        from argus.ask import Hint, PatchKind, Want, ask

        kind = PatchKind(arguments["kind"])
        addr = _parse_addr(arguments.get("addr"))
        out = arguments.get("output") or (arguments["binary"] + ".patched")
        stub_addrs = None
        if arguments.get("addrs"):
            stub_addrs = []
            for a in arguments["addrs"]:
                pa = _parse_addr(a) if not isinstance(a, int) else int(a)
                if pa is not None:
                    stub_addrs.append(pa)
        r = ask(
            arguments["binary"],
            Hint(
                want=Want.PATCH,
                patch_kind=kind,
                function=arguments.get("function"),
                output=out,
                note="llm tool patch",
                branch_addr=addr if kind == PatchKind.FORCE_BRANCH else None,
                patch_addr=addr,
                patch_size=arguments.get("size"),
                force_taken=bool(arguments.get("taken", True)),
                ret_value=int(arguments.get("value", 1)),
                old_string=arguments.get("old") or arguments.get("old_string"),
                new_string=arguments.get("new") if "new" in arguments else arguments.get("new_string"),
                stub_addrs=stub_addrs,
            ),
        )
        env = _ask_to_envelope(r)
        # Logic patches: remind to use patch_plan verify — string absence is NOT success
        if r.ok and r.patched_path and kind.value in (
            "ret_imm",
            "force_branch",
            "skip_check",
            "nop_bytes",
            "always_true",
        ):
            try:
                import json as _json

                prev = _json.loads(env) if isinstance(env, str) else {}
                note = (
                    "logic patch applied — for gate transforms prefer argus_apply_plan "
                    "(patch_bytes verify). rodata strings are NOT proof of behavior change."
                )
                return _envelope(
                    ok=bool(r.ok),
                    summary=str(prev.get("summary") or r.answer or ""),
                    evidence={**(prev.get("evidence") or {})},
                    next_hint=note,
                    patched_path=r.patched_path,
                    verify={"kind": "patch_bytes", "ok": bool(r.ok), "detail": "logic patch applied"},
                )
            except Exception:
                pass
        return env

    if name == "argus_discover":
        from argus.discover import discover_targets, is_workspace_cache_path, merge_install_discover
        from argus.llm.session import get_session

        sess = get_session()
        root = arguments.get("root")
        inst = sess.install_dir or (
            str(__import__("pathlib").Path(sess.original_binary).parent)
            if sess.original_binary
            else ""
        )
        if inst and (not root or is_workspace_cache_path(str(root))):
            arguments["root"] = inst
        d = discover_targets(
            arguments.get("prompt") or "",
            root=arguments.get("root"),
            binary=arguments.get("binary"),
        )
        if inst:
            d = merge_install_discover(
                d,
                inst,
                binary=sess.original_binary or arguments.get("binary"),
            )
        return _truncate(
            {
                "ok": bool(d.get("ok")),
                "summary": d.get("summary"),
                "next_hint": d.get("next_hint"),
                "primary": d.get("primary"),
                "candidates": d.get("candidates") or [],
                "linked": d.get("linked") or [],
                "brief": d.get("brief"),
                "evidence": {
                    "primary": d.get("primary"),
                    "linked": d.get("linked") or [],
                    "brief": d.get("brief"),
                },
                "verify": {"kind": "none", "ok": None},
            },
            limit=8000,
        )

    if name == "argus_slice":
        from argus.find_slice import gate_scan, gate_scan_modules
        from argus.llm.session import cached_gate_scan, note_slice_call, record_gate_scan_result, slice_loop_detected

        binary = arguments["binary"]
        query = arguments.get("query")
        multi = arguments.get("multi")
        if multi is None:
            multi = True
        modules = arguments.get("modules")

        cached = cached_gate_scan(binary, query=query, modules=modules, multi=bool(multi))
        if cached and slice_loop_detected(binary, query):
            d = dict(cached)
            d["summary"] = (d.get("summary") or "") + " (cached — repeated slice skipped)"
            plan = d.get("patch_plan") or []
            note_slice_call(binary, query, len(plan))
            return _truncate(
                {
                    "ok": True,
                    "summary": d.get("summary"),
                    "cached": True,
                    "patch_plan": plan,
                    "observations": [f"cached slice plan={len(plan)} — change query/module or pivot"],
                    "next_hint": d.get("next_hint"),
                    "evidence": {"patch_plan": plan, "cached": True},
                    "verify": {"kind": "none", "ok": None},
                },
                limit=14000,
            )

        if multi:
            d = gate_scan_modules(binary, modules=modules, query=query, auto_widen=True)
        else:
            d = gate_scan(binary, query)
        plan = d.get("patch_plan") or []
        note_slice_call(binary, query, len(plan))
        record_gate_scan_result(
            binary,
            d.get("patch_plan") or [],
            full=d,
            query=query,
            modules=modules,
            multi=bool(multi),
        )
        previews = d.get("patch_site_previews") or []
        patch_plan = d.get("patch_plan") or []
        slice_obs = [
            f"plan={len(patch_plan)} gates={len(d.get('gate_candidates') or [])}",
            f"session_ready={'yes' if patch_plan else 'no'} — argus_apply_plan without steps= applies batch",
        ]
        if not patch_plan:
            slice_obs.append(
                "empty patch_plan — incomplete, not failure; "
                "argus_find with task nouns → argus_diagnose(error_text=hit preview)"
            )
        if previews and previews[0].get("disasm"):
            slice_obs.append(
                "primary disasm: " + " | ".join(previews[0]["disasm"][:2])
            )
        hints = _batch_hints(patch_plan, dict(d.get("hints") or {}))
        slice_ok = bool(d.get("ok", True))
        empty_hint = (
            "empty patch_plan is incomplete, not failure — "
            "argus_find query= task nouns, then argus_diagnose(error_text=verbatim preview)"
        )
        return _truncate(
            {
                "ok": slice_ok,
                "summary": d.get("summary"),
                "next_hint": d.get("next_hint") if patch_plan else empty_hint,
                "next_errors": ([] if patch_plan else [empty_hint]),
                "modules": d.get("modules") or [binary],
                "pivoted": d.get("pivoted"),
                "widened_from": d.get("widened_from") or [],
                "per_module": d.get("per_module") or [],
                "gate_candidates": d.get("gate_candidates") or [],
                "patch_plan": patch_plan,
                "patch_site_previews": previews,
                "observations": slice_obs,
                "hints": hints,
                "string_hits": d.get("string_hits") or [],
                "reject_ui_candidates": d.get("reject_ui_candidates") or [],
                "evidence": {
                    "gate_candidates": d.get("gate_candidates") or [],
                    "patch_plan": patch_plan,
                    "patch_site_previews": d.get("patch_site_previews") or [],
                    "string_hits": d.get("string_hits") or [],
                    "modules": d.get("modules") or [binary],
                    "pivoted": d.get("pivoted"),
                    "reject_ui_candidates": d.get("reject_ui_candidates") or [],
                },
                "verify": {"kind": "patch_plan", "ok": bool(patch_plan), "detail": f"plan_steps={len(patch_plan)}"},
            },
            limit=14000,
        )

    if name == "argus_apply_plan":
        from argus.apply_plan import apply_plan
        from argus.llm.session import resolve_apply_steps
        from argus.patch.sandbox import test_patch_in_sandbox

        binary = arguments["binary"]
        modules = arguments.get("modules")
        max_steps = arguments.get("max_steps")
        plan_steps, step_source, step_note = resolve_apply_steps(
            binary,
            arguments.get("steps"),
            max_steps=max_steps,
        )
        if not plan_steps:
            from argus.llm.session import get_session as _gs

            site = _gs().last_text_site or {}
            if site.get("window") or site.get("match"):
                match = str(site.get("match") or "")[:120]
                return _truncate(
                    {
                        "ok": False,
                        "summary": "argus_apply: pass steps= from diagnose window (omit steps= needs a native plan)",
                        "next_errors": [step_note],
                        "next_hint": (
                            "argus_apply(steps=[{kind:replace_string, inner, old, new}]) "
                            f"old= match {match!r} (substring of window); new may be longer."
                        ),
                        "match": site.get("match"),
                        "inner": site.get("inner"),
                        "verify": {"kind": "patch_bytes", "ok": False, "detail": "missing payload steps"},
                    },
                    limit=8000,
                )
            return _truncate(
                {
                    "ok": False,
                    "summary": "argus_apply: no steps (run argus_diagnose first or pass steps=)",
                    "next_errors": [step_note],
                    "next_hint": "argus_diagnose then argus_apply with only binary= (uses session plan)",
                    "verify": {"kind": "patch_bytes", "ok": False, "detail": "missing steps"},
                },
                limit=8000,
            )

        sb = test_patch_in_sandbox(binary, plan_steps)
        if not sb.get("safe"):
            return _truncate(
                {
                    "ok": False,
                    "summary": f"sandbox preflight failed: {sb.get('detail')}",
                    "next_hint": sb.get("suggested_action")
                    or "fix patch plan before apply_plan",
                    "step_source": step_source,
                    "sandbox": sb,
                    "verify": {"kind": "patch_behavior", "ok": False, "detail": sb.get("detail")},
                },
                limit=14000,
            )

        d = apply_plan(
            binary,
            output=arguments.get("output"),
            steps=plan_steps,
            query=arguments.get("query"),
            modules=modules,
        )
        verify = d.get("verify") or {}
        behavior = verify.get("patch_behavior") or {}
        observations = [
            f"step_source={step_source}",
            *( [step_note] if step_note else [] ),
            f"plan_source={d.get('plan_source')} steps={len(d.get('applied') or [])}/{len(d.get('patch_plan') or [])}",
            f"verify.kind={verify.get('kind')} verify.ok={verify.get('ok')}",
        ]
        if behavior.get("ran"):
            observations.append(
                f"behavior: ok={behavior.get('ok')} method={behavior.get('method')} detail={behavior.get('detail')}"
            )
        elif behavior.get("skipped"):
            observations.append(f"behavior skipped: {behavior.get('detail')}")
        return _truncate(
            {
                "ok": bool(d.get("ok")),
                "summary": d.get("summary"),
                "observations": observations,
                "next_hint": d.get("next_hint"),
                "plan_source": d.get("plan_source"),
                "slice_plan_len": d.get("slice_plan_len"),
                "patched_path": d.get("patched_path"),
                "patched_paths": d.get("patched_paths") or {},
                "patch_plan": d.get("patch_plan") or [],
                "applied": d.get("applied") or [],
                "verify": d.get("verify")
                or {"kind": "patch_bytes", "ok": False, "detail": "missing"},
                "evidence": d.get("evidence") or {},
            },
            limit=14000,
        )

    if name == "argus_cfg":
        from argus.binary import load_binary
        from argus.disasm import build_cfg, build_function_cfg

        img = load_binary(arguments["binary"])
        if arguments.get("entry"):
            cfg = build_cfg(img, entry=int(arguments["entry"], 0), max_blocks=400)
        elif arguments.get("function") and arguments["function"] in img.symbols:
            cfg = build_function_cfg(img, arguments["function"])
        else:
            cfg = build_cfg(img, entry=img.entry, max_blocks=400)
        ev = {
            "entry": hex(cfg.entry),
            "blocks": len(cfg.blocks),
            "edges": cfg.graph.number_of_edges(),
            "function": cfg.function_name,
        }
        return _envelope(ok=True, summary=f"cfg blocks={ev['blocks']}", evidence=ev, **ev)

    if name == "argus_disasm":
        from argus.payload import peek_payload, sniff_magic

        magic = sniff_magic(arguments["binary"])
        if magic not in ("elf", "pe"):
            from argus.llm.session import get_session as _gs

            site = _gs().last_text_site or {}
            peeked = peek_payload(
                arguments["binary"],
                arguments.get("addr"),
                inner=arguments.get("inner") or site.get("inner") or None,
                radius=min(800, max(80, int(arguments.get("count") or 25) * 16)),
            )
            return _envelope(
                ok=bool(peeked.get("ok")),
                summary=str(peeked.get("summary") or "peek"),
                evidence={k: v for k, v in peeked.items() if k not in ("ok", "summary")},
                next_hint=(
                    "argus_apply(steps=[{kind:replace_string, inner, old, new}]) "
                    "old from this window, new length ≤ old"
                    if peeked.get("window")
                    else "argus_find then argus_diagnose(error_text=verbatim hit)"
                ),
                window=peeked.get("window"),
                inner=peeked.get("inner"),
                addr=peeked.get("addr"),
                ir=peeked.get("ir"),
            )

        from argus.binary import load_binary
        import capstone as cs
        from argus.find import count_function_callers

        img = load_binary(arguments["binary"])
        addr_str = str(arguments.get("addr") or "").strip()
        count = min(max(int(arguments.get("count") or 25), 1), 100)

        addr = 0
        try:
            if addr_str.startswith("0x") or addr_str.startswith("0X"):
                addr = int(addr_str, 16)
            elif addr_str.isdigit():
                addr = int(addr_str)
            elif addr_str in img.symbols:
                addr = img.symbols[addr_str].addr
        except Exception:
            pass

        if not addr:
            return _envelope(ok=False, error=f"Invalid address: {addr_str!r}")

        mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
        md = cs.Cs(cs.CS_ARCH_X86, mode)
        data = img.read_bytes(addr, count * 15)
        if not data:
            return _envelope(ok=False, error=f"Failed to read bytes at {hex(addr)}")

        insns = list(md.disasm(data, addr))[:count]
        lines = []
        for insn in insns:
            annot = ""
            if insn.mnemonic == "call":
                try:
                    target_fn = int(insn.op_str, 16)
                    nc = count_function_callers(img, target_fn)
                    if nc >= 3:
                        annot = f" ; [validator/hub in-degree={nc}]"
                    elif target_fn in img.symbols:
                        annot = f" ; <{img.symbols[target_fn].name}>"
                except Exception:
                    pass
            elif insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
                annot = " ; [conditional branch]"
            lines.append(f"0x{insn.address:x}:  {insn.bytes.hex():14}  {insn.mnemonic:8} {insn.op_str}{annot}")

        disasm_text = "\n".join(lines)
        return _envelope(
            ok=True,
            summary=f"disasm {hex(addr)} ({len(insns)} insns)",
            evidence={
                "addr": hex(addr),
                "count": len(insns),
                "disassembly": disasm_text,
            },
            addr=hex(addr),
            count=len(insns),
            disassembly=disasm_text,
        )

    if name == "argus_atlas":
        from argus.atlas import build_atlas

        d = build_atlas(
            arguments["binary"],
            arguments.get("query") or "",
            string_addr=arguments.get("string_addr") or arguments.get("addr"),
            module=arguments.get("module"),
            max_modules=int(arguments.get("max_modules") or 8),
        )
        return _truncate(
            {
                "ok": bool(d.get("ok")),
                "phase": d.get("phase"),
                "summary": d.get("summary"),
                "observations": d.get("observations") or [],
                "next_hint": d.get("next_hint"),
                "query": d.get("query"),
                "string_addr": d.get("string_addr"),
                "suggested_string_addr": d.get("suggested_string_addr"),
                "primary": d.get("primary"),
                "strings": d.get("strings") or [],
                "callers": d.get("callers") or [],
                "hops": d.get("hops") or [],
                "jumps": d.get("jumps") or [],
                "modules": d.get("modules") or [],
                "evidence": {
                    "phase": d.get("phase"),
                    "hops": d.get("hops") or [],
                    "module_names": [m.get("name") for m in (d.get("modules") or [])],
                    "string_count": len(d.get("strings") or []),
                    "jump_count": len(d.get("jumps") or []),
                    "caller_sets": len(d.get("callers") or []),
                    "suggested_string_addr": d.get("suggested_string_addr"),
                },
                "hints": {
                    "suggested_tools": (
                        ["argus_atlas"]
                        if d.get("phase") == "strings"
                        else ["argus_diagnose_failure", "argus_apply_plan"]
                    )
                },
            },
            limit=24000,
        )

    if name == "argus_decision_flow":
        from argus.binary import load_binary
        from argus.flow import build_decision_flow

        img = load_binary(arguments["binary"])
        target = arguments.get("target") or ""
        graph = build_decision_flow(img, target)
        text_flow = graph.to_text_flow()
        patches = graph.synthesize_patch_plan(img)
        from argus.llm.session import add_verified_plan_steps
        add_verified_plan_steps(patches)
        for step in patches:
            if isinstance(step, dict) and "confidence" not in step:
                step["confidence"] = "medium"

        return _envelope(
            ok=True,
            summary=f"decision_flow for {graph.func_name} ({len(graph.gates)} gates, {len(graph.validator_hubs)} hubs)",
            observations=[
                f"gates={len(graph.gates)} hubs={len(graph.validator_hubs)} plan_steps={len(patches)}",
            ],
            evidence={
                "func_addr": hex(graph.func_addr),
                "func_name": graph.func_name,
                "gates_count": len(graph.gates),
                "hubs_count": len(graph.validator_hubs),
                "patch_plan": patches,
                "decision_flow": text_flow,
            },
            hints=_batch_hints(patches),
            decision_flow=text_flow,
            patch_plan=patches,
            func_addr=hex(graph.func_addr),
            func_name=graph.func_name,
        )

    if name == "argus_diagnose_failure":
        if not arguments.get("error_text") and not arguments.get("crash_code"):
            return _envelope(
                ok=False,
                summary="argus_diagnose_failure requires error_text= or crash_code=",
                next_errors=[
                    "pass error_text verbatim from user, sandbox, GUI, or find hits",
                    "or crash_code + last_patch_addr for access violations",
                ],
                evidence={"error": "missing_needle"},
            )
        error_text = str(arguments.get("error_text") or "")
        if error_text.strip():
            from argus.llm.session import get_session
            from argus.llm.verification_hints import looks_post_patch_success_banner

            if looks_post_patch_success_banner(error_text, get_session().tool_trace):
                return _envelope(
                    ok=False,
                    summary=(
                        "argus_diagnose_failure refused: this text appeared only after a patch "
                        "(current/success banner, not the original reject). Stop diagnosing it."
                    ),
                    evidence={"error": "post_patch_banner"},
                    next_hint=(
                        "If the original reject fragment is gone from stdout/GUI, the task is done. "
                        "Do not diagnose the new banner; do not start research."
                    ),
                )
        from argus.flow import diagnose_target

        diag = diagnose_target(
            arguments["binary"],
            error_text=arguments.get("error_text"),
            crash_code=arguments.get("crash_code"),
            last_patch_addr=arguments.get("last_patch_addr"),
        )
        if diag.get("corrective_patch"):
            from argus.llm.autopilot import focus_corrective_patch, suggest_patch_batches
            from argus.llm.session import add_verified_plan_steps

            full_plan = list(diag["corrective_patch"] or [])
            focused = focus_corrective_patch(full_plan)
            add_verified_plan_steps(focused, replace=True)
        is_ok = bool(diag.get("ok")) and bool(
            diag.get("corrective_patch")
            or arguments.get("crash_code")
            or diag.get("window")
        )
        clean_diag = {k: v for k, v in diag.items() if k != "ok"}
        from argus.llm.autopilot import suggest_patch_batches

        batches = suggest_patch_batches(list(diag.get("corrective_patch") or []))
        from argus.llm.tool_result import ToolResult

        n_full = len(diag.get("corrective_patch") or [])
        n_focus = len(focused) if diag.get("corrective_patch") else 0
        if diag.get("window"):
            from argus.llm.session import note_text_site

            note_text_site(diag)
        if n_full > n_focus:
            apply_hint = (
                f"plan has {n_full} steps (wide handler) — apply suggested_batches[0] "
                f"({n_focus} predicate gates) via argus_apply; do not apply every je "
                "and do not argus_patch atlas jumps."
            )
        elif n_full:
            apply_hint = str(diag.get("explanation") or "") + (
                " Next: argus_apply (omit steps=) then verify the same fragment."
            )
        elif diag.get("window"):
            apply_hint = str(
                diag.get("next_hint")
                or (
                    "argus_apply(steps=[{kind:replace_string, inner, old, new}]) "
                    "old= match= from this result; new may be longer."
                )
            )
        else:
            apply_hint = str(diag.get("explanation") or diag.get("next_hint") or "")
            if "Next: argus_apply" in apply_hint and n_full == 0:
                apply_hint = (
                    "No native plan and no payload window. "
                    "argus_find(query= another task noun) or argus_run to capture a runtime line."
                )

        result = ToolResult(
            ok=is_ok,
            summary=str(diag.get("root_cause") or diag.get("symptom") or "failure diagnosis"),
            observations=[
                ("match=" + str(diag.get("match") or diag.get("string_preview") or ""))[:200],
                str(diag.get("explanation") or "")[:200],
                f"corrective_steps={n_full} focused={n_focus}"
                + (f" inner={diag.get('inner')}" if diag.get("inner") else ""),
            ],
            evidence=clean_diag,
            hints={
                "suggested_batches": batches.get("suggested_batches") or [],
                "full_plan_len": len(batches.get("full_plan") or []),
                "focused_plan": (focused if diag.get("corrective_patch") else []),
            },
            next_hint=apply_hint,
            extra={k: v for k, v in clean_diag.items() if k not in ("corrective_patch",)},
        )
        return _envelope(result=result)

    if name == "argus_diagnose_scan":
        from argus.binary import load_binary
        from argus.flow import auto_diagnose_plan, discover_reject_ui_strings

        img = load_binary(arguments["binary"])
        limit = int(arguments.get("limit") or 6)
        candidates = discover_reject_ui_strings(img, limit=limit)
        ranked: List[Dict[str, Any]] = []
        best = auto_diagnose_plan(img)
        if best:
            ranked.append(
                {
                    "error_text": best.get("symptom"),
                    "score": "best",
                    "corrective_patch": best.get("corrective_patch") or [],
                    "caller_func": best.get("caller_func"),
                }
            )
        for text in candidates:
            if any(r.get("error_text") == text for r in ranked):
                continue
            from argus.flow import diagnose_failure

            d = diagnose_failure(img, error_text=text)
            patch = list(d.get("corrective_patch") or [])
            if patch:
                ranked.append(
                    {
                        "error_text": text,
                        "patch_steps": len(patch),
                        "corrective_patch": patch[:12],
                        "caller_func": d.get("caller_func"),
                    }
                )
            if len(ranked) >= limit:
                break
        return _envelope(
            ok=True,
            summary=f"diagnose_scan: {len(ranked)} ranked candidates (pick error_text — does not auto-apply)",
            evidence={"ranked_diagnoses": ranked, "reject_ui_candidates": candidates},
            hints={
                "suggested_tools": [
                    {
                        "tool": "argus_diagnose_failure",
                        "reason": "pick one error_text from ranked_diagnoses",
                        "confidence": 0.8,
                    }
                ]
            },
            observations=[f"candidates={len(candidates)} ranked={len(ranked)}"],
        )

    if name == "argus_state_flags":
        from argus.binary import load_binary
        from argus.state_struct import scan_state_struct_invariants

        img = load_binary(arguments["binary"])
        min_reads = int(arguments.get("min_reads") or 6)
        flags = scan_state_struct_invariants(img, min_reads=min_reads)
        summary = f"detected {len(flags)} global state flags"
        patches = [f["recommended_patch"] for f in flags if f.get("recommended_patch")]
        return _envelope(
            ok=True,
            summary=summary,
            evidence={"flags": flags[:10], "patches": patches},
            next_hint="force writer sites (setcc/mov) to unlock state flags globally",
            flags=flags[:10],
            patches=patches,
        )

    if name == "argus_gui_oracle":
        from pathlib import Path

        from argus.binary import load_binary
        from argus.patch.gui_oracle import observe_gui_launch
        from argus.patch.safety import looks_windowed_gui

        binary = arguments["binary"]
        try:
            img = load_binary(binary)
        except Exception:
            img = None
        if img is not None and not looks_windowed_gui(img):
            return _envelope(
                ok=False,
                summary="gui_oracle skipped: binary looks CLI/console (no GUI toolkit imports)",
                evidence={"error": "cli_not_gui", "fmt": getattr(img, "fmt", None)},
                next_hint=(
                    "CLI verify: run the work copy and pass the same reject/banner fragment "
                    "from stdout to confirm it is gone. Do not call argus_gui_oracle again."
                ),
                verify={"kind": "gui_launch_oracle", "ok": False, "detail": "cli_not_gui", "ran": False},
            )
        reject = arguments.get("reject_texts") or []
        if isinstance(reject, str):
            reject = [reject]
        res = observe_gui_launch(
            binary,
            cwd=arguments.get("cwd"),
            main_window_hint=arguments.get("main_window_hint"),
            reject_texts=[str(x) for x in reject if str(x).strip()],
            settle_s=float(arguments.get("settle_s") or 3.0),
        )
        verify = {
            "kind": res.get("kind") or "gui_launch_oracle",
            "ok": bool(res.get("ok")),
            "detail": res.get("detail"),
            "level": res.get("level") or ("EXECUTION_VERIFIED" if res.get("ok") else "UNKNOWN"),
            "ran": bool(res.get("ran")),
            "no_keyboard_input": True,
            "outcome_verified": False,
        }
        if res.get("ok"):
            hint = (
                "EXECUTION_VERIFIED only — idle launch smoke passed. "
                "Does NOT type validation input or prove check outcome changed. "
                "If task requires acceptance/bypass of checks: compare diagnose corrective_patch "
                "vs applied addrs; patch remaining error sinks before stopping."
            )
        else:
            hint = "fix patch or reject_texts still visible at idle; try argus_diagnose_failure"
        observations = [
            f"install_cwd={res.get('install_cwd')}",
            f"windows={len(res.get('windows') or [])}",
            f"verification_tier={verify.get('level')}",
            "no_keyboard_input=true",
        ]
        if reject:
            observations.append(f"reject_texts_checked={len(reject)} (idle UI only)")
        return _envelope(
            ok=bool(res.get("ok")),
            summary=str(res.get("detail") or "gui launch oracle"),
            observations=observations,
            evidence={k: v for k, v in res.items() if k not in ("ok", "detail")},
            verify=verify,
            next_hint=hint,
            patched_path=binary if Path(binary).suffix.lower() == ".patched" else None,
        )

    if name == "argus_sandbox_test":
        from argus.patch.sandbox import test_patch_in_sandbox

        binary = arguments["binary"]
        steps = arguments.get("steps") or []
        s_res = test_patch_in_sandbox(binary, steps)
        is_safe = bool(s_res.get("safe"))
        clean_res = {k: v for k, v in s_res.items() if k != "ok"}
        return _envelope(
            ok=is_safe,
            summary=s_res.get("detail") or "sandbox test complete",
            evidence=s_res,
            next_hint=s_res.get("suggested_action") or "",
            **clean_res,
        )

    if name == "argus_exec":
        import os
        import re
        import subprocess
        import sys
        import tempfile
        from pathlib import Path

        from argus.llm.workspace import exec_workspace_dir
        from argus.llm.session import get_session

        binary = arguments.get("binary") or ""
        code = arguments.get("code") or ""
        lang = (arguments.get("language") or "python").lower()
        timeout = min(max(int(arguments.get("timeout") or 30), 1), 180)
        save_as = arguments.get("save_as")

        sess = get_session()
        sess.exec_calls = int(getattr(sess, "exec_calls", 0) or 0) + 1

        if os.environ.get("ARGUS_EXEC", "1").strip().lower() in ("0", "false", "no", "off"):
            return _envelope(
                ok=False,
                summary="argus_exec disabled (ARGUS_EXEC=0) — use argus_find / argus_look / argus_peek",
                evidence={"error": "exec_disabled"},
                next_hint="Observe via find/look/peek; do not shell out.",
            )

        try:
            exec_max = int((os.environ.get("ARGUS_EXEC_MAX") or "8").strip() or "8")
        except ValueError:
            exec_max = 8
        exec_max = max(0, min(exec_max, 20))
        if sess.exec_calls > exec_max:
            return _envelope(
                ok=False,
                summary=(
                    f"argus_exec budget exhausted ({exec_max}/session) — last resort only. "
                    "Pass a verbatim stdout fragment to argus_find(query=) / argus_diagnose(error_text=)."
                ),
                evidence={"error": "exec_budget", "exec_calls": sess.exec_calls, "exec_max": exec_max},
                next_hint="argus_find(query=<observed banner or error line>), not more exec.",
            )

        # Reinventing RE CLIs / network / priv-esc — Argus already has tools for the first set.
        _blocked = re.compile(
            r"(?i)(?<![A-Za-z_])"
            r"(strings|readelf|objdump|nm|gdb|strace|ltrace|hexdump|\bxxd\b|"
            r"radare2|\br2\b|ghidra|pip3?|curl|wget|apt-get|sudo|chmod\s+\+x)"
            r"(?![A-Za-z_])"
        )
        if _blocked.search(code or ""):
            return _envelope(
                ok=False,
                summary=(
                    "argus_exec refused: that CLI is not last-resort. "
                    "strings/readelf/nm → argus_find / argus_look / argus_peek. "
                    "Run the target once only to copy a banner into find/diagnose."
                ),
                evidence={"error": "exec_replaced_tool"},
                next_hint="argus_find(query=<verbatim runtime text>) then argus_diagnose(error_text=).",
            )

        shell_ok = os.environ.get("ARGUS_EXEC_SHELL", "").strip().lower() in ("1", "true", "yes")
        if lang != "python" and not shell_ok:
            return _envelope(
                ok=False,
                summary="argus_exec: only language=python allowed (set ARGUS_EXEC_SHELL=1 for shell)",
                evidence={"error": "shell_disabled", "language": lang},
                next_hint="Use language=python to subprocess the target, or use find/look.",
            )

        if sess.work_binary:
            exec_dir = exec_workspace_dir(sess.work_binary)
        else:
            exec_dir = Path(tempfile.gettempdir()) / "argus_exec"
            exec_dir.mkdir(parents=True, exist_ok=True)

        temp_file = None
        target_script = None

        try:
            if lang == "python":
                if save_as:
                    save_path = exec_dir / Path(save_as).name
                    save_path.write_text(code, encoding="utf-8")
                    target_script = str(save_path)
                else:
                    fd, temp_file = tempfile.mkstemp(
                        suffix=".py", prefix="argus_exec_", dir=str(exec_dir)
                    )
                    os.write(fd, code.encode("utf-8"))
                    os.close(fd)
                    target_script = temp_file
                cmd = [sys.executable, target_script]
            else:
                if os.name == "nt":
                    cmd = ["cmd.exe", "/c", code]
                else:
                    cmd = ["/bin/sh", "-c", code]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                cwd=str(exec_dir),
                env=os.environ.copy(),
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            rc = proc.returncode
            ok = rc == 0

            evidence: Dict[str, Any] = {
                "language": lang,
                "returncode": rc,
                "stdout": stdout[:8000],
                "stderr": stderr[:4000],
                "exec_dir": str(exec_dir),
            }
            if target_script and save_as:
                evidence["script_path"] = target_script

            summary = f"exec lang={lang} rc={rc} stdout={len(stdout)} chars"
            if not ok and stderr:
                summary += f" err: {stderr[:60].strip()}"

            return _envelope(
                ok=ok,
                summary=summary,
                evidence=evidence,
                stdout=stdout[:8000],
                stderr=stderr[:4000],
                returncode=rc,
                next_hint=(
                    "If this printed a banner/error, copy one verbatim line into "
                    "argus_find(query=) — do not exec strings/readelf."
                ),
            )
        except subprocess.TimeoutExpired:
            return _envelope(
                ok=False,
                summary=f"exec timed out after {timeout}s",
                evidence={"error": "timeout", "timeout": timeout},
                error=f"timed out after {timeout}s",
            )
        except Exception as e:
            return _envelope(
                ok=False,
                summary=f"exec failed: {e}",
                evidence={"error": str(e)},
                error=str(e),
            )
        finally:
            if temp_file and os.path.isfile(temp_file):
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass

    return _envelope(ok=False, summary=f"unknown tool {name}", evidence={"error": f"unknown tool {name}"})



def _ask_to_envelope(r, *, readable_limit: int = 4500) -> str:
    d = r.to_dict()
    readable = d.get("readable")
    truncated = False
    if isinstance(readable, str) and len(readable) > readable_limit:
        d["readable"] = readable[:readable_limit] + f"\n… truncated readable ({len(readable)} chars)"
        truncated = True
    d.pop("tool_schema", None)
    summary = d.get("answer") or ("; ".join(d.get("notes") or [])[:200]) or ("ok" if d.get("ok") else "fail")
    safety = (d.get("certificate") or {}).get("safety") or (d.get("evidence") or {}).get("safety") or {}
    next_hint = ""
    if safety and safety.get("safe") is False:
        next_hint = safety.get("next_hint") or (
            "re-patch surgically (force_branch/nop_bytes); do not stub main"
        )
        summary = f"UNSAFE/refused: {safety.get('reason') or summary}"
    elif d.get("ok") is False and d.get("want") == "patch":
        next_hint = "patch refused — try argus_find then force_branch/nop_bytes on check VA"
    elif d.get("patched_path"):
        next_hint = f"patched file at {d['patched_path']}; cite path in final answer"
    elif d.get("want") == "lift":
        conf = (d.get("evidence") or {}).get("confidence", "low")
        next_hint = f"confidence={conf}; only claim what callees/blocks show; else say unknown"
    return _envelope(
        ok=bool(d.get("ok")),
        summary=str(summary),
        evidence={
            "want": d.get("want"),
            "patched_path": d.get("patched_path"),
            "certificate": d.get("certificate"),
            "safety": safety,
            "lift": {
                k: (d.get("evidence") or {}).get(k)
                for k in (
                    "confidence",
                    "callees",
                    "blocks",
                    "shown_blocks",
                    "entry",
                    "function",
                    "truncated",
                )
                if (d.get("evidence") or {}).get(k) is not None
            },
            "notes": d.get("notes"),
        },
        limits={"readable_truncated": truncated, "readable_limit": readable_limit},
        next_hint=next_hint,
        answer=d.get("answer"),
        readable=d.get("readable"),
        patched_path=d.get("patched_path") if d.get("ok") else None,
        certificate=d.get("certificate"),
        notes=d.get("notes"),
        want=d.get("want"),
        safe=safety.get("safe") if safety else (True if d.get("ok") else None),
    )


def _parse_addr(raw: Any) -> Optional[int]:
    if raw is None or raw == "":
        return None
    if isinstance(raw, int):
        return raw
    return int(str(raw), 0)


def _require_binary(arguments: Dict[str, Any]) -> Optional[str]:
    """Return an error envelope string if binary path is missing/not a file."""
    import os

    path = arguments.get("binary")
    if not path:
        return _envelope(
            ok=False,
            summary="нет файла: binary path not provided",
            evidence={"error": "missing_binary"},
            next_hint="stop; ask user for a real binary path",
            error="missing_binary",
        )
    if not os.path.isfile(path):
        return _envelope(
            ok=False,
            summary=f"нет файла: {path}",
            evidence={"error": "file_not_found", "path": path},
            next_hint="stop; tell the user the file does not exist",
            error="file_not_found",
            path=path,
        )
    return None


