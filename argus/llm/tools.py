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


ARGUS_TOOLS: List[dict] = [
    openai_tool(
        "argus_investigate",
        "Investigation-first: analyze + find + gate_scan + xrefs in one call. "
        "Returns observations[], hypotheses[], suggested_next_tool. "
        "Call at task start or when stuck before patching. Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "query": {"type": "string", "description": "Keywords from user task"},
            "task": {"type": "string", "description": "Optional full task text for intent routing"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_research",
        "Research when stuck: re-analyze binary, find strings, optional web hints. "
        "Call before giving up on a task. Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "query": {"type": "string", "description": "What to research (task/problem keywords)"},
        },
        ["binary", "query"],
    ),
    openai_tool(
        "argus_ai",
        "Natural-language solve/deobf/patch/lift. Prefer this for user intents like 'дай пароль'. "
        "For bypass/remove check prefer argus_patch after argus_find. Always pass for_task.",
        {
            "prompt": {"type": "string", "description": "RU/EN request"},
            "binary": {"type": "string", "description": "Path to ELF/PE"},
            "output": {"type": "string", "description": "Optional output path for patches"},
        },
        ["prompt", "binary"],
    ),
    openai_tool(
        "argus_analyze",
        "Show binary format, arch, entry, symbols, detected protection. Pass for_task.",
        {"binary": {"type": "string"}},
        ["binary"],
    ),
    openai_tool(
        "argus_detect",
        "Detect protection class: none|ollvm|vmp|themida|mixed|unknown|stripped. Pass for_task.",
        {"binary": {"type": "string"}},
        ["binary"],
    ),
    openai_tool(
        "argus_find",
        "Find strings / gate_candidates / suggested_stubs. Pass for_task. "
        "Prefer ui_label_only=false for logic patches. Runtime finalizes task status.",
        {
            "binary": {"type": "string"},
            "query": {"type": "string", "description": "Extra keywords / phrase e.g. 'free version'"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_xrefs",
        "Find code xrefs to a string/data VA and nearby force_branch/nop_bytes candidates. Pass for_task.",
        {
            "binary": {"type": "string"},
            "addr": {"type": "string", "description": "VA from argus_find hit, e.g. 0x4f2a41"},
        },
        ["binary", "addr"],
    ),
    openai_tool(
        "argus_solve",
        "Symbolic/concolic crackme solve. Pass find= success stdout needle. Use deobf=true for OLLVM. Pass for_task.",
        {
            "binary": {"type": "string"},
            "deobf": {"type": "boolean", "description": "Unflatten CFF before solve"},
            "find": {"type": "string", "description": "Success needle in stdout"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_deobf",
        "CFF unflatten recovery and optional patch write. Pass for_task.",
        {
            "binary": {"type": "string"},
            "function": {"type": "string"},
            "patch": {"type": "string", "description": "Output patched binary path"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_lift",
        "Annotated pseudo-C lift. Pass function name, entry=0xVA, and/or query=string "
        "(string→xref→covering fn). Works on stripped ELF. Pass for_task.",
        {
            "binary": {"type": "string"},
            "function": {"type": "string", "description": "Symbol, sub_HEX, or 0xVA"},
            "entry": {"type": "string", "description": "Code VA hex/dec"},
            "query": {"type": "string", "description": "String in binary to find covering function"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_patch",
        "Write a patched binary. Always pass for_task=<TASKS id>. "
        "replace_string: old=exact substring, new≤len(old). "
        "For gate transforms prefer argus_slice then argus_apply_plan (not freestyle gates). "
        "Freestyle logic patch never completes gate-transform tasks. "
        "ETXTBSY: quit the running app. Never stub main/entry.",
        {
            "binary": {"type": "string"},
            "kind": {
                "type": "string",
                "enum": [
                    "always_true",
                    "always_false",
                    "skip_check",
                    "nop_prompts",
                    "unflatten",
                    "force_branch",
                    "nop_bytes",
                    "ret_imm",
                    "replace_string",
                ],
            },
            "function": {"type": "string", "description": "Symbol name or 0x VA (not main for stubs)"},
            "addr": {"type": "string", "description": "VA for force_branch / nop_bytes / ret_imm"},
            "addrs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Multi-target VAs for ret_imm (from suggested_stubs)",
            },
            "size": {"type": "integer", "description": "Byte length for nop_bytes (default 5)"},
            "taken": {
                "type": "boolean",
                "description": "force_branch: true=always jump, false=NOP (use false for je/jz fail-path)",
            },
            "value": {"type": "integer", "description": "ret_imm return value (1 for bool checkers)"},
            "old": {
                "type": "string",
                "description": "replace_string: exact existing substring from argus_find hits",
            },
            "new": {
                "type": "string",
                "description": "replacement; MUST be ≤ len(old) UTF-8 bytes — pad with spaces",
            },
            "output": {"type": "string"},
        },
        ["binary", "kind"],
    ),
    openai_tool(
        "argus_discover",
        "Find the target ELF/PE and related DLL/SO modules when path is missing or unclear, "
        "or when a prior slice found nothing — re-rank candidates across the install dir. "
        "Pass for_task. Prefer before gate scan if no Binary path or after empty patch_plan.",
        {
            "prompt": {"type": "string", "description": "User task text (may contain paths)"},
            "root": {"type": "string", "description": "Directory to scan (default cwd)"},
            "binary": {"type": "string", "description": "Optional known primary path"},
        },
        [],
    ),
    openai_tool(
        "argus_slice",
        "Gate scan (universal): validate/UI strings → xrefs → "
        "gate_candidates + patch_plan. Scans linked DLL/SO when multi=true; auto-widens to "
        "nearby binaries if primary has no plan. If still empty: pivot via argus_discover. "
        "Always call before apply_plan. Then argus_apply_plan. Pass for_task. "
        "If patch_plan is empty: STOP — do not invent steps; pivot modules or use password path.",
        {
            "binary": {"type": "string"},
            "query": {"type": "string", "description": "Optional extra phrase e.g. invalid license"},
            "modules": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra module paths (DLL/SO); default = auto linked",
            },
            "multi": {
                "type": "boolean",
                "description": "Also slice linked modules (default true)",
            },
        },
        ["binary"],
    ),
    openai_tool(
        "argus_apply_plan",
        "Apply patch_plan steps in order, then composite verify (bytes + static disasm). "
        "REQUIRED: steps= copied verbatim from argus_slice, argus_diagnose_failure corrective_patch, "
        "or argus_decision_flow patch_candidates. Never invent steps. Pass for_task.",
        {
            "binary": {"type": "string"},
            "output": {"type": "string", "description": "Patched primary output path (default binary.patched)"},
            "query": {"type": "string", "description": "Optional metadata only"},
            "modules": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Module paths referenced in step.module fields",
            },
            "steps": {
                "type": "array",
                "description": "REQUIRED patch_plan steps from tool evidence",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["ret_imm", "force_branch", "force_flag", "nop_call", "nop_bytes"]},
                        "addr": {"type": "string"},
                        "value": {"type": "integer"},
                        "taken": {"type": "boolean"},
                        "module": {"type": "string"},
                        "why": {"type": "string"},
                    },
                },
            },
        },
        ["binary", "steps"],
    ),
    openai_tool(
        "argus_cfg",
        "Build CFG summary: block/edge counts for a function or entry. Pass for_task.",
        {
            "binary": {"type": "string"},
            "function": {"type": "string"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_disasm",
        "Disassemble instructions at a specific virtual address or function. "
        "Shows annotated assembly with resolved call targets, in-degrees, strings, and jump directions. "
        "Use this to inspect gates, understand validation predicates, and verify branch polarity before patching. Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "addr": {"type": "string", "description": "Virtual address (hex like '0x14004a990' or decimal) to disassemble"},
            "count": {"type": "integer", "description": "Number of instructions to disassemble (default 25, max 100)"},
        },
        ["binary", "addr"],
    ),
    openai_tool(
        "argus_decision_flow",
        "Build a compact Semantic Decision Graph (CDG / Decision Tree) for a function, string, or address. "
        "Shows the cause-and-effect flow slice connecting entry, validator calls, decision gates, error sinks, and success paths in <500 tokens. "
        "Use this to understand why a patch failed, how validation logic is structured, or which gates control access. Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "target": {
                "type": "string",
                "description": "Function VA (e.g. '0x14004a836'), symbol name, or error string (e.g. 'invalid license')",
            },
        },
        ["binary", "target"],
    ),
    openai_tool(
        "argus_diagnose_failure",
        "Perform instant root-cause analysis on an observed error dialog, error message, or crash returncode. "
        "Traces backwards from the symptom through the call graph to find the exact unsatisfied gate or broken call. "
        "Returns the root cause explanation and minimal corrective patch plan in <0.2s. Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "error_text": {
                "type": "string",
                "description": "Exact error dialog/body text observed at runtime (copy verbatim from UI or sandbox)",
            },
            "crash_code": {
                "type": "string",
                "description": "Process crash returncode or exception code (e.g. '0xC0000005', '4294930433', 'SIGSEGV')",
            },
            "last_patch_addr": {
                "type": "string",
                "description": "Address of the last applied patch that may have triggered the crash",
            },
        },
        ["binary"],
    ),
    openai_tool(
        "argus_diagnose_scan",
        "Rank candidate error strings from rodata and run diagnose_failure on each — returns ranked "
        "corrective_patch options (you pick which error_text to apply). Does NOT auto-apply. Pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "limit": {
                "type": "integer",
                "description": "Max candidates to rank (default 6)",
            },
        },
        ["binary"],
    ),
    openai_tool(
        "argus_state_flags",
        "Scan executable sections for global AppState struct boolean invariants (e.g. is_licensed, is_admin, trial_flag). "
        "Finds fields accessed as [reg + offset] across multiple functions and locates their writer sites (setcc/mov) "
        "to enable a single global patch that unlocks the whole program. Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "min_reads": {
                "type": "integer",
                "description": "Minimum times a struct field must be tested across the binary (default 6)",
            },
        },
        ["binary"],
    ),
    openai_tool(
        "argus_gui_oracle",
        "GUI launch oracle (observe only — NO keyboard input). Stages exe into install dir, "
        "launches with native cwd/PATH/LD_LIBRARY_PATH, checks: no crash, no generic error modal, "
        "reject_texts not visible when GUI introspection is available (Win32 / Linux wmctrl|xdotool). "
        "Headless Linux: process-alive check only. Does NOT prove license key acceptance. Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Patched work copy path"},
            "cwd": {"type": "string", "description": "Optional override launch cwd (default: resolved install dir)"},
            "main_window_hint": {
                "type": "string",
                "description": "Substring to detect main window (default: exe stem)",
            },
            "reject_texts": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Fragments that must NOT appear in UI after launch (from diagnose/find)",
            },
            "settle_s": {
                "type": "number",
                "description": "Seconds to wait after first window before scanning (default 3)",
            },
        },
        ["binary"],
    ),
    openai_tool(
        "argus_sandbox_test",
        "Pre-flight safety test of proposed patch steps in an isolated sandbox before applying to the work binary. "
        "Catches crashes (0xC0000005, SIGSEGV) and modal error dialogs in milliseconds without touching the workspace copy. Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "steps": {
                "type": "array",
                "items": {"type": "object"},
                "description": "List of patch steps to simulate: [{'kind': 'ret_imm'|'force_branch', 'addr': '0x...', ...}]",
            },
        },
        ["binary", "steps"],
    ),
    openai_tool(
        "argus_exec",
        "Run custom Python code or shell commands when built-in Argus tools are insufficient. "
        "Use this to write custom analysis/patching scripts, inspect binary structures, solve complex crypto, "
        "or download/install external utilities (pip/curl). Runs in the binary's workspace with full access to "
        "Python libraries (argus, capstone, pefile, z3, numpy). Always pass for_task.",
        {
            "binary": {"type": "string", "description": "Work copy path"},
            "code": {"type": "string", "description": "Python script code or shell command line to run"},
            "language": {
                "type": "string",
                "enum": ["python", "shell"],
                "description": "Execution language: 'python' (default) or 'shell' (sh/cmd)",
            },
            "save_as": {
                "type": "string",
                "description": "Optional relative filename to persist the script in the workspace (e.g. 'custom_solve.py')",
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout in seconds (default 30, max 120)",
            },
        },
        ["binary", "code"],
    ),
]


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
    ):
        if key in slim:
            if isinstance(slim[key], list):
                slim[key] = slim[key][:3]
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
    for keep in ("verify", "patched_path", "patched_paths", "sandbox", "plan_source", "applied"):
        if keep in slim and slim[keep] is not None:
            minimal[keep] = slim[keep]
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
            return _truncate(payload)
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
    return _truncate(payload)


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
        if name in ("argus_patch", "argus_apply_plan", "argus_deobf", "argus_exec"):
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

    for_task = _parse_for_task(arguments)
    missing_task_warn = "" if for_task is not None else "missing for_task — runtime will not count this toward TASK done"

    sess = get_session()
    if (
        sess.strict_plan
        and name == "argus_apply_plan"
        and arguments.get("steps")
        and sess.last_patch_plan_len == 0
    ):
        raw = _envelope(
            ok=False,
            summary="blocked: argus_apply_plan with custom steps after empty patch_plan",
            evidence={
                "error": "strict_plan",
                "plan_source": "rejected_model",
                "slice_plan_len": 0,
            },
            verify={"kind": "patch_bytes", "ok": False, "detail": "steps not from patch_plan"},
            next_hint="argus_slice must return non-empty patch_plan before apply_plan with steps=",
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
    if name.startswith("argus_") and name not in ("argus_discover", "argus_exec"):
        err = _require_binary(arguments)
        if err is not None:
            return err

    if name == "argus_investigate":
        from argus.llm.investigate import run_investigate
        from argus.llm.session import get_session as _gs, record_investigate

        _sess = _gs()
        payload = run_investigate(
            arguments["binary"],
            arguments.get("query") or "",
            original_binary=_sess.original_binary or None,
            task_text=arguments.get("task") or arguments.get("query") or "",
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
                "archetype": payload.get("archetype"),
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
        funcs = [
            {"name": s.name, "addr": hex(s.addr), "size": s.size}
            for s in sorted(img.symbols.values(), key=lambda x: x.addr)
            if s.is_function and not s.is_import and s.addr
        ][:40]
        return _envelope(
            ok=True,
            summary=f"{img.fmt}/{img.arch} entry={hex(img.entry)} prot={prot.kind}",
            evidence={
                "fmt": img.fmt,
                "arch": img.arch,
                "entry": hex(img.entry),
                "sections": len(img.sections),
                "protection": prot.to_dict(),
                "functions": funcs,
            },
            next_hint="observe with argus_find(query=...) or argus_investigate — do not invent function roles",
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
                    {k: h.get(k) for k in ("addr", "kind", "preview", "score")}
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
                    {k: h.get(k) for k in ("addr", "kind", "preview", "score", "nearby_fn")}
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
                "evidence": {
                    "primary": d.get("primary"),
                    "linked": d.get("linked") or [],
                },
                "verify": {"kind": "none", "ok": None},
            },
            limit=8000,
        )

    if name == "argus_slice":
        from argus.find_slice import gate_scan, gate_scan_modules
        from argus.llm.session import record_gate_scan_result

        binary = arguments["binary"]
        query = arguments.get("query")
        multi = arguments.get("multi")
        if multi is None:
            multi = True
        modules = arguments.get("modules")
        if multi:
            d = gate_scan_modules(binary, modules=modules, query=query, auto_widen=True)
        else:
            d = gate_scan(binary, query)
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
        ]
        if previews and previews[0].get("disasm"):
            slice_obs.append(
                "primary disasm: " + " | ".join(previews[0]["disasm"][:2])
            )
        hints = _batch_hints(patch_plan, dict(d.get("hints") or {}))
        return _truncate(
            {
                "ok": True,
                "summary": d.get("summary"),
                "next_hint": d.get("next_hint"),
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
                "verify": {"kind": "none", "ok": None},
            },
            limit=14000,
        )

    if name == "argus_apply_plan":
        from argus.apply_plan import apply_plan
        from argus.patch.sandbox import test_patch_in_sandbox

        binary = arguments["binary"]
        modules = arguments.get("modules")
        steps = arguments.get("steps")
        if not steps:
            return _truncate(
                {
                    "ok": False,
                    "summary": "argus_apply_plan requires explicit steps= from tool evidence",
                    "next_errors": [
                        "call argus_slice, argus_diagnose_failure, or argus_decision_flow first",
                        "copy corrective_patch or patch_plan into steps=",
                    ],
                    "next_hint": "steps= is required in 0.5 — no auto-slice from agent",
                    "verify": {"kind": "patch_bytes", "ok": False, "detail": "missing steps"},
                },
                limit=8000,
            )

        plan_steps = list(steps)
        if plan_steps:
            sb = test_patch_in_sandbox(binary, plan_steps)
            if not sb.get("safe"):
                return _truncate(
                    {
                        "ok": False,
                        "summary": f"sandbox preflight failed: {sb.get('detail')}",
                        "next_hint": sb.get("suggested_action")
                        or "fix patch plan before apply_plan",
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
        from argus.binary import load_binary
        from argus.flow import diagnose_failure

        img = load_binary(arguments["binary"])
        diag = diagnose_failure(
            img,
            error_text=arguments.get("error_text"),
            crash_code=arguments.get("crash_code"),
            last_patch_addr=arguments.get("last_patch_addr"),
        )
        if diag.get("corrective_patch"):
            from argus.llm.session import add_verified_plan_steps

            add_verified_plan_steps(diag["corrective_patch"])
        is_ok = bool(diag.get("ok")) and bool(diag.get("corrective_patch") or arguments.get("crash_code"))
        clean_diag = {k: v for k, v in diag.items() if k != "ok"}
        from argus.llm.autopilot import suggest_patch_batches

        batches = suggest_patch_batches(list(diag.get("corrective_patch") or []))
        from argus.llm.tool_result import ToolResult

        result = ToolResult(
            ok=is_ok,
            summary=str(diag.get("root_cause") or diag.get("symptom") or "failure diagnosis"),
            observations=[
                str(diag.get("explanation") or "")[:200],
                f"corrective_steps={len(diag.get('corrective_patch') or [])}",
            ],
            evidence=clean_diag,
            hints={
                "suggested_batches": batches.get("suggested_batches") or [],
                "full_plan_len": len(batches.get("full_plan") or []),
            },
            next_hint=str(diag.get("explanation") or ""),
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

        from argus.patch.gui_oracle import observe_gui_launch

        binary = arguments["binary"]
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

        shell_ok = os.environ.get("ARGUS_EXEC_SHELL", "").strip().lower() in ("1", "true", "yes")
        if lang != "python" and not shell_ok:
            return _envelope(
                ok=False,
                summary="argus_exec: only language=python allowed (set ARGUS_EXEC_SHELL=1 for shell)",
                evidence={"error": "shell_disabled", "language": lang},
            )

        sess = get_session()
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


