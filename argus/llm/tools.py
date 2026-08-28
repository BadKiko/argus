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
        "Apply patch_plan in order (ret_imm/force_branch) per module, then "
        "composite verify (bytes + behavior smoke when available). "
        "NEVER pass custom steps= unless copied verbatim from argus_slice patch_plan JSON. "
        "Omit steps= to auto-slice. Prefer this over freestyle argus_patch for gate transforms. Pass for_task.",
        {
            "binary": {"type": "string"},
            "output": {"type": "string", "description": "Patched primary output path (default binary.patched)"},
            "query": {"type": "string", "description": "Optional query if auto-building plan"},
            "modules": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra modules to include in auto plan",
            },
            "steps": {
                "type": "array",
                "description": "patch_plan steps from argus_slice (may include module=)",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["ret_imm", "force_branch"]},
                        "addr": {"type": "string"},
                        "value": {"type": "integer"},
                        "taken": {"type": "boolean"},
                        "module": {"type": "string"},
                        "why": {"type": "string"},
                    },
                },
            },
        },
        ["binary"],
    ),
    openai_tool(
        "argus_cfg",
        "Build CFG summary: block/edge counts for a function or entry. Pass for_task.",
        {
            "binary": {"type": "string"},
            "function": {"type": "string"},
            "entry": {"type": "string", "description": "Hex/dec VA if no symbols"},
        },
        ["binary"],
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


def _truncate(obj: Any, limit: int = 10000) -> str:
    """Serialize tool result; if oversized, shrink payload so JSON stays valid."""
    if isinstance(obj, str):
        if len(obj) <= limit:
            return obj
        # Best-effort: keep a valid tiny JSON note rather than mid-string cut
        return json.dumps(
            {"ok": False, "summary": "truncated", "note": obj[: max(0, limit - 80)], "limits": {"chars": len(obj)}},
            ensure_ascii=False,
        )
    payload = _json_safe(obj)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if len(text) <= limit:
        return text
    # Progressively drop bulky keys
    slim = dict(payload) if isinstance(payload, dict) else {"ok": True, "data": payload}
    for key in (
        "string_hits",
        "hits",
        "gate_candidates",
        "patch_candidates",
        "patch_plan",
        "applied",
        "evidence",
        "suggested_stubs",
        "gate_symbols",
    ):
        if key in slim:
            slim[key] = (slim[key][:3] if isinstance(slim[key], list) else {"truncated": True})
        text = json.dumps(slim, ensure_ascii=False, indent=2)
        if len(text) <= limit:
            slim.setdefault("limits", {})
            if isinstance(slim["limits"], dict):
                slim["limits"]["truncated"] = True
            return json.dumps(slim, ensure_ascii=False, indent=2)
    slim = {
        "ok": bool(slim.get("ok", True)),
        "summary": str(slim.get("summary") or "")[:500],
        "next_hint": str(slim.get("next_hint") or "")[:800],
        "limits": {"truncated": True, "original_chars": len(json.dumps(payload))},
    }
    return json.dumps(slim, ensure_ascii=False, indent=2)

def _envelope(
    *,
    ok: bool = True,
    summary: str = "",
    evidence: Optional[dict] = None,
    limits: Optional[dict] = None,
    next_hint: str = "",
    **extra: Any,
) -> str:
    payload: Dict[str, Any] = {
        "ok": ok,
        "summary": summary,
        "evidence": evidence or {},
        "limits": limits or {},
        "next_hint": next_hint,
    }
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
        from argus.llm.workspace import assert_not_original_target, rewrite_tool_paths

        arguments = rewrite_tool_paths(
            arguments,
            work_binary=sess.work_binary,
            original_binary=sess.original_binary,
        )
        if name in ("argus_patch", "argus_apply_plan", "argus_deobf"):
            for key in ("binary", "output", "patch"):
                err = assert_not_original_target(arguments.get(key), sess.original_binary)
                if err:
                    return _inject_task_fields(
                        _envelope(ok=False, summary=err, evidence={"error": "original_protected"}),
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
    # Discover may run without a known binary; everything else needs a file on disk
    if name.startswith("argus_") and name != "argus_discover":
        err = _require_binary(arguments)
        if err is not None:
            return err

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
            next_hint="use argus_find for license strings; do not invent function roles",
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

        found = find_in_binary(arguments["binary"], arguments.get("query"))
        # Put gate-scan guidance first — full hits often truncate past gate_symbols
        slim = {
            "ok": found.get("ok", True),
            "summary": found.get("summary"),
            "next_hint": found.get("next_hint"),
            "suggested_stubs": found.get("suggested_stubs") or [],
            "gate_symbols": (found.get("gate_symbols") or [])[:12],
            "gate_candidates": (found.get("gate_candidates") or [])[:10],
            "patch_candidates": (found.get("patch_candidates") or [])[:8],
            "stripped_like": found.get("stripped_like"),
            "hits": [
                {k: h.get(k) for k in ("addr", "kind", "preview", "score", "nearby_fn")}
                for h in (found.get("hits") or [])[:10]
            ],
            "evidence": {
                "suggested_stubs": found.get("suggested_stubs") or [],
                "gate_symbols": (found.get("gate_symbols") or [])[:12],
                "gate_candidates": (found.get("gate_candidates") or [])[:10],
                "patch_candidates": (found.get("patch_candidates") or [])[:8],
                "stripped_like": found.get("stripped_like"),
                "hits": [
                    {k: h.get(k) for k in ("addr", "kind", "preview", "score")}
                    for h in (found.get("hits") or [])[:8]
                ],
                "entry": (found.get("evidence") or {}).get("entry"),
                "fmt": (found.get("evidence") or {}).get("fmt"),
            },
            "verify": {"kind": "none", "ok": None},
        }
        return _truncate(slim, limit=14000)

    if name == "argus_xrefs":
        from argus.binary import load_binary
        from argus.find import find_string_xrefs, suggest_patches_near

        img = load_binary(arguments["binary"])
        addr = _parse_addr(arguments.get("addr"))
        if addr is None:
            return _envelope(ok=False, summary="addr required", evidence={"error": "bad addr"})
        xrefs = find_string_xrefs(img, addr)
        cands: list = []
        for xr in xrefs[:6]:
            cands.extend(suggest_patches_near(img, int(xr["addr"], 0)))
        return _envelope(
            ok=True,
            summary=f"xrefs={len(xrefs)} candidates={len(cands)}",
            evidence={"addr": hex(addr), "xrefs": xrefs, "patch_candidates": cands[:12]},
            next_hint=(
                f"argus_patch kind=force_branch addr={cands[0]['addr']}"
                if cands
                else "no jcc near xref; try another string"
            ),
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
                    verify={"kind": "none", "ok": None, "detail": note},
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
                "patch_plan": d.get("patch_plan") or [],
                "string_hits": d.get("string_hits") or [],
                "evidence": {
                    "gate_candidates": d.get("gate_candidates") or [],
                    "patch_plan": d.get("patch_plan") or [],
                    "string_hits": d.get("string_hits") or [],
                    "modules": d.get("modules") or [binary],
                    "pivoted": d.get("pivoted"),
                },
                "verify": {"kind": "none", "ok": None},
            },
            limit=14000,
        )

    if name == "argus_apply_plan":
        from argus.discover import discover_targets
        from argus.apply_plan import apply_plan

        binary = arguments["binary"]
        modules = arguments.get("modules")
        if not arguments.get("steps") and modules is None:
            disc = discover_targets("", binary=binary)
            modules = [m["path"] for m in (disc.get("linked") or [])] or None
        d = apply_plan(
            binary,
            output=arguments.get("output"),
            steps=arguments.get("steps"),
            query=arguments.get("query"),
            modules=modules,
        )
        return _truncate(
            {
                "ok": bool(d.get("ok")),
                "summary": d.get("summary"),
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


