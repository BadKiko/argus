from __future__ import annotations

"""MCP-style tools the LLM can call — each maps to real Argus pipelines."""

import json
from typing import Any, Dict, List, Optional


def openai_tool(name: str, description: str, properties: dict, required: Optional[List[str]] = None) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required or [],
            },
        },
    }


ARGUS_TOOLS: List[dict] = [
    openai_tool(
        "argus_ai",
        "Natural-language solve/deobf/patch/lift. Prefer this for user intents like 'дай пароль'. "
        "For bypass/remove check prefer argus_patch after argus_find.",
        {
            "prompt": {"type": "string", "description": "RU/EN request"},
            "binary": {"type": "string", "description": "Path to ELF/PE"},
            "output": {"type": "string", "description": "Optional output path for patches"},
        },
        ["prompt", "binary"],
    ),
    openai_tool(
        "argus_analyze",
        "Show binary format, arch, entry, symbols, detected protection.",
        {"binary": {"type": "string"}},
        ["binary"],
    ),
    openai_tool(
        "argus_detect",
        "Detect protection class: none|ollvm|vmp|themida|mixed|unknown.",
        {"binary": {"type": "string"}},
        ["binary"],
    ),
    openai_tool(
        "argus_find",
        "Find license/auth strings and return ranked hits, gate_candidates (scored VA patches), "
        "gate_symbols/suggested_stubs when named. For unlock: prefer suggested_stubs; else "
        "gate_candidates with ui_label_only=false. Re-find after patch; never claim unlock on UI-only.",
        {
            "binary": {"type": "string"},
            "query": {"type": "string", "description": "Extra keywords / phrase e.g. 'free version'"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_xrefs",
        "Find code xrefs to a string/data VA and nearby force_branch/nop_bytes candidates.",
        {
            "binary": {"type": "string"},
            "addr": {"type": "string", "description": "VA from argus_find hit, e.g. 0x4f2a41"},
        },
        ["binary", "addr"],
    ),
    openai_tool(
        "argus_solve",
        "Symbolic/concolic crackme solve. Pass find= success stdout needle. Use deobf=true for OLLVM flattened binaries.",
        {
            "binary": {"type": "string"},
            "deobf": {"type": "boolean", "description": "Unflatten CFF before solve"},
            "find": {"type": "string", "description": "Success needle in stdout (required unless binary has accepted symbol)"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_deobf",
        "CFF unflatten recovery and optional patch write.",
        {
            "binary": {"type": "string"},
            "function": {"type": "string"},
            "patch": {"type": "string", "description": "Output patched binary path"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_lift",
        "Lift function to pseudo-C (bounded). Pass function name or 0xaddr from argus_find.",
        {
            "binary": {"type": "string"},
            "function": {"type": "string"},
        },
        ["binary"],
    ),
    openai_tool(
        "argus_patch",
        "Write a patched binary WITHOUT breaking app startup. "
        "For license unlock: use argus_find suggested_stubs OR gate_candidates "
        "(prefer ui_label_only=false, higher score). kind=ret_imm/force_branch/nop_bytes. "
        "After patch, call argus_find again for Unregistered — if still primary and only "
        "ui_label_only was patched, unlock is incomplete. "
        "Do not ret_imm UI *Callback*/*Widget* alone. replace_string only changes UI text. "
        "If error Text file busy / ETXTBSY: quit the running app and retry. Never stub main/entry.",
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
            "taken": {"type": "boolean", "description": "force_branch: take branch if true"},
            "value": {"type": "integer", "description": "ret_imm return value (0=OK-style gate, 1=bool true)"},
            "old": {
                "type": "string",
                "description": "replace_string: exact existing substring from argus_find hits",
            },
            "new": {
                "type": "string",
                "description": "replacement; MUST be ≤ len(old) UTF-8 bytes — pad with spaces, never longer",
            },
            "output": {"type": "string"},
        },
        ["binary", "kind"],
    ),
    openai_tool(
        "argus_cfg",
        "Build CFG summary: block/edge counts for a function or entry.",
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
    text = obj if isinstance(obj, str) else json.dumps(_json_safe(obj), ensure_ascii=False, indent=2)
    if len(text) > limit:
        return text[:limit] + f"\n… truncated ({len(text)} chars)"
    return text


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


def dispatch_tool(name: str, arguments: Dict[str, Any]) -> str:
    """Execute one Argus tool; return JSON/text for the model."""
    try:
        # All current Argus tools need a real binary on disk
        if name.startswith("argus_"):
            err = _require_binary(arguments)
            if err is not None:
                return err

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
            # Put unlock guidance first — full hits often truncate past gate_symbols
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

            r = ask(
                arguments["binary"],
                Hint(want=Want.LIFT, function=arguments.get("function"), note="llm tool lift"),
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
            # Static unlock verify hint for agent
            if r.ok and r.patched_path and kind.value in (
                "ret_imm",
                "force_branch",
                "skip_check",
                "nop_bytes",
                "always_true",
            ):
                try:
                    from argus.find import find_in_binary
                    import json as _json

                    prev = _json.loads(env) if isinstance(env, str) else {}
                    vf = find_in_binary(
                        r.patched_path,
                        "Unregistered unregistered Buy License",
                        limit=12,
                        with_xrefs=False,
                    )
                    still = [
                        h.get("preview")
                        for h in (vf.get("hits") or [])
                        if h.get("kind") == "string"
                        and any(
                            x in (h.get("preview") or "").lower()
                            for x in ("unregistered", "buy license")
                        )
                    ][:5]
                    note = (
                        "unlock_verify: Unregistered/Buy License strings still present — "
                        "do NOT claim full activation; try next gate_candidate"
                        if still
                        else "unlock_verify: no Unregistered/Buy License string hits (weak positive)"
                    )
                    return _envelope(
                        ok=bool(r.ok),
                        summary=str(prev.get("summary") or r.answer or ""),
                        evidence={
                            **(prev.get("evidence") or {}),
                            "unlock_verify": {"still_locked_strings": still, "note": note},
                        },
                        next_hint=note if still else (prev.get("next_hint") or ""),
                        patched_path=r.patched_path,
                    )
                except Exception:
                    pass
            return env

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
    except OSError as e:
        err = str(e)
        if e.errno == 26 or "Text file busy" in err or "ETXTBSY" in err:
            return _envelope(
                ok=False,
                summary="Text file busy (ETXTBSY): target binary is running — quit the app, then retry patch",
                evidence={"error": err, "errno": getattr(e, "errno", None)},
                next_hint="close the running program and patch again",
                error=err,
                tool=name,
            )
        return _envelope(ok=False, summary=err, evidence={"error": err, "tool": name}, error=err, tool=name)
    except Exception as e:
        return _envelope(ok=False, summary=str(e), evidence={"error": str(e), "tool": name}, error=str(e), tool=name)
