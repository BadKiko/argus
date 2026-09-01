from __future__ import annotations

"""Deterministic agent bootstrap and next-step planner for weak LLMs."""

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.llm.intent import TaskKind, classify_task_intent
from argus.llm.investigate import run_investigate, suggest_next_tool


def is_weak_model(model: Optional[str]) -> bool:
    import os

    if os.environ.get("ARGUS_WEAK_MODEL", "").strip().lower() in ("1", "true", "yes"):
        return True
    m = (model or "").lower()
    return "flash-lite" in m or "flash_lite" in m


WEAK_SYSTEM = """You are Argus Agent — reverse-engineering assistant with deterministic tools.

Rules:
- MUST call tools; never invent results.
- Address EVERY task; bind EVERY tool call with for_task=<id>.
- Patch ONLY the work copy path.
- Tools return observations + hints.suggested_tools — hints are ideas only, not the binary's architecture. You form hypotheses from evidence.
- Static first: argus_find/atlas with user-task nouns (not the filename). On a hit, argus_diagnose_failure(error_text=verbatim preview), then argus_apply_plan. Do not argus_patch atlas jumps.
- Empty slice is incomplete, not failure.
- argus_exec is LAST RESORT when find/atlas return 0 hits. Never strings/readelf/nm.
- A CRT/_start lift is not a solved check. argus_ai is not for gate bypass.
- argus_apply_plan: omit steps= to use diagnose/slice plan, or copy suggested_batches[0]. Huge plans: first batch only.
- argus_diagnose_failure requires error_text= verbatim from find hits, user, or sandbox — never guess.
- CLI: verify stdout fragment. Do not argus_gui_oracle when there are no windows.
- On verify failure: capture exact text, then diagnose_failure → apply_plan (small batches).
- NEVER hardcode vendor addresses or one-off recipes — derive everything from tool evidence.
"""

_DIAGNOSE_STOP_WORDS = frozenset({
    "сделай", "чтобы", "любой", "любая", "любое", "чтобы", "программа", "программу",
    "make", "that", "with", "from", "this", "accept", "any", "key",
})

# Max patch steps per apply_plan call (gate tasks).
_DEFAULT_APPLY_BATCH = 3
_FAST_HUB_BATCH = 1


def default_max_steps_for_model(model: Optional[str]) -> int:
    """0.5: no weak-model step cap — use CLI --max-steps only."""
    import os

    if os.environ.get("ARGUS_AGENT_MAX_STEPS", "").strip():
        return 0
    return 0


def suggest_patch_batches(
    plan: List[Dict[str, Any]],
    *,
    exclude_addrs: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Return batch hints — LLM picks; does not apply."""
    if not plan:
        return {"full_plan": [], "suggested_batches": []}
    full = [dict(s) for s in plan]
    batches: List[Dict[str, Any]] = []
    pred = focus_corrective_patch(plan)
    if pred and any("validator" in str(s.get("taint_source") or "") for s in pred):
        batches.append(
            {
                "label": "predicate_gates",
                "steps": pred,
                "rationale": "validator_return gates nearest the observed string — apply this first",
            }
        )
    hub = trim_patch_plan(plan, max_steps=1, exclude_addrs=exclude_addrs, hub_first=True)
    if hub:
        batches.append({"label": "hub_first", "steps": hub, "rationale": "single ret_imm hub"})
    small = trim_patch_plan(plan, max_steps=_DEFAULT_APPLY_BATCH, exclude_addrs=exclude_addrs)
    if small and small != hub:
        batches.append({"label": "incremental_3", "steps": small, "rationale": "hub + gates"})
    diag = trim_patch_plan(plan, max_steps=len(plan), exclude_addrs=exclude_addrs, mode="diagnose")
    if diag:
        batches.append({"label": "full_diagnose_order", "steps": diag, "rationale": "complete corrective order"})
    return {"full_plan": full, "suggested_batches": batches}


def trim_patch_plan(
    plan: List[Dict[str, Any]],
    *,
    max_steps: int = _DEFAULT_APPLY_BATCH,
    exclude_addrs: Optional[Set[str]] = None,
    hub_first: bool = True,
    mode: str = "incremental",
) -> List[Dict[str, Any]]:
    """Return a small batch. mode='diagnose' applies full corrective ordering."""
    if not plan:
        return []
    exclude = set(exclude_addrs or ())

    def _addr_key(step: Dict[str, Any]) -> str:
        return str(step.get("addr") or "")

    def _allowed(step: Dict[str, Any]) -> bool:
        key = _addr_key(step)
        return bool(key) and key not in exclude

    if mode == "diagnose":
        order = {"ret_imm": 0, "force_branch": 1, "force_flag": 2, "nop_call": 3, "nop_bytes": 4}
        ranked = sorted(plan, key=lambda s: order.get(str(s.get("kind")), 9))
        out = [dict(s) for s in ranked if _allowed(s)][:max_steps]
        return out

    out: List[Dict[str, Any]] = []

    def _taint(step: Dict[str, Any]) -> str:
        return str(step.get("taint_source") or step.get("taint") or "").lower()

    if hub_first:
        for step in plan:
            if len(out) >= max_steps:
                break
            if step.get("kind") != "ret_imm":
                continue
            key = _addr_key(step)
            if not key or key in exclude:
                continue
            out.append(dict(step))
            if max_steps == _FAST_HUB_BATCH:
                return out

    seen = {_addr_key(s) for s in out}
    for step in plan:
        if len(out) >= max_steps:
            break
        if step.get("kind") != "force_branch":
            continue
        if "validator" not in _taint(step):
            continue
        key = _addr_key(step)
        if not key or key in exclude or key in seen:
            continue
        out.append(dict(step))
        seen.add(key)

    for step in plan:
        if len(out) >= max_steps:
            break
        if step.get("kind") != "force_branch":
            continue
        key = _addr_key(step)
        if not key or key in exclude or key in seen:
            continue
        out.append(dict(step))
        seen.add(key)

    if not out and hub_first:
        for step in plan:
            if len(out) >= max_steps:
                break
            key = _addr_key(step)
            if not key or key in exclude:
                continue
            out.append(dict(step))
    return out[:max_steps]


def focus_corrective_patch(
    plan: List[Dict[str, Any]],
    *,
    wide_threshold: int = 12,
    max_steps: int = 3,
) -> List[Dict[str, Any]]:
    """Narrow diagnose output: predicate gates near the sink, not every je in a parser."""
    if not plan:
        return []
    val = [
        dict(s)
        for s in plan
        if s.get("kind") == "force_branch"
        and "validator" in str(s.get("taint_source") or s.get("taint") or "").lower()
    ]
    if val:
        return val[:max_steps]
    if len(plan) > wide_threshold:
        return trim_patch_plan(plan, max_steps=max_steps)
    return [dict(s) for s in plan]


def extract_failure_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Parse sandbox/apply_plan failure into diagnose_failure args."""
    detail = str(payload.get("summary") or payload.get("detail") or "")
    sandbox = payload.get("sandbox") or {}
    verify = payload.get("verify") or {}
    if not detail:
        detail = str(sandbox.get("detail") or verify.get("detail") or "")
        pb = verify.get("patch_behavior") or {}
        if pb.get("detail"):
            detail = str(pb.get("detail"))
    crash_code = sandbox.get("crash_code") or payload.get("crash_code")
    error_text: Optional[str] = None
    for m in re.finditer(r"'([^']{12,200})'", detail):
        frag = m.group(1)
        if re.search(r"invalid|license|error|doesn|appear|valid|denied|incorrect", frag, re.I):
            error_text = frag
            break
    if not error_text:
        m = re.search(r"reject text visible: '([^']+)'", detail, re.I)
        if m:
            error_text = m.group(1)
    if not error_text:
        m = re.search(r"title '([^']+)'", detail, re.IGNORECASE)
        if m and re.search(r"invalid|error|license|denied", m.group(1), re.I):
            error_text = m.group(1)
    if not error_text and re.search(r"\binvalid\b|\bincorrect\b", detail, re.IGNORECASE):
        m = re.search(r"'([^']{12,120})'", detail)
        if m:
            error_text = m.group(1)
    last_addr = None
    applied = payload.get("applied") or []
    if applied:
        last_addr = (applied[-1] or {}).get("addr")
    return {
        "error_text": error_text,
        "crash_code": crash_code,
        "detail": detail,
        "last_patch_addr": last_addr,
    }


def _is_gate_task(intent: TaskKind, plan: List[Dict[str, Any]], user_prompt: str) -> bool:
    if intent == TaskKind.GATE_TRANSFORM:
        return True
    if plan and any(s.get("kind") in ("ret_imm", "force_branch") for s in plan):
        return True
    return bool(re.search(r"активир|лиценз|license|ключ|trial|serial", user_prompt, re.I))


def _diagnose_needles(
    boot: Dict[str, Any],
    ctx: Dict[str, Any],
    user_prompt: str,
) -> List[str]:
    """Build error_text candidates from runtime context — no vendor/product hardcoding."""
    needles: List[str] = []
    if ctx.get("error_text"):
        needles.append(str(ctx["error_text"]))
    if ctx.get("detail"):
        # Extract quoted fragments from sandbox/verify detail
        detail = str(ctx["detail"])
        for m in re.finditer(r"'([^']{8,120})'", detail):
            needles.append(m.group(1))
        for m in re.finditer(r'"([^"]{8,120})"', detail):
            needles.append(m.group(1))

    inv = boot.get("investigate") or {}
    find_q = (inv.get("find") or {}).get("query") or ""
    if find_q:
        needles.append(find_q[:80])
    for hit in (inv.get("find") or {}).get("hits") or []:
        if isinstance(hit, dict):
            s = hit.get("string") or hit.get("text")
            if s and len(str(s)) >= 6:
                needles.append(str(s)[:80])
    for obs in inv.get("observations") or []:
        if isinstance(obs, str) and len(obs) >= 8:
            needles.append(obs[:80])
    for m in re.finditer(r'["\']([^"\']{8,})["\']', user_prompt):
        needles.append(m.group(1))
    for word in re.findall(r"[A-Za-z\u0400-\u04FF]{5,}", user_prompt):
        if word.lower() not in _DIAGNOSE_STOP_WORDS:
            needles.append(word)

    # Skip task-shaped prompts as error_text (not dialog copy).
    task_markers = ("сделай", "make ", "чтобы", "please", "need ", "want ")
    up = user_prompt.lower()
    if any(m in up for m in task_markers) and len(user_prompt) > 40:
        needles = [n for n in needles if n != user_prompt.strip() and len(n) < 80]

    out: List[str] = []
    for n in needles:
        n = n.strip()
        if n and n not in out and len(n) >= 6:
            out.append(n)
    return out[:6]


def _run_diagnose(
    binary: str,
    boot: Dict[str, Any],
    ctx: Dict[str, Any],
    user_prompt: str,
    trace: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if ctx.get("crash_code"):
        diag_args: Dict[str, Any] = {
            "binary": binary,
            "for_task": 1,
            "crash_code": str(ctx["crash_code"]),
        }
        if ctx.get("last_patch_addr"):
            diag_args["last_patch_addr"] = str(ctx["last_patch_addr"])
        return _dispatch_and_trace("argus_diagnose_failure", diag_args, trace)

    best: Dict[str, Any] = {}
    for needle in _diagnose_needles(boot, ctx, user_prompt):
        diag_args = {"binary": binary, "for_task": 1, "error_text": needle}
        payload = _dispatch_and_trace("argus_diagnose_failure", diag_args, trace)
        corrective = list(
            (payload.get("evidence") or {}).get("corrective_patch")
            or payload.get("corrective_patch")
            or []
        )
        if corrective:
            return payload
        if payload.get("ok") and not best:
            best = payload
    return best or (trace[-1].get("result") if trace else {})


def _dispatch_and_trace(
    tool: str,
    args: Dict[str, Any],
    trace: List[Dict[str, Any]],
) -> Dict[str, Any]:
    from argus.llm.tools import dispatch_tool

    raw = dispatch_tool(tool, args)
    entry: Dict[str, Any] = {"tool": tool, "args": args, "result_preview": raw[:2000]}
    try:
        entry["result"] = json.loads(raw)
    except json.JSONDecodeError:
        entry["result"] = {"raw": raw}
    trace.append(entry)
    return entry["result"] if isinstance(entry["result"], dict) else {}


def run_gate_fast_path(
    binary: str,
    user_prompt: str,
    *,
    discover: Optional[dict] = None,
    original_binary: Optional[str] = None,
    tasks: Optional[List[Any]] = None,
    verbose: bool = False,
    max_rounds: int = 4,
) -> Dict[str, Any]:
    """Deterministic gate pipeline before LLM: bootstrap → incremental apply → diagnose recover."""
    from argus.llm.session import get_session

    sess = get_session()
    if sess.gate_fast_path_done:
        return {"done": False, "trace": [], "boot": {}, "brief": ""}
    sess.gate_fast_path_done = True

    boot = bootstrap_agent_context(
        binary,
        user_prompt,
        discover=discover,
        original_binary=original_binary,
        tasks=tasks,
    )
    plan = list(boot.get("patch_plan") or [])
    auto_diag: Dict[str, Any] = {}

    # Prefer auto-diagnose from rodata reject strings over blind gate_scan hubs.
    try:
        from argus.binary import load_binary
        from argus.flow import auto_diagnose_plan

        auto_diag = auto_diagnose_plan(load_binary(binary))
        auto_patch = list(auto_diag.get("corrective_patch") or [])
        if auto_patch:
            plan = auto_patch
            if verbose:
                print(f"[fast-path] auto_diagnose plan steps={len(plan)}", flush=True)
    except Exception:
        pass

    intent = TaskKind((boot.get("investigate") or {}).get("intent") or "general")
    if not _is_gate_task(intent, plan, user_prompt):
        return {"done": False, "trace": [], "boot": boot, "brief": boot.get("brief") or ""}

    from argus.llm.session import record_gate_scan_result

    if plan:
        record_gate_scan_result(
            binary,
            plan,
            full={"patch_plan": plan},
            query=user_prompt[:120],
        )

    trace: List[Dict[str, Any]] = []
    tried_addrs: Set[str] = set()
    last_detail = ""

    diagnose_plan = bool(plan and any(s.get("kind") in ("force_branch", "force_flag", "nop_call") for s in plan))

    for round_idx in range(max_rounds):
        use_mode = "diagnose" if diagnose_plan else "incremental"
        batch_size = _FAST_HUB_BATCH if round_idx == 0 and use_mode == "incremental" else _DEFAULT_APPLY_BATCH
        batch = trim_patch_plan(
            plan,
            max_steps=len(plan) if use_mode == "diagnose" else batch_size,
            exclude_addrs=tried_addrs,
            mode=use_mode,
        )
        if not batch:
            break
        for s in batch:
            tried_addrs.add(str(s.get("addr") or ""))

        record_gate_scan_result(
            binary,
            batch,
            full={"patch_plan": batch},
            query=user_prompt[:120],
        )

        if verbose:
            print(f"[fast-path] round {round_idx + 1} apply_plan steps={len(batch)}", flush=True)
        result = _dispatch_and_trace(
            "argus_apply_plan",
            {"binary": binary, "steps": batch, "for_task": 1},
            trace,
        )
        if result.get("ok"):
            return {"done": True, "trace": trace, "boot": boot, "brief": boot.get("brief") or "", "result": result}

        last_detail = str(result.get("summary") or "")
        ctx = extract_failure_context(result)
        if verbose:
            print(f"[fast-path] diagnose ctx={ctx}", flush=True)
        diag = _run_diagnose(binary, boot, ctx, user_prompt, trace)
        corrective = list(
            (diag.get("evidence") or {}).get("corrective_patch") or diag.get("corrective_patch") or []
        )
        if not corrective:
            corrective = list((diag.get("evidence") or {}).get("patch_plan") or [])
        if corrective:
            plan = corrective + [s for s in plan if str(s.get("addr")) not in tried_addrs]
            fix_batch = trim_patch_plan(
                corrective,
                max_steps=len(corrective),
                exclude_addrs=tried_addrs,
                mode="diagnose",
            )
            if fix_batch:
                for s in fix_batch:
                    tried_addrs.add(str(s.get("addr") or ""))
                record_gate_scan_result(
                    binary,
                    fix_batch,
                    full={"patch_plan": fix_batch},
                    query=user_prompt[:120],
                )
                if verbose:
                    print(f"[fast-path] corrective apply steps={len(fix_batch)}", flush=True)
                fix_res = _dispatch_and_trace(
                    "argus_apply_plan",
                    {"binary": binary, "steps": fix_batch, "for_task": 1},
                    trace,
                )
                if fix_res.get("ok"):
                    return {
                        "done": True,
                        "trace": trace,
                        "boot": boot,
                        "brief": boot.get("brief") or "",
                        "result": fix_res,
                    }

    brief = boot.get("brief") or ""
    if last_detail:
        brief += f"\nFAST PATH ({len(trace)} tool calls): last failure — {last_detail[:200]}"
    return {"done": False, "trace": trace, "boot": boot, "brief": brief}


def gate_loop_detected(tool_trace: List[Dict[str, Any]], *, window: int = 8) -> bool:
    """Detect decision_flow ↔ apply_plan churn without diagnose."""
    recent = [e.get("tool") for e in tool_trace[-window:] if e.get("tool")]
    if len(recent) < 4:
        return False
    if "argus_diagnose_failure" in recent:
        return False
    flow_apply = sum(
        1
        for i in range(1, len(recent))
        if recent[i - 1] in ("argus_decision_flow", "argus_apply_plan")
        and recent[i] in ("argus_decision_flow", "argus_apply_plan")
    )
    return flow_apply >= 3


def bootstrap_evidence(
    binary: str,
    user_prompt: str,
    *,
    discover: Optional[dict] = None,
    original_binary: Optional[str] = None,
) -> Dict[str, Any]:
    """Lightweight pre-LLM evidence — no auto-slice, no imperative NEXT_ACTION."""
    from argus.binary import load_binary
    from argus.deobf import detect_protection
    from argus.flow import discover_reject_ui_strings
    from argus.llm.intent import task_signals

    img = load_binary(binary)
    prot = detect_protection(img)
    sym_count = sum(1 for s in img.symbols.values() if s.is_function and not s.is_import)
    reject_hints = discover_reject_ui_strings(img, limit=8)
    signals = task_signals(user_prompt, binary=original_binary or binary, discover=discover)

    observations = [
        f"Binary {img.fmt}/{img.arch} entry={hex(img.entry)} protection={prot.kind} symbols≈{sym_count}",
    ]
    if reject_hints:
        observations.append(
            "reject_ui_candidates: " + " | ".join(reject_hints[:3])
        )

    suggested_tools: List[Dict[str, Any]] = [
        {"tool": "argus_analyze", "reason": "confirm format/protection", "confidence": 0.9},
        {"tool": "argus_find", "reason": "search needles from user task (query=)", "confidence": 0.85},
        {"tool": "argus_investigate", "reason": "full observe pass when task is unclear", "confidence": 0.7},
    ]
    if reject_hints:
        suggested_tools.append(
            {
                "tool": "argus_diagnose_failure",
                "reason": "pick error_text verbatim from reject_ui_candidates matching user intent",
                "confidence": 0.65,
            }
        )

    lines = [
        "EVIDENCE REPORT (observations — you choose the next experiment):",
        *observations,
        f"task_signals (hints only): {json.dumps(signals, ensure_ascii=False)}",
    ]
    if reject_hints:
        lines.append("reject_ui_candidates (unverified — pick one for diagnose_failure error_text=):")
        for r in reject_hints[:6]:
            lines.append(f"  - {r!r}")
    if discover and discover.get("install_dir"):
        lines.append(f"install_dir: {discover['install_dir']}")
    lines.append(
        "hints.suggested_tools: " + json.dumps(suggested_tools[:5], ensure_ascii=False)
    )

    return {
        "brief": "\n".join(lines),
        "observations": observations,
        "hints": {"suggested_tools": suggested_tools, "task_signals": signals},
        "reject_ui_candidates": reject_hints,
        "patch_plan": [],
    }


def bootstrap_agent_context(
    binary: str,
    user_prompt: str,
    *,
    discover: Optional[dict] = None,
    original_binary: Optional[str] = None,
    tasks: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """Run investigate (+ optional flow) before first LLM step."""
    from argus.llm.session import get_session

    sess = get_session()
    task_text = user_prompt
    if tasks:
        task_text = "; ".join(getattr(t, "text", str(t)) for t in tasks)

    inv = run_investigate(
        binary,
        query=user_prompt[:120],
        original_binary=original_binary,
        discover=discover,
        task_text=task_text,
    )
    sess.last_investigate = inv

    intent = TaskKind(inv.get("intent") or "general")
    if intent == TaskKind.GENERAL:
        intent = classify_task_intent(task_text, binary=binary, discover=discover)
    slice_data = inv.get("_slice_full") or inv.get("slice") or {}
    plan = list(slice_data.get("patch_plan") or inv.get("slice", {}).get("patch_plan") or [])

    flow_summary = ""
    if intent == TaskKind.GATE_TRANSFORM and plan:
        try:
            from argus.binary import load_binary
            from argus.flow import build_decision_flow

            top_addr = None
            for step in plan:
                raw = step.get("addr")
                if raw:
                    top_addr = int(str(raw), 0) if isinstance(raw, str) else int(raw)
                    break
            if top_addr:
                img = load_binary(binary)
                graph = build_decision_flow(img, top_addr)
                flow_summary = graph.to_text_flow()
        except Exception:
            pass

    if not plan and discover:
        linked = discover.get("linked") or discover.get("install_modules_hint") or []
        if linked and intent == TaskKind.GATE_TRANSFORM:
            modules = []
            for m in linked[:6]:
                p = m.get("path") if isinstance(m, dict) else m
                if p:
                    modules.append(str(p))
            if modules:
                from argus.find_slice import gate_scan_modules

                widened = gate_scan_modules(binary, modules=modules, query=user_prompt[:120])
                plan = list(widened.get("patch_plan") or [])
                if plan:
                    slice_data = widened
                    inv["slice"] = {
                        **(inv.get("slice") or {}),
                        "patch_plan": plan,
                        "summary": widened.get("summary"),
                    }
                    sess.last_slice_patch_plan = plan

    if plan:
        from argus.llm.session import record_gate_scan_result

        record_gate_scan_result(
            binary,
            plan,
            full=slice_data if slice_data else {"patch_plan": plan},
            query=user_prompt[:120],
        )

    reject_hints: List[str] = []
    try:
        from argus.binary import load_binary
        from argus.flow import discover_reject_ui_strings

        reject_hints = discover_reject_ui_strings(load_binary(binary), limit=5)
    except Exception:
        pass

    from argus.llm.investigate import rank_tool_suggestions

    ranked = rank_tool_suggestions(
        intent=intent,
        analyze_ok=True,
        find_ok=bool((inv.get("find") or {}).get("hits")),
        slice_data={"patch_plan": plan, **slice_data},
    )

    batch_hints = suggest_patch_batches(plan) if plan else {"full_plan": [], "suggested_batches": []}

    observations = list(inv.get("observations") or [])[:8]
    lines = [
        "EVIDENCE REPORT (from investigate — hypotheses unverified):",
        f"legacy_intent={intent.value} patch_plan_steps={len(plan)} plan_confident={slice_data.get('plan_confident')}",
    ]
    if observations:
        lines.append("observations: " + " | ".join(observations[:4]))
    if reject_hints:
        lines.append(
            "reject_ui_candidates: " + " | ".join(reject_hints[:3])
        )
    if flow_summary:
        lines.append("decision_flow:\n" + flow_summary[:1200])
    if ranked:
        lines.append(
            "hints.suggested_tools: " + json.dumps(ranked[:5], ensure_ascii=False)
        )
    if batch_hints.get("suggested_batches"):
        lines.append(
            "hints.suggested_batches (pick one — copy steps= into apply_plan): "
            + json.dumps(
                [{"label": b["label"], "step_count": len(b.get("steps") or [])} for b in batch_hints["suggested_batches"]],
                ensure_ascii=False,
            )
        )

    return {
        "brief": "\n".join(lines),
        "investigate": inv,
        "next_action": None,
        "next_tool": ranked[0]["tool"] if ranked else None,
        "next_reason": ranked[0]["reason"] if ranked else "",
        "patch_plan": plan,
        "hints": {"suggested_tools": ranked, "suggested_batches": batch_hints.get("suggested_batches")},
        "observations": observations,
    }


def _build_next_action(
    tool: str,
    binary: str,
    plan: List[Dict[str, Any]],
    intent: TaskKind,
    *,
    query: str = "",
    discover: Optional[dict] = None,
) -> Optional[Dict[str, Any]]:
    args: Dict[str, Any] = {"binary": binary, "for_task": 1}
    if tool == "argus_apply_plan" and plan:
        args["steps"] = trim_patch_plan(plan, max_steps=_DEFAULT_APPLY_BATCH)
        return {"tool": tool, "args": args}
    if tool == "argus_slice":
        args["query"] = query
        args["multi"] = True
        if discover:
            linked = discover.get("linked") or []
            mods = [m.get("path") for m in linked[:6] if isinstance(m, dict) and m.get("path")]
            if mods:
                args["modules"] = mods
        return {"tool": tool, "args": args}
    if tool == "argus_discover":
        inst = ""
        if discover and discover.get("install_dir"):
            inst = discover["install_dir"]
        args = {"prompt": query, "for_task": 1}
        if inst:
            args["root"] = inst
        return {"tool": tool, "args": args}
    if tool == "argus_ai" and intent == TaskKind.PASSWORD:
        return {"tool": tool, "args": {"binary": binary, "prompt": query or "password", "for_task": 1}}
    if tool == "argus_solve" and intent == TaskKind.PASSWORD:
        return {"tool": tool, "args": {"binary": binary, "deobf": True, "for_task": 1}}
    if tool == "argus_decision_flow" and plan:
        addr = plan[0].get("addr")
        if addr:
            args["target"] = str(addr)
            return {"tool": tool, "args": args}
    if tool == "argus_diagnose_failure":
        if query:
            args["error_text"] = query[:120]
        return {"tool": tool, "args": args, "note": "error_text required — use verbatim dialog text"}
    if tool == "argus_investigate":
        args["query"] = query
        args["task"] = query
        return {"tool": tool, "args": args}
    return {"tool": tool, "args": args}


def recovery_hints_from_trace(
    tool_trace: List[Dict[str, Any]],
    *,
    binary: str,
    user_prompt: str,
    discover: Optional[dict] = None,
) -> str:
    """Text hints only — never dispatches tools."""
    from argus.llm.investigate import rank_tool_suggestions
    from argus.llm.session import get_session

    sess = get_session()
    inv = sess.last_investigate or {}
    slice_data = inv.get("_slice_full") or inv.get("slice") or {}
    plan = list(slice_data.get("patch_plan") or [])
    intent = classify_task_intent(user_prompt, binary=binary)
    tried = [e.get("tool") for e in tool_trace if e.get("tool")]

    for entry in tool_trace:
        if entry.get("tool") not in ("argus_slice", "argus_investigate"):
            continue
        raw = entry.get("result")
        payload = raw if isinstance(raw, dict) else {}
        if isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {}
        p = payload.get("patch_plan") or (payload.get("evidence") or {}).get("patch_plan") or []
        if isinstance(p, list) and len(p) > len(plan):
            plan = p

    verify_failed = False
    last_fail_ctx: Dict[str, Any] = {}
    for entry in reversed(tool_trace):
        if entry.get("tool") != "argus_apply_plan":
            continue
        raw = entry.get("result")
        payload = raw if isinstance(raw, dict) else {}
        if isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {}
        if payload.get("ok") is False:
            verify_failed = True
            last_fail_ctx = extract_failure_context(payload)
            break

    hints: List[str] = []
    ranked = rank_tool_suggestions(
        intent=intent,
        analyze_ok=True,
        find_ok=True,
        slice_data={"patch_plan": plan},
        tools_tried=tried,
        verify_ok=False if verify_failed else None,
    )
    if ranked:
        hints.append(
            "hints.suggested_tools: " + json.dumps(ranked[:4], ensure_ascii=False)
        )

    if verify_failed:
        err = last_fail_ctx.get("error_text")
        if err:
            hints.append(f"last_failure fragment (use for diagnose_failure error_text=): {err!r}")
        else:
            hints.append(
                "verify failed but no error_text extracted — run argus_sandbox_test or capture dialog verbatim"
            )

    if (
        not plan
        and "argus_slice" in tried
        and discover
        and not sess.auto_pivot_done
    ):
        linked = discover.get("linked") or []
        mods = [m.get("path") for m in linked[:8] if isinstance(m, dict) and m.get("path")]
        if mods:
            hints.append(
                f"pivot_candidate: patch_plan empty — consider argus_slice(modules={mods[:3]!r})"
            )

    if gate_loop_detected(tool_trace):
        hints.append(
            "LOOP detected: decision_flow ↔ apply_plan churn — use argus_diagnose_failure with verbatim error_text"
        )

    return "\n".join(hints)


def suggest_next_action_from_trace(
    tool_trace: List[Dict[str, Any]],
    *,
    binary: str,
    user_prompt: str,
    discover: Optional[dict] = None,
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Legacy helper — returns hint metadata, not for auto-dispatch."""
    ranked_text = recovery_hints_from_trace(
        tool_trace, binary=binary, user_prompt=user_prompt, discover=discover
    )
    from argus.llm.investigate import rank_tool_suggestions
    from argus.llm.session import get_session

    sess = get_session()
    inv = sess.last_investigate or {}
    plan = list((inv.get("slice") or {}).get("patch_plan") or [])
    intent = classify_task_intent(user_prompt, binary=binary)
    tried = [e.get("tool") for e in tool_trace if e.get("tool")]
    ranked = rank_tool_suggestions(
        intent=intent,
        analyze_ok=True,
        find_ok=True,
        slice_data={"patch_plan": plan},
        tools_tried=tried,
    )
    if not ranked:
        return None, ranked_text
    top = ranked[0]
    return {"tool": top["tool"], "args": {"binary": binary, "for_task": 1}, "hint_only": True}, top.get("reason", "")


def format_next_action_hint(action: Optional[Dict[str, Any]], reason: str = "") -> str:
    if not action:
        return ""
    parts = [f"Suggested next: {action.get('tool')}"]
    if reason:
        parts.append(f"({reason})")
    parts.append(f"args={json.dumps(action.get('args') or {}, ensure_ascii=False)}")
    return " ".join(parts)
