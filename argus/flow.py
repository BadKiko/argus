"""Argus Semantic Decision Flow Engine.

Constructs compact decision graphs (CDG / Flow Slices) between function entry,
validator calls, and decision sinks (Error Dialogs vs Success Handlers).
Enables the LLM to inspect full cause-and-effect control logic in small tokens.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np


@dataclass
class DecisionGate:
    addr: int
    mnemonic: str
    op_str: str
    target_addr: Optional[int]
    predicate: str
    producer_call: Optional[Dict[str, Any]] = None
    taken_sink: Optional[str] = None
    fallthrough_sink: Optional[str] = None
    recommended_action: str = ""
    score: int = 100
    taint_source: str = ""
    dominates_error: bool = False


@dataclass
class DecisionGraph:
    func_addr: int
    func_name: str
    func_size: int
    gates: List[DecisionGate] = field(default_factory=list)
    validator_hubs: List[Dict[str, Any]] = field(default_factory=list)
    sinks: List[Dict[str, Any]] = field(default_factory=list)

    def to_text_flow(self) -> str:
        """Format a human- and LLM-friendly compact decision tree."""
        lines = [
            f"Function: {self.func_name} @ {hex(self.func_addr)} [size: {self.func_size}B]",
            f"Decision Summary: {len(self.gates)} gates, {len(self.validator_hubs)} validator hubs, {len(self.sinks)} sinks",
            "Control Flow Slice:",
            f"  [ENTRY @ {hex(self.func_addr)}]",
        ]

        if not self.gates:
            lines.append("    (No conditional decision gates found in function body)")
            return "\n".join(lines)

        for i, g in enumerate(self.gates, 1):
            lines.append("    |")
            if g.producer_call:
                p = g.producer_call
                lines.append(
                    f"    v [CALL {hex(p['target'])}: {p.get('name', 'callee')} (in-degree={p.get('in_degree', 1)})]"
                )
                lines.append("    |")

            pred_str = f" ({g.predicate})" if g.predicate else ""
            taint_lbl = f" [Taint: {g.taint_source}]" if g.taint_source else ""
            lines.append(f"    Gate {i} @ {hex(g.addr)}: {g.mnemonic} {g.op_str}{pred_str}{taint_lbl}")

            taken_label = (
                f"---> {g.taken_sink}"
                if g.taken_sink
                else f"---> Jump to {hex(g.target_addr) if g.target_addr else 'target'}"
            )
            fall_label = (
                f"---> {g.fallthrough_sink}"
                if g.fallthrough_sink
                else "---> Fallthrough (Next Block)"
            )

            lines.append(f"      +-- [{g.mnemonic.upper()} (Taken)] {taken_label}")
            lines.append(f"      \\-- [FALLTHROUGH]     {fall_label}")

        lines.append("")
        lines.append("Recommended Strategy:")
        patches = self.synthesize_patch_plan()
        if not patches:
            lines.append("  (Inspect gates manually via argus_disasm)")
        else:
            for p in patches:
                lines.append(f"  * {p['kind']} @ {p['addr']}: {p['why']}")

        return "\n".join(lines)

    def synthesize_patch_plan(self, img: Any = None) -> List[Dict[str, Any]]:
        """Synthesize minimal, high-confidence patch steps from the decision graph."""
        from argus.find import _is_safe_boolean_validator

        gate_callees = {
            g.producer_call["target"]
            for g in self.gates
            if g.producer_call and g.producer_call.get("target")
        }

        plan: List[Dict[str, Any]] = []
        for h in self.validator_hubs:
            tgt = h["target"]
            # Only stub validators on the gate path inside THIS function — not global fan-out hubs.
            if tgt not in gate_callees:
                continue
            indeg = h.get("in_degree", 0)
            if not (3 <= indeg <= 12):
                continue
            if img is not None and not _is_safe_boolean_validator(img, tgt):
                continue
            plan.append({
                "kind": "ret_imm",
                "addr": hex(tgt),
                "value": 1,
                "why": (
                    f"Function-local validator hub (in-degree={indeg}) "
                    "called immediately before decision gates"
                ),
            })

        for g in self.gates:
            if g.recommended_action == "force_taken":
                plan.append({
                    "kind": "force_branch",
                    "addr": hex(g.addr),
                    "taken": True,
                    "why": "Force jump to bypass error sink",
                    "taint_source": g.taint_source or "",
                })
            elif g.recommended_action == "force_fallthrough":
                plan.append({
                    "kind": "force_branch",
                    "addr": hex(g.addr),
                    "taken": False,
                    "why": "NOP conditional branch that jumps into error sink",
                    "taint_source": g.taint_source or "",
                })

        if img is not None:
            plan = enrich_patch_plan(img, self, plan)
        return plan


def scan_topological_hubs(
    img: Any,
    *,
    min_indegree: int = 4,
    max_indegree: int = 250,
    min_size: int = 128,
    max_size: int = 8192,
) -> List[Dict[str, Any]]:
    """Discover central validator hubs across the binary without needing strings."""
    sec = None
    for s in getattr(img, "sections", []):
        if getattr(s, "name", "") in (".text", "code", "text"):
            sec = s
            break
    if not sec or not getattr(sec, "data", None):
        return []

    data = sec.data
    base = sec.addr

    calls = []
    for shift in range(4):
        chunk_len = (len(data) - shift) // 4 * 4
        arr = np.frombuffer(data[shift : shift + chunk_len], dtype=np.int32)
        offsets = (np.arange(len(arr), dtype=np.int64) * 4 + shift).astype(np.int64)
        targets = base + offsets + 4 + arr.astype(np.int64)
        valid_mask = offsets > 0
        for idx in np.flatnonzero(valid_mask):
            off = int(offsets[idx])
            if data[off - 1] == 0xE8:
                tgt = int(targets[idx])
                if base <= tgt < base + len(data):
                    calls.append(tgt)

    counts = Counter(calls)
    from argus.disasm.recovery import function_covering

    hubs = []
    for tgt, cnt in counts.items():
        if min_indegree <= cnt <= max_indegree:
            bound = function_covering(img, tgt)
            sz = (bound.end - bound.start) if bound else 0
            if min_size <= sz <= max_size:
                name = img.symbols[tgt].name if tgt in getattr(img, "symbols", {}) else f"sub_{tgt:x}"
                epilogue = img.read_bytes(max(tgt, (bound.end - 32) if bound else tgt), 32)
                is_bool = any(b in epilogue for b in (b"\xb8\x01\x00\x00\x00", b"\x31\xc0", b"\x0f\x94", b"\x0f\x95"))
                score = cnt * 10 + (sz // 16) + (50 if is_bool else 0)
                hubs.append({
                    "target": tgt,
                    "name": name,
                    "in_degree": cnt,
                    "size": sz,
                    "is_bool_signature": is_bool,
                    "score": score,
                })

    hubs.sort(key=lambda x: -x["score"])
    return hubs[:12]


def build_decision_flow(
    img: Any,
    target: Union[int, str],
) -> DecisionGraph:
    """Build a compact decision graph starting from target address, function, or error string."""
    import capstone as cs
    from argus.disasm.recovery import function_covering
    from argus.find import count_function_callers, find_string_xrefs_multi

    func_addr = 0
    if isinstance(target, str):
        target = target.strip()
        if target.startswith("0x") or target.startswith("0X"):
            func_addr = int(target, 16)
        elif target.isdigit():
            func_addr = int(target)
        elif target in getattr(img, "symbols", {}):
            func_addr = img.symbols[target].addr
        else:
            needle = target.encode("utf-8")
            for s in getattr(img, "sections", []):
                if s.readable and s.data:
                    idx = s.data.find(needle)
                    if idx != -1:
                        s_va = s.addr + idx
                        xrefs = find_string_xrefs_multi(img, [s_va]).get(s_va, [])
                        if xrefs:
                            x_addr = int(xrefs[0]["addr"], 16)
                            bound = function_covering(img, x_addr)
                            if bound:
                                cx = find_string_xrefs_multi(img, [bound.start]).get(bound.start, [])
                                if cx:
                                    ca = int(cx[0]["addr"], 16)
                                    cbound = function_covering(img, ca)
                                    func_addr = cbound.start if cbound else ca
                                else:
                                    func_addr = bound.start
                        break
    elif isinstance(target, int):
        func_addr = target

    if not func_addr:
        top_hubs = scan_topological_hubs(img)
        func_addr = top_hubs[0]["target"] if top_hubs else getattr(img, "entry", 0)

    bound = function_covering(img, func_addr)
    start_addr = bound.start if bound else func_addr
    func_size = (bound.end - bound.start) if bound else 0x400
    func_size = min(max(func_size, 64), 0x2000)

    mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    data = img.read_bytes(start_addr, func_size)
    insns = list(md.disasm(data, start_addr))

    name = img.symbols[start_addr].name if start_addr in getattr(img, "symbols", {}) else f"sub_{start_addr:x}"

    graph = DecisionGraph(
        func_addr=start_addr,
        func_name=name,
        func_size=func_size,
    )

    called_targets: Dict[int, int] = {}
    for insn in insns:
        if insn.mnemonic == "call":
            try:
                op_str = insn.op_str
                if op_str.startswith("0x"):
                    tgt = int(op_str, 16)
                    nc = count_function_callers(img, tgt)
                    called_targets[tgt] = nc
                    if nc >= 3 and not any(h["target"] == tgt for h in graph.validator_hubs):
                        tname = img.symbols[tgt].name if tgt in getattr(img, "symbols", {}) else f"sub_{tgt:x}"
                        graph.validator_hubs.append({
                            "target": tgt,
                            "name": tname,
                            "in_degree": nc,
                        })
            except Exception:
                pass

    for i, insn in enumerate(insns):
        m = insn.mnemonic
        if m.startswith("j") and m not in ("jmp", "jecxz", "jrcxz"):
            target_addr = None
            try:
                target_addr = int(insn.op_str, 16)
            except Exception:
                pass

            pred_str = ""
            for b in range(max(0, i - 4), i):
                if insns[b].mnemonic in ("test", "cmp", "sete", "setne"):
                    pred_str = f"{insns[b].mnemonic} {insns[b].op_str}"

            prod_call = None
            for b in range(max(0, i - 8), i):
                if insns[b].mnemonic == "call":
                    try:
                        ct = int(insns[b].op_str, 16)
                        prod_call = {
                            "addr": insns[b].address,
                            "target": ct,
                            "in_degree": called_targets.get(ct, 1),
                            "name": img.symbols[ct].name if ct in getattr(img, "symbols", {}) else f"sub_{ct:x}",
                        }
                    except Exception:
                        pass

            taken_sink = None
            fall_sink = None
            recommended = ""

            is_cmp_1 = ", 1" in pred_str or " 1" in pred_str or "sete" in pred_str
            is_test_or_0 = "test " in pred_str or ", 0" in pred_str or ", rax" in pred_str or "setne" in pred_str

            if is_cmp_1:
                # Comparison against 1 (True): je -> Success, jne -> Error
                if m in ("je", "jz"):
                    taken_sink = "SINK_SUCCESS: Proceeds to Success Handler"
                    fall_sink = "SINK_ERROR: Error Dialog / Reject"
                    recommended = "force_taken"
                elif m in ("jne", "jnz"):
                    taken_sink = "SINK_ERROR: Error Dialog / Reject"
                    fall_sink = "SINK_SUCCESS: Proceeds to Success Handler"
                    recommended = "force_fallthrough"
            elif is_test_or_0:
                # Comparison against 0 (False): jne -> Success, je -> Error
                if m in ("jne", "jnz"):
                    taken_sink = "SINK_SUCCESS: Proceeds to Success Handler"
                    fall_sink = "SINK_ERROR: Error Dialog / Reject"
                    recommended = "force_taken"
                elif m in ("je", "jz"):
                    taken_sink = "SINK_ERROR: Error Dialog / Reject"
                    fall_sink = "SINK_SUCCESS: Proceeds Normally"
                    recommended = "force_fallthrough"
            else:
                # Default heuristic based on branch direction and sinks
                if m in ("jne", "jnz"):
                    taken_sink = "SINK_SUCCESS: Proceeds to Success"
                    fall_sink = "SINK_ERROR: Error Branch"
                    recommended = "force_taken"
                elif m in ("je", "jz"):
                    taken_sink = "SINK_ERROR: Error Branch"
                    fall_sink = "SINK_SUCCESS: Proceeds Normally"
                    recommended = "force_fallthrough"

            # Micro-Taint Analysis: identify data-flow source
            taint = ""
            if "eax" in pred_str or "rax" in pred_str or "al" in pred_str:
                taint = f"validator_return ({prod_call['name'] if prod_call else 'callee'})"
            elif any(r in pred_str for r in ("rcx", "rdx", "r8", "r9", "rsi", "rdi")):
                taint = "input_argument"
            elif "[" in pred_str:
                taint = "struct_field_state"

            # Dominance: check if branch leads to an identified error sink
            dominates_error = False
            if target_addr and graph.sinks:
                for es in graph.sinks:
                    if es.get("kind") == "error" and abs(target_addr - es.get("addr", 0)) < 64:
                        dominates_error = True
                        break

            if dominates_error:
                if m in ("jne", "jnz"):
                    recommended = "force_fallthrough"
                    taken_sink, fall_sink = fall_sink, taken_sink
                elif m in ("je", "jz"):
                    recommended = "force_taken"
                    taken_sink, fall_sink = fall_sink, taken_sink

            gate = DecisionGate(
                addr=insn.address,
                mnemonic=m,
                op_str=insn.op_str,
                target_addr=target_addr,
                predicate=pred_str,
                producer_call=prod_call,
                taken_sink=taken_sink,
                fallthrough_sink=fall_sink,
                recommended_action=recommended,
                taint_source=taint,
                dominates_error=dominates_error,
            )
            graph.gates.append(gate)

    return graph


_REJECT_UI_TOKENS = (
    "invalid",
    "not valid",
    "denied",
    "rejected",
    "incorrect",
    "wrong",
    "expired",
    "unregistered",
    "evaluation",
    "trial",
    "license",
    "error",
    "failed",
    "failure",
)


def _score_reject_ui_string(text: str) -> int:
    """Rank rodata snippets that look like error/reject dialog bodies (generic)."""
    if not text or len(text) < 12:
        return -1
    low = text.lower()
    if text.count("_") > 8 and " " not in text:
        return -1
    score = 0
    for tok in _REJECT_UI_TOKENS:
        if tok in low:
            score += 3
    if " " in text:
        score += 2
    if any(ch in text for ch in "?.!"):
        score += 1
    if "appear to be valid" in low or "doesn't appear" in low or "does not appear" in low:
        score += 12
    if "not valid" in low or "invalid" in low:
        score += 6
    if "license" in low and "key" in low:
        score += 10
    if low.startswith("unregistered") and len(text) < 35:
        score -= 4
    if "regular expression" in low or "parse error:" in low or "invalid command line" in low:
        score -= 12
    if len(text) > 28:
        score += 1
    return score


def _extract_rodata_strings(img: Any, *, min_len: int = 18, max_len: int = 160) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for sec in getattr(img, "sections", []):
        if not getattr(sec, "readable", False) or not getattr(sec, "data", None):
            continue
        if getattr(sec, "executable", False):
            continue
        data = sec.data
        i = 0
        while i < len(data):
            if not (32 <= data[i] < 127):
                i += 1
                continue
            j = i
            while j < len(data) and 32 <= data[j] < 127 and j - i < max_len:
                j += 1
            if j - i >= min_len:
                s = data[i:j].decode("latin1", errors="replace").strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
            i = j if j > i else i + 1
    return out


def discover_reject_ui_strings(img: Any, *, limit: int = 12) -> List[str]:
    """Discover candidate error-dialog strings from rodata (no product hardcoding)."""
    ranked: Dict[str, int] = {}

    for preview in _extract_rodata_strings(img):
        sc = _score_reject_ui_string(preview)
        if sc <= 0:
            continue
        ranked[preview] = max(ranked.get(preview, 0), sc)

    # Supplement with keyword hits from find (structural tokens only).
    path = getattr(img, "path", None)
    if path:
        from argus.find import find_in_binary

        for tok in _REJECT_UI_TOKENS:
            found = find_in_binary(str(path), tok, limit=12, with_xrefs=False)
            for hit in found.get("hits") or []:
                preview = (hit.get("preview") or "").strip()
                sc = _score_reject_ui_string(preview)
                if sc <= 0:
                    continue
                ranked[preview] = max(ranked.get(preview, 0), sc)

    ordered = sorted(ranked.items(), key=lambda kv: kv[1], reverse=True)
    return [s for s, _ in ordered[:limit]]


def _score_diagnose_plan(diag: Dict[str, Any], patch: List[Dict[str, Any]]) -> int:
    """Prefer focused plans tied to a caller handler — penalize nop_call sprawl."""
    if not patch:
        return -1
    score = 0
    if diag.get("caller_func"):
        score += 80
    else:
        score -= 40
    if diag.get("leaf_dialog_func"):
        score += 20
    score += 8 * sum(1 for s in patch if s.get("kind") == "force_branch")
    score += 5 * sum(1 for s in patch if s.get("kind") == "force_flag")
    score += 3 * sum(1 for s in patch if s.get("kind") == "ret_imm")
    score -= min(len(patch), 40)
    score -= 3 * sum(1 for s in patch if s.get("kind") == "nop_call")
    if len(patch) > 20:
        score -= 50
    return score


def _cap_patch_plan(plan: List[Dict[str, Any]], *, max_steps: int = 12) -> List[Dict[str, Any]]:
    """Keep highest-value steps when plan is too large."""
    if len(plan) <= max_steps:
        return plan
    order = {"ret_imm": 0, "force_branch": 1, "force_flag": 2, "nop_call": 3, "nop_bytes": 4}
    ranked = sorted(plan, key=lambda s: order.get(str(s.get("kind")), 9))
    out: List[Dict[str, Any]] = []
    nop_budget = 2
    for step in ranked:
        if len(out) >= max_steps:
            break
        if step.get("kind") == "nop_call":
            if nop_budget <= 0:
                continue
            nop_budget -= 1
        out.append(step)
    return out


def auto_diagnose_plan(img: Any) -> Dict[str, Any]:
    """Try diagnose_failure on discovered reject UI strings; return best diagnosis."""
    best: Dict[str, Any] = {}
    best_score = -1
    for text in discover_reject_ui_strings(img):
        diag = diagnose_failure(img, error_text=text, use_atlas=False)
        patch = list(diag.get("corrective_patch") or [])
        if not patch:
            continue
        patch = _cap_patch_plan(patch)
        diag = dict(diag)
        diag["corrective_patch"] = patch
        sc = _score_diagnose_plan(diag, patch)
        if sc > best_score:
            best = diag
            best_score = sc
    return best


def _disasm_function(img: Any, func_addr: int, func_size: int) -> List[Any]:
    import capstone as cs

    mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    data = img.read_bytes(func_addr, func_size)
    return list(md.disasm(data, func_addr))


def _error_block_range(gate: DecisionGate, gate_size: int) -> Optional[Tuple[int, int]]:
    """Return [start, end) VA range of the error-path basic block for a gate."""
    if not gate.recommended_action:
        return None
    if gate.recommended_action == "force_fallthrough" and gate.target_addr is not None:
        return gate.target_addr, gate.target_addr + 96
    if gate.recommended_action == "force_taken":
        fall_start = gate.addr + gate_size
        fall_end = gate.target_addr if gate.target_addr and gate.target_addr > fall_start else fall_start + 64
        return fall_start, fall_end
    return None


def _scan_error_path_calls(insns: List[Any], gates: List[DecisionGate], img: Any = None) -> List[Dict[str, Any]]:
    """Find repeated helper calls between decision gates (typical dialog/message sinks)."""
    if not gates:
        return []
    lo = min(g.addr for g in gates)
    hi = max(g.addr for g in gates) + 320
    call_sites: List[Tuple[int, int]] = []
    for insn in insns:
        if insn.address < lo or insn.address > hi:
            continue
        if insn.mnemonic != "call" or not insn.op_str.startswith("0x"):
            continue
        try:
            tgt = int(insn.op_str, 16)
        except ValueError:
            continue
        call_sites.append((tgt, insn.address))

    if not call_sites:
        return []

    from collections import Counter

    counts = Counter(t for t, _ in call_sites)
    dialog_targets: Set[int] = set()
    indeg_cache: Dict[int, int] = {}
    for tgt, c in counts.items():
        if c < 2 or c > 4:
            continue
        indeg = 99
        if img is not None:
            try:
                from argus.find import count_function_callers

                indeg = count_function_callers(img, tgt)
            except Exception:
                pass
        indeg_cache[tgt] = indeg
        if indeg > 20:
            continue
        dialog_targets.add(tgt)

    if not dialog_targets:
        return []

    best_tgt = max(
        dialog_targets,
        key=lambda t: (counts[t], -indeg_cache.get(t, 99)),
    )

    steps: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for tgt, addr in sorted(call_sites, key=lambda x: x[1]):
        if tgt != best_tgt:
            continue
        if addr in seen:
            continue
        seen.add(addr)
        ins = next((i for i in insns if i.address == addr), None)
        if ins is None:
            continue
        steps.append({
            "kind": "nop_call",
            "addr": hex(addr),
            "size": ins.size,
            "why": f"NOP repeated dialog/helper call -> {hex(tgt)}",
        })
        if len(steps) >= 2:
            break
    return steps


def _scan_flag_writers(insns: List[Any], gates: List[DecisionGate]) -> List[Dict[str, Any]]:
    """Find setcc writers to struct flags immediately before license/state gates."""
    steps: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for gi, g in enumerate(gates):
        idx = next((i for i, ins in enumerate(insns) if ins.address == g.addr), None)
        if idx is None:
            continue
        for ins in insns[max(0, idx - 14):idx]:
            if not ins.mnemonic.startswith("set"):
                continue
            if "ptr" not in ins.op_str:
                continue
            if ins.address in seen:
                continue
            seen.add(ins.address)
            steps.append({
                "kind": "force_flag",
                "addr": hex(ins.address),
                "why": (
                    f"Force boolean state flag writer before gate @ {hex(g.addr)} "
                    f"({ins.mnemonic} {ins.op_str})"
                ),
            })
    return steps


def enrich_patch_plan(img: Any, graph: DecisionGraph, plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add struct-flag and error-path call patches; dedupe by address."""
    insns = _disasm_function(img, graph.func_addr, graph.func_size)
    extras = _scan_flag_writers(insns, graph.gates) + _scan_error_path_calls(insns, graph.gates, img)
    out: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, str]] = set()
    for step in plan + extras:
        key = (str(step.get("kind")), str(step.get("addr")))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        out.append(step)
    return out


_JCC_OPS = frozenset(
    {
        "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
        "js", "jns", "jo", "jno", "jp", "jpo",
    }
)


def _caller_sites(rec: Dict[str, Any]) -> List[int]:
    out: List[int] = []
    for s in rec.get("sites") or []:
        try:
            out.append(int(s, 0))
        except (TypeError, ValueError):
            continue
    return out


def _plan_from_sink_sites(img: Any, sink: int, sites: List[int]) -> List[Dict[str, Any]]:
    """Turn every call to the error sink into nop_call or a preceding force_branch."""
    import capstone as cs

    mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    plan: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for site in sites[:16]:
        if site in seen:
            continue
        seen.add(site)
        lo = max(0, site - 0x50)
        data = img.read_bytes(lo, site - lo + 16) or b""
        insns = list(md.disasm(data, lo))
        last_jcc = None
        call_ins = None
        for ins in insns:
            if ins.mnemonic in _JCC_OPS:
                last_jcc = ins
            if ins.mnemonic == "call" and abs(ins.address - site) <= 4:
                call_ins = ins
        if last_jcc is not None:
            taken = True
            try:
                jtgt = int(last_jcc.op_str, 16)
                # jump past the call → force taken to skip the sink
                taken = jtgt > site
            except (TypeError, ValueError):
                taken = True
            plan.append(
                {
                    "kind": "force_branch",
                    "addr": hex(last_jcc.address),
                    "taken": taken,
                    "why": f"gate before call to error sink {hex(sink)} @ {hex(site)}",
                    "confidence": "medium",
                }
            )
        elif call_ins is not None:
            plan.append(
                {
                    "kind": "nop_call",
                    "addr": hex(call_ins.address),
                    "size": call_ins.size,
                    "why": f"NOP call to error sink {hex(sink)}",
                    "confidence": "medium",
                }
            )
        else:
            plan.append(
                {
                    "kind": "nop_call",
                    "addr": hex(site),
                    "size": 5,
                    "why": f"NOP call site to error sink {hex(sink)}",
                    "confidence": "low",
                }
            )
    return plan


def _diagnose_via_atlas(img: Any, error_text: str, found_va: int) -> Dict[str, Any]:
    """FPC/resource tables: no lea to the string — walk atlas callers of the sink."""
    from argus.atlas import build_atlas

    path = getattr(img, "path", None)
    if not path:
        return {"ok": False, "corrective_patch": []}
    atlas = build_atlas(str(path), query=error_text[:80], string_addr=found_va)
    ranked: List[Tuple[int, int, Dict[str, Any], List[int]]] = []
    for rec in atlas.get("callers") or []:
        sites = _caller_sites(rec)
        n = len(sites)
        if not (2 <= n <= 32):
            continue
        span = (max(sites) - min(sites)) if n >= 2 else 0
        if span > 0x100000:
            continue
        compactness = 50 if span < 0x8000 else (20 if span < 0x40000 else 0)
        score = compactness + n
        ranked.append((score, span, rec, sites))
    ranked.sort(key=lambda t: t[0], reverse=True)
    if not ranked:
        return {
            "ok": False,
            "string_addr": hex(found_va),
            "corrective_patch": [],
            "explanation": "atlas mapped the string but found no clustered caller-set (2–64 sites)",
            "atlas_summary": atlas.get("summary"),
        }

    _score, span, sink_rec, sites = ranked[0]
    sink_va = int(sink_rec.get("fn") or "0", 0)
    plan = _plan_from_sink_sites(img, sink_va, sites)

    # Decision flow on the function that contains the most sink-call sites.
    handler = None
    best_cover = 0
    for mod in atlas.get("modules") or []:
        for fn in mod.get("functions") or []:
            try:
                lo = int(fn.get("fn") or "0", 0)
            except (TypeError, ValueError):
                continue
            hi = lo + int(fn.get("size") or 0)
            cover = sum(1 for s in sites if lo <= s < hi)
            if cover > best_cover:
                best_cover = cover
                handler = lo
    flow_text = ""
    if handler:
        graph = build_decision_flow(img, handler)
        flow_text = graph.to_text_flow()
        # eh_frame covering on stripped binaries can jump to a megabyte-wide "function"
        if abs(int(graph.func_addr) - handler) <= 0x80:
            extra = graph.synthesize_patch_plan(img)
            seen_addr = {p.get("addr") for p in plan}
            for step in extra:
                if step.get("addr") not in seen_addr:
                    plan.append(step)
                    seen_addr.add(step.get("addr"))

    plan = _cap_patch_plan(plan, max_steps=12)
    hops = atlas.get("hops") or []
    hop_note = ""
    if hops:
        hop_note = " Linked modules: " + ", ".join(
            f"{h.get('to')} ({h.get('via')})" for h in hops[:6]
        )
    return {
        "ok": True,
        "symptom": error_text,
        "string_addr": hex(found_va),
        "leaf_dialog_func": hex(sink_va),
        "caller_func": hex(handler) if handler else None,
        "root_cause": (
            f"Error string has no code lea (table-backed). Sink {hex(sink_va)} "
            f"called from {len(sites)} sites"
            + (f" (span {hex(span)})" if span else "")
        ),
        "explanation": (
            f"Atlas walked string {hex(found_va)} → sink {hex(sink_va)} "
            f"with {len(sites)} call sites. Apply corrective_patch to ALL listed sites, "
            "then verify with the same error_text as reject_texts. "
            "If launch crashes, those sites are shared with boot — roll back and patch "
            "only the cluster that atlas marked via=caller from this string."
            + hop_note
        ),
        "decision_flow": flow_text,
        "corrective_patch": plan,
        "atlas_callers": [
            {"fn": sink_rec.get("fn"), "count": sink_rec.get("count"), "sites": sink_rec.get("sites")}
        ],
        "atlas_summary": atlas.get("summary"),
    }


def diagnose_failure(
    img: Any,
    *,
    error_text: Optional[str] = None,
    crash_code: Optional[Union[int, str]] = None,
    last_patch_addr: Optional[Union[int, str]] = None,
    use_atlas: bool = True,
) -> Dict[str, Any]:
    """Automated root-cause diagnosis of an observed error dialog or crash.

    Traces backwards from the error message or crash address to identify the
    exact conditional branch or broken call, returning the minimal corrective patch.
    """
    import capstone as cs
    from argus.disasm.recovery import function_covering
    from argus.find import count_function_callers, find_string_xrefs_multi

    diagnosis: Dict[str, Any] = {
        "ok": True,
        "symptom": error_text or f"Crash {crash_code}",
        "root_cause": "",
        "explanation": "",
        "corrective_patch": [],
    }

    # 1. Crash code analysis (e.g. 0xC0000005 ACCESS_VIOLATION)
    if crash_code is not None:
        cc_str = str(crash_code).lower()
        if "c0000005" in cc_str or "4294930433" in cc_str:
            p_addr = None
            if last_patch_addr:
                p_addr = int(last_patch_addr, 16) if isinstance(last_patch_addr, str) and last_patch_addr.startswith("0x") else int(last_patch_addr)
            diagnosis["root_cause"] = "STATUS_ACCESS_VIOLATION (0xC0000005): Null pointer or clobbered return stack"
            diagnosis["explanation"] = (
                f"Patch at {hex(p_addr) if p_addr else 'last site'} violated calling conventions or clobbered required output registers. "
                "Do not stub this function with ret_imm! Roll back this patch and force the caller's conditional branch instead."
            )
            if p_addr:
                cbound = function_covering(img, p_addr)
                if cbound:
                    cx = find_string_xrefs_multi(img, [cbound.start]).get(cbound.start, [])
                    if cx:
                        ca = int(cx[0]["addr"], 16)
                        diagnosis["corrective_patch"].append({
                            "kind": "force_branch",
                            "addr": hex(ca),
                            "taken": True,
                            "why": f"Bypass calling {hex(p_addr)} directly at caller gate",
                        })
            return diagnosis

    # 2. Error string back-tracing
    if error_text:
        from argus.find import locate_query_string

        located = locate_query_string(img, error_text)
        found_va = located["addr"] if located else None

        if not found_va:
            # Try shorter substring (utf-8 only — encodings of a clipped phrase are noisy)
            short = error_text[:30].strip()
            if len(short) >= 4 and short != error_text.strip():
                located = locate_query_string(img, short)
                found_va = located["addr"] if located else None

        if found_va:
            if located:
                diagnosis["string_addr"] = hex(found_va)
                diagnosis["string_kind"] = located.get("kind")
                diagnosis["string_preview"] = located.get("preview")
            xrefs = find_string_xrefs_multi(img, [found_va]).get(found_va, [])
            if xrefs:
                leaf_addr = int(xrefs[0]["addr"], 16)
                leaf_bound = function_covering(img, leaf_addr)
                caller_func = None
                caller_site = None
                if leaf_bound:
                    cx = find_string_xrefs_multi(img, [leaf_bound.start]).get(leaf_bound.start, [])
                    if cx:
                        caller_site = int(cx[0]["addr"], 16)
                        cbound = function_covering(img, caller_site)
                        caller_func = cbound.start if cbound else caller_site

                target_fn = caller_func or (leaf_bound.start if leaf_bound else leaf_addr)
                graph = build_decision_flow(img, target_fn)

                diagnosis["string_addr"] = hex(found_va)
                diagnosis["leaf_dialog_func"] = hex(leaf_bound.start) if leaf_bound else hex(leaf_addr)
                diagnosis["caller_func"] = hex(caller_func) if caller_func else None
                diagnosis["root_cause"] = f"Error string '{error_text[:40]}...' triggered from {hex(leaf_addr)}"
                diagnosis["decision_flow"] = graph.to_text_flow()
                diagnosis["corrective_patch"] = graph.synthesize_patch_plan(img)
                diagnosis["explanation"] = (
                    f"Error UI text xref → leaf @ {diagnosis.get('leaf_dialog_func')} → "
                    f"decision handler {graph.func_name}. "
                    "Apply corrective_patch in order: function-local ret_imm (if any) → "
                    "force_branch gates → force_flag writers → nop_call on error-path dialogs. "
                    "Verify via apply_plan static bytes + capstone disasm (no GUI auto-input)."
                )
                return diagnosis

            if use_atlas:
                from argus.payload import get_cached_brief, payload_ir_of

                hostish = False
                try:
                    hostish = payload_ir_of(getattr(img, "path", None)) != "native"
                    brief = get_cached_brief(getattr(img, "path", None)) or {}
                    hostish = hostish or brief.get("execution") == "host_runtime"
                except Exception:
                    hostish = False
                if not hostish:
                    atlas_diag = _diagnose_via_atlas(img, error_text, found_va)
                    if atlas_diag.get("corrective_patch"):
                        return atlas_diag

    diagnosis["ok"] = False
    diagnosis["explanation"] = f"Could not find exact string or crash root cause for '{error_text or crash_code}'"
    try:
        from argus.payload import get_cached_brief, payload_ir_of

        path = getattr(img, "path", None)
        brief = get_cached_brief(path) or {}
        if brief.get("execution") == "host_runtime" or payload_ir_of(path) != "native":
            names = [x.get("name") for x in (brief.get("payloads") or [])[:6]]
            diagnosis["next_hint"] = (
                "0 native gates on host_runtime — argus_find/atlas on payload modules "
                f"({', '.join(str(n) for n in names) or 'sidecar'}), not the shell ELF"
            )
            diagnosis["corrective_patch"] = []
    except Exception:
        pass
    return diagnosis


def diagnose_target(
    path: str,
    *,
    error_text: Optional[str] = None,
    crash_code: Optional[Union[int, str]] = None,
    last_patch_addr: Optional[Union[int, str]] = None,
    use_atlas: bool = True,
) -> Dict[str, Any]:
    """Diagnose native CFG or payload text/archive — same tool, decoder by module kind."""
    from argus.payload import (
        build_target_brief,
        diagnose_text_module,
        get_cached_brief,
        list_payload_modules,
        locate_in_bytes,
        read_payload_bytes,
        sniff_magic,
        store_brief,
    )

    brief = get_cached_brief(path) or build_target_brief(path)
    store_brief(brief)
    q = (error_text or "").strip()
    if q:
        payloads = list(brief.get("payloads") or []) or list_payload_modules(path)
        if sniff_magic(path) in ("asar", "zip"):
            primary = str(Path(path).resolve())
            payloads = [{"path": primary, "kind": "archive"}] + [
                r for r in payloads if str(Path(str(r.get("path") or "")).resolve()) != primary
            ]
        for rec in payloads:
            mod = rec.get("path")
            if not mod or not Path(mod).is_file():
                continue
            if rec.get("kind") == "archive" or sniff_magic(mod) in ("asar", "zip"):
                from argus.payload import scan_payload_strings

                ranked = scan_payload_strings(mod, q, limit=8)
                if not ranked:
                    continue
                return diagnose_text_module(mod, q, inner=ranked[0].get("inner"))
            try:
                data = read_payload_bytes(mod)
            except OSError:
                continue
            loc = locate_in_bytes(data, q)
            if not loc:
                continue
            return diagnose_text_module(mod, q)
        magic = sniff_magic(path)
        if magic not in ("elf", "pe"):
            return diagnose_text_module(path, q)

    native_path = path
    try:
        from argus.binary import load_binary

        img = load_binary(native_path)
    except (ValueError, OSError, Exception) as exc:
        return {
            "ok": False,
            "symptom": error_text or f"Crash {crash_code}",
            "root_cause": "",
            "explanation": f"not a native image: {exc}",
            "corrective_patch": [],
            "next_hint": brief.get("next_hint") or "search payload modules",
        }
    return diagnose_failure(
        img,
        error_text=error_text,
        crash_code=crash_code,
        last_patch_addr=last_patch_addr,
        use_atlas=use_atlas,
    )
