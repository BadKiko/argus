from __future__ import annotations

"""Intent-driven API for LLM agents (`argus ai` / `ask`).

Hint in → answer | readable | patched_path + certificate.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Want(str, Enum):
    PASSWORD = "password"
    LIFT = "lift"
    PATCH = "patch"
    DEOBF = "deobf"
    REPORT = "report"
    IR = "ir"  # compact JSON IR for agents


class PatchKind(str, Enum):
    ALWAYS_TRUE = "always_true"
    ALWAYS_FALSE = "always_false"
    UNFLATTEN = "unflatten"
    NOP_PROMPTS = "nop_prompts"
    FORCE_BRANCH = "force_branch"
    SKIP_CHECK = "skip_check"  # NOP strcmp / force success path
    NOP_BYTES = "nop_bytes"  # NOP length at VA
    RET_IMM = "ret_imm"  # mov eax,imm; ret at VA / function
    REPLACE_STRING = "replace_string"  # in-place UI/data string swap


TOOL_SCHEMA: Dict[str, Any] = {
    "name": "argus_ai",
    "description": "Natural-language binary solve/deobf/patch. Returns password, lift, or patched path.",
    "parameters": {
        "type": "object",
        "properties": {
            "prompt": {"type": "string", "description": "RU/EN request"},
            "binary": {"type": "string", "description": "Path to ELF/PE"},
            "output": {"type": "string", "description": "Optional patch/deobf output path"},
        },
        "required": ["prompt", "binary"],
    },
}


@dataclass
class Hint:
    want: Want
    function: Optional[str] = None
    entry: Optional[int] = None
    patch_kind: Optional[PatchKind] = None
    find: Optional[bytes] = None  # success needle for solve; None = no default oracle
    output: Optional[str] = None
    note: str = ""
    force_taken: bool = True
    branch_addr: Optional[int] = None
    patch_addr: Optional[int] = None
    patch_size: Optional[int] = None
    ret_value: int = 1
    old_string: Optional[str] = None
    new_string: Optional[str] = None
    stdin_seed: Optional[bytes] = None
    prompt_needles: Optional[List[bytes]] = None  # for nop_prompts
    stub_addrs: Optional[List[int]] = None  # multi ret_imm targets (VA)

    def to_dict(self) -> dict:
        return {
            "want": self.want.value,
            "function": self.function,
            "entry": hex(self.entry) if self.entry is not None else None,
            "patch_kind": self.patch_kind.value if self.patch_kind else None,
            "find": None if self.find is None else self.find.decode("latin1", errors="replace"),
            "output": self.output,
            "note": self.note,
            "force_taken": self.force_taken,
            "branch_addr": hex(self.branch_addr) if self.branch_addr is not None else None,
            "patch_addr": hex(self.patch_addr) if self.patch_addr is not None else None,
            "patch_size": self.patch_size,
            "ret_value": self.ret_value,
            "old_string": self.old_string,
            "new_string": self.new_string,
            "stdin_seed": None if self.stdin_seed is None else self.stdin_seed.decode("latin1", errors="replace"),
            "stub_addrs": [hex(a) for a in (self.stub_addrs or [])],
        }


@dataclass
class AskResult:
    ok: bool
    want: str
    answer: Optional[str] = None
    readable: Optional[str] = None
    patched_path: Optional[str] = None
    certificate: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "want": self.want,
            "answer": self.answer,
            "readable": self.readable,
            "patched_path": self.patched_path,
            "certificate": self.certificate,
            "evidence": self.evidence,
            "notes": self.notes,
            "tool_schema": TOOL_SCHEMA,
        }


_ENTRY_LABELS = frozenset({"main", "entry", "_start", "start", "WinMain", "wWinMain"})
_MAX_LIFT_BLOCKS = 64
_MAX_CALLEES = 48


def _pick_function(img, hinted: Optional[str]) -> str:
    """hint → symbol at entry → main → 'main' (caller may resolve VA separately)."""
    if hinted:
        if hinted in img.symbols:
            return hinted
        try:
            int(hinted, 0)
            return hinted
        except ValueError:
            pass
    for s in img.symbols.values():
        if s.is_function and not s.is_import and s.addr == img.entry and s.name:
            return s.name
    if "main" in img.symbols:
        return "main"
    return "main"


def _resolve_addr(img, fn: Optional[str], entry: Optional[int] = None) -> tuple[Optional[int], str]:
    """Resolve function name or hex VA to address."""
    if entry is not None:
        return entry, fn or hex(entry)
    if fn and fn in img.symbols:
        return img.symbols[fn].addr, fn
    if fn:
        try:
            return int(fn, 0), fn
        except ValueError:
            pass
    if "main" in img.symbols:
        return img.symbols["main"].addr, "main"
    return img.entry, "entry"


def _is_program_entry(img, addr: Optional[int], label: str) -> bool:
    """True if patch target is process entry / main — early ret kills the app."""
    if label in _ENTRY_LABELS:
        return True
    if addr is None:
        return False
    if addr == img.entry:
        return True
    main = img.symbols.get("main")
    if main and addr == main.addr:
        return True
    return False


def _refuse_app_breaking_stub(img, addr: Optional[int], label: str) -> Optional[str]:
    """Block mov eax,imm; ret only on program entry — any other VA is allowed."""
    if addr is None:
        return "cannot resolve patch address"
    if _is_program_entry(img, addr, label):
        return (
            f"refused: stubbing {label}@{hex(addr)} would exit the app immediately; "
            "pass a non-entry VA/symbol (from argus_find evidence) or use nop_bytes/force_branch"
        )
    return None


def _default_patch_out(path: str, kind: Optional[str] = None) -> str:
    return str(path) + ".patched"


def _answer_from_stdin(stdin: bytes) -> str:
    """Turn solver stdin bytes into a user-facing answer (no sample-specific constants)."""
    import re

    text = stdin.decode("latin1", errors="replace")
    tokens = re.findall(r"[A-Za-z0-9_]{4,}", text)
    if tokens:
        return max(tokens, key=len)
    return text.strip()


def _pseudo_c_lift(
    path: str,
    fn: str,
    *,
    entry: Optional[int] = None,
    max_blocks: int = _MAX_LIFT_BLOCKS,
) -> tuple[str, dict]:
    """Pseudo-C style lift after CFF adjacency cleanup (bounded for LLM context)."""
    from argus.binary import load_binary
    from argus.deobf.cff import cleaned_adjacency, recover_cff
    from argus.disasm import build_cfg, build_function_cfg

    img = load_binary(path)
    if fn in img.symbols:
        cfg = build_function_cfg(img, fn)
        label = fn
    else:
        addr, label = _resolve_addr(img, fn, entry)
        if addr is None:
            raise KeyError(f"cannot resolve lift target {fn!r}")
        cfg = build_cfg(img, entry=addr, function_name=label, max_blocks=max_blocks)
    cff = recover_cff(cfg)
    adj = cleaned_adjacency(cfg, cff)

    callees: List[dict] = []
    for baddr, blk in cfg.blocks.items():
        for ins in blk.instructions:
            if ins.mnemonic != "call":
                continue
            callees.append(
                {
                    "from": hex(baddr),
                    "at": hex(ins.address),
                    "to": ins.op_str,
                    "targets": [hex(t) for t in (ins.targets or [])],
                }
            )
            if len(callees) >= _MAX_CALLEES:
                break
        if len(callees) >= _MAX_CALLEES:
            break

    total_blocks = len(cfg.blocks)
    block_addrs = sorted(cfg.blocks)[:max_blocks]
    truncated = total_blocks > max_blocks

    lines: List[str] = [
        f"/* Argus lift: {label} @ {hex(cfg.entry)} */",
        f"/* cff_cases={len(cff.case_map)} dispatcher="
        f"{hex(cff.dispatcher) if cff.dispatcher else 'none'} */",
        f"/* blocks={total_blocks} shown={len(block_addrs)} truncated={truncated} */",
        f"int {label}(/* args */) {{",
    ]
    for addr in block_addrs:
        blk = cfg.blocks[addr]
        succs = adj.get(addr, list(blk.successors))
        lines.append(f"  L_{addr:x}:")
        for ins in blk.instructions[:20]:
            m, o = ins.mnemonic, ins.op_str
            if m == "ret":
                lines.append("    return /* eax */;")
            elif m in ("je", "jz") and succs:
                t = succs[0] if len(succs) >= 1 else 0
                f = succs[1] if len(succs) >= 2 else (addr + ins.size)
                lines.append(f"    if (ZF) goto L_{t:x}; else goto L_{f:x}; /* {m} {o} */")
            elif m in ("jne", "jnz") and succs:
                t = succs[0] if succs else 0
                lines.append(f"    if (!ZF) goto L_{t:x}; /* {m} {o} */")
            elif m == "jmp" and succs:
                lines.append(f"    goto L_{succs[0]:x};")
            elif m == "call":
                lines.append(f"    call({o});")
            elif m.startswith("mov"):
                lines.append(f"    {o.split(',')[0].strip()} = {','.join(o.split(',')[1:]).strip()}; /* mov */")
            elif m == "cmp":
                lines.append(f"    /* cmp {o} → ZF */")
            else:
                lines.append(f"    /* {m} {o} */")
        if len(blk.instructions) > 20:
            lines.append(f"    /* … {len(blk.instructions) - 20} more */")
        for u, v in cff.recovered_edges:
            if u == addr:
                lines.append(f"    /* CFF edge → L_{v:x} */")
        if len(succs) == 1 and blk.instructions and blk.instructions[-1].mnemonic not in (
            "jmp", "ret", "je", "jz", "jne", "jnz",
        ):
            lines.append(f"    goto L_{succs[0]:x};")
    if truncated:
        lines.append(f"  /* … {total_blocks - max_blocks} blocks omitted */")
    lines.append("}")
    if cff.case_map:
        lines.append("/* state machine cases */")
        for imm, tgt in list(sorted(cff.case_map.items()))[:32]:
            lines.append(f"/* case {hex(imm)} → L_{tgt:x} */")

    known = label in img.symbols
    if cff.case_map and known:
        confidence = "high"
    elif known and not truncated:
        confidence = "medium"
    else:
        confidence = "low"

    evidence = {
        "cff": cff.to_dict(),
        "blocks": total_blocks,
        "shown_blocks": len(block_addrs),
        "style": "pseudo_c",
        "callees": callees,
        "confidence": confidence,
        "truncated": truncated,
        "entry": hex(cfg.entry),
        "function": label,
    }
    return "\n".join(lines), evidence


def _ir_blocks(path: str, fn: str) -> tuple[str, dict]:
    from argus.binary import load_binary
    from argus.deobf.cff import cleaned_adjacency, recover_cff
    from argus.disasm import build_function_cfg

    img = load_binary(path)
    cfg = build_function_cfg(img, fn)
    cff = recover_cff(cfg)
    adj = cleaned_adjacency(cfg, cff)
    blocks = []
    for addr in sorted(cfg.blocks):
        blk = cfg.blocks[addr]
        blocks.append(
            {
                "addr": hex(addr),
                "succs": [hex(s) for s in adj.get(addr, list(blk.successors))],
                "insns": [{"m": i.mnemonic, "o": i.op_str, "a": hex(i.address)} for i in blk.instructions[:32]],
            }
        )
    payload = {
        "function": fn,
        "entry": hex(cfg.entry),
        "cff": cff.to_dict(),
        "blocks": blocks,
    }
    return json.dumps(payload, indent=2), {"blocks": len(blocks), "cff_cases": len(cff.case_map)}


def _encode_mov_eax_imm(imm: int) -> bytes:
    return b"\xb8" + (imm & 0xFFFFFFFF).to_bytes(4, "little")


def _encode_ret() -> bytes:
    return b"\xc3"


def _seal_patch(
    original_path: str,
    output: str,
    ok: bool,
    cert: dict,
    notes: List[str],
    *,
    answer_ok: str,
) -> tuple[bool, dict, List[str], str]:
    """Post-check patched file; if unsafe → ok=False + hint for LLM re-patch."""
    if not ok:
        return False, cert, notes, notes[0] if notes else "patch failed"
    from argus.patch.safety import finalize_patch_safety

    safe, cert2, extra = finalize_patch_safety(original_path, output, cert, remove_if_unsafe=True)
    notes = notes + extra
    if not safe:
        reason = extra[0] if extra else "unsafe patch"
        return False, cert2, notes, reason
    return True, cert2, notes, answer_ok


def _patch_always_const(path: str, fn: str, value: int, output: str) -> tuple[bool, dict, List[str]]:
    from argus.binary import load_binary
    from argus.patch import Patcher
    from argus.patch.safety import preflight_patch
    from argus.prove.certificate import PatchCertificate

    img = load_binary(path)
    addr, label = _resolve_addr(img, fn)
    if addr is None:
        return False, {}, [f"function {fn} not found"]
    refuse = _refuse_app_breaking_stub(img, addr, label)
    if refuse:
        return False, {"proven": False, "notes": [refuse], "safety": {"safe": False, "reason": refuse}}, [refuse]
    pre = preflight_patch(path, target_addr=addr, label=label, kind="always_true" if value else "always_false")
    if not pre.get("safe"):
        msg = pre.get("reason") or "preflight refused"
        return False, {"proven": False, "safety": pre, "notes": [msg]}, [msg, pre.get("next_hint") or ""]
    payload = _encode_mov_eax_imm(value) + _encode_ret()
    patcher = Patcher.from_path(path)
    ok = patcher.patch_bytes(addr, payload, note=f"{label} := {value}; ret")
    notes = [f"patch {label}@{hex(addr)} -> mov eax,{value}; ret" if ok else "patch failed"]
    if not ok:
        return False, {}, notes
    patcher.nop(addr + len(payload), 10, note="pad after stub")
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(addr), "new": payload.hex(), "note": f"always_{value}"}],
        proven=False,
        notes=[f"function {label} forced return {value}"],
    )
    if img.fmt == "elf":
        v = patcher.verify_runs(stdin=b"x\ny\n")
        cert.behavioral = {
            "ok": v.get("ok"),
            "returncode": v.get("returncode"),
            "stdout": (v.get("stdout") or b"")[:120],
        }
        if v.get("ok"):
            cert.proven = True
            cert.notes.append("behavioral verify ran")
        if isinstance(cert.behavioral.get("stdout"), bytes):
            cert.behavioral["stdout"] = cert.behavioral["stdout"].decode("latin1", errors="replace")
    ok2, cert2, notes2, _ans = _seal_patch(path, output, True, cert.to_dict(), notes, answer_ok=f"forced return {value}")
    return ok2, cert2, notes2


def _nop_prompt_puts(
    path: str,
    output: str,
    needles: Optional[List[bytes]] = None,
) -> tuple[bool, dict, List[str]]:
    from argus.binary import load_binary
    from argus.disasm import build_function_cfg
    from argus.patch import Patcher
    from argus.prove.certificate import PatchCertificate

    img = load_binary(path)
    fn = "main" if "main" in img.symbols else None
    if not fn:
        # fall back to entry CFG
        from argus.disasm import build_cfg

        cfg = build_cfg(img, entry=img.entry, max_blocks=200)
    else:
        cfg = build_function_cfg(img, fn)
    if not needles:
        return False, {}, ["nop_prompts requires hint.prompt_needles (no hardcoded prompt strings)"]
    patcher = Patcher.from_path(path)
    n = 0
    prompt_addrs = set()
    for sec in img.sections:
        if not sec.data:
            continue
        for needle in needles:
            idx = 0
            while True:
                j = sec.data.find(needle, idx)
                if j < 0:
                    break
                prompt_addrs.add(sec.addr + j)
                idx = j + 1
    for blk in cfg.blocks.values():
        for i, ins in enumerate(blk.instructions):
            if ins.mnemonic != "call":
                continue
            window = blk.instructions[max(0, i - 6) : i]
            hit = False
            for w in window:
                if "0x" not in w.op_str:
                    continue
                for tok in w.op_str.replace(",", " ").split():
                    try:
                        imm = int(tok, 0)
                    except ValueError:
                        continue
                    if any(abs(imm - p) < 64 for p in prompt_addrs):
                        hit = True
                        break
                if hit:
                    break
            if hit and ins.size >= 5 and patcher.nop(ins.address, ins.size, note="nop prompt call"):
                n += 1
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(p.addr), "note": p.note} for p in patcher.patches],
        proven=False,
        notes=[f"nopped {n} prompt-related calls"],
    )
    if n <= 0:
        return False, cert.to_dict(), [f"nop_prompts patched={n}"]
    ok2, cert2, notes2, _ = _seal_patch(
        path, output, True, cert.to_dict(), [f"nop_prompts patched={n}"], answer_ok="nop prompts"
    )
    return ok2, cert2, notes2


def _nop_strcmp_in_function(img, patcher, fn: str) -> int:
    """Replace strcmp/memcmp calls in fn with xor eax,eax. Returns patch count."""
    from argus.disasm import build_function_cfg

    if fn not in img.symbols:
        return 0
    cfg = build_function_cfg(img, fn)
    strcmp_plt = {a for a, n in img.imports.items() if n.split("@")[0] in ("strcmp", "memcmp")}
    n = 0
    for blk in cfg.blocks.values():
        for ins in blk.instructions:
            if ins.mnemonic != "call" or not ins.targets:
                continue
            tgt = ins.targets[0]
            if tgt in strcmp_plt or any(abs(tgt - p) < 16 for p in strcmp_plt):
                if ins.size >= 2:
                    payload = b"\x31\xc0" + b"\x90" * (ins.size - 2)
                    if patcher.patch_bytes(ins.address, payload, note="skip_check strcmp→0"):
                        n += 1
    return n


def _skip_check_patch(
    path: str,
    fn: str,
    output: str,
    note: str,
    find_query: Optional[str] = None,
) -> tuple[bool, dict, List[str]]:
    """Surgical skip: NOP strcmp/memcmp in hinted fn; else evidence patch_candidates."""
    from argus.binary import load_binary
    from argus.patch import Patcher
    from argus.prove.certificate import PatchCertificate

    img = load_binary(path)
    patcher = Patcher.from_path(path)
    candidates: List[str] = []
    if fn and fn not in _ENTRY_LABELS and fn in img.symbols:
        candidates.append(fn)

    n = 0
    used: List[str] = []
    for cand in candidates:
        c = _nop_strcmp_in_function(img, patcher, cand)
        if c:
            n += c
            used.append(cand)

    if n == 0:
        # If hinted non-entry symbol: stub return 1 (generic always_true)
        if fn and fn not in _ENTRY_LABELS and fn in img.symbols:
            return _patch_always_const(path, fn, 1, output)
        # Evidence-driven: patch_candidates from find (query from note or caller)
        try:
            from argus.find import find_in_binary
            from argus.patch.intents import force_branch, nop_bytes

            q = find_query or note or ""
            found = find_in_binary(path, q if q.strip() else None, limit=20, with_xrefs=True)
            cands = found.get("patch_candidates") or []
        except Exception as e:
            cands = []
            notes_extra = [f"find_candidates_fail: {e}"]
        else:
            notes_extra = [f"candidates={len(cands)}"]

        for c in cands[:8]:
            try:
                addr = int(c["addr"], 0)
            except (TypeError, ValueError):
                continue
            if c.get("kind") == "force_branch":
                ok, cert = force_branch(path, addr, output, taken=bool(c.get("taken", True)))
            elif c.get("kind") == "nop_bytes":
                ok, cert = nop_bytes(path, addr, int(c.get("size") or 5), output)
            else:
                continue
            if not ok:
                continue
            ok2, cert2, notes2, _ = _seal_patch(
                path,
                output,
                True,
                cert,
                notes_extra + [f"tried {c['kind']}@{c['addr']}: {c.get('reason')}"],
                answer_ok=f"skip_check via {c['kind']}@{c['addr']}",
            )
            if ok2:
                return ok2, cert2, notes2

        msg = (
            "refused: no strcmp in hinted fn and no patch_candidate passed safety; "
            "pass function=/addr= from argus_find evidence"
        )
        if cands:
            msg += f"; tried {min(8, len(cands))} candidates"
        return False, {"proven": False, "notes": [msg], "candidates": cands[:8]}, [msg] + notes_extra

    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(p.addr), "note": p.note} for p in patcher.patches],
        proven=False,
        notes=[f"skip_check nopped/zeroed {n} strcmp-like calls in {used}", note],
    )
    if img.fmt == "elf":
        v = patcher.verify_runs(stdin=b"x\ny\n")
        stdout = v.get("stdout") or b""
        if isinstance(stdout, bytes):
            stdout_s = stdout[:120].decode("latin1", errors="replace")
        else:
            stdout_s = str(stdout)[:120]
        cert.behavioral = {"ok": v.get("ok"), "stdout": stdout_s}
        if v.get("ok"):
            cert.proven = True
    ok2, cert2, notes2, _ = _seal_patch(
        path, output, True, cert.to_dict(), [f"skip_check patches={n} fns={used}"], answer_ok="skip_check"
    )
    return ok2, cert2, notes2


def ask(path: str, hint: Hint) -> AskResult:
    from argus.binary import load_binary
    from argus.deobf import detect_protection, solve_after_deobf
    from argus.deobf.unflatten import deobf_and_patch
    from argus.symbolic import solve_binary

    notes: List[str] = []
    if hint.note:
        notes.append(f"llm_hint: {hint.note}")

    # UPX pre-unpack (Wave E hook)
    try:
        from argus.patch.packers import maybe_upx_unpack

        unpacked = maybe_upx_unpack(path)
        if unpacked:
            notes.append(f"upx_unpacked={unpacked}")
            path = unpacked
    except Exception as e:
        notes.append(f"upx_skip: {e}")

    img = load_binary(path)
    prot = detect_protection(img)
    notes.append(f"detect={prot.kind}")
    fn = _pick_function(img, hint.function)
    notes.append(f"function={fn}")
    # Stripped: prefer explicit VA for lift/patch over bogus main/entry
    lift_entry = hint.entry if hint.entry is not None else hint.patch_addr
    if prot.kind == "stripped" and hint.want in (Want.LIFT, Want.IR) and lift_entry is None and not hint.function:
        try:
            from argus.find import find_in_binary

            found = find_in_binary(path, hint.note or "license", limit=12)
            gates = found.get("gate_candidates") or []
            non_ui = [g for g in gates if not g.get("ui_label_only")]
            pick = (non_ui or gates or [None])[0]
            if pick and pick.get("addr"):
                lift_entry = int(pick["addr"], 0)
                notes.append(f"stripped_lift_va={hex(lift_entry)} from gate_candidates")
        except Exception as e:
            notes.append(f"stripped_lift_pick_fail: {e}")

    # VMP lift path
    if prot.kind in ("vmp", "themida", "mixed") and hint.want in (Want.LIFT, Want.IR, Want.REPORT):
        if "vmp" in hint.note.lower() or hint.want != Want.REPORT:
            try:
                from argus.deobf.vmp_trace import vmp_partial_lift

                text, ev = vmp_partial_lift(path)
                return AskResult(
                    ok=True,
                    want=hint.want.value,
                    answer="vmp partial lift",
                    readable=text,
                    evidence=ev,
                    certificate={"proven": False, "layer": "vmp_partial"},
                    notes=notes + ["vmp_partial_lift"],
                )
            except Exception as e:
                notes.append(f"vmp_lift_fallback: {e}")

    if hint.want == Want.PASSWORD:
        use_deobf = (
            prot.kind in ("ollvm", "unknown")
            or "flatten" in hint.note.lower()
            or "cff" in hint.note.lower()
            or "deobf" in hint.note.lower()
            or "unflatten" in hint.note.lower()
            or "ollvm" in hint.note.lower()
        )
        if use_deobf:
            res = solve_after_deobf(path, function=hint.function, find=hint.find)
            notes.append("solve_after_deobf")
        else:
            res = solve_binary(path, find=hint.find)
            notes.append("solve_direct")
        ok = bool(res.success and res.stdin)
        answer = None
        if ok and res.stdin is not None:
            answer = _answer_from_stdin(res.stdin)
        return AskResult(
            ok=ok,
            want=hint.want.value,
            answer=answer,
            evidence={
                "stdin": None if res.stdin is None else res.stdin.decode("latin1", errors="replace"),
                "stdout": res.stdout.decode("latin1", errors="replace") if res.stdout else "",
                "paths": res.paths_explored,
                "message": res.message,
            },
            certificate={"proven": ok, "method": "symbolic+optional_cff"},
            notes=notes,
        )

    if hint.want == Want.LIFT:
        try:
            text, ev = _pseudo_c_lift(path, fn, entry=lift_entry)
        except Exception as e:
            notes.append(f"lift_fail: {e}")
            try:
                from argus.deobf.vmp_trace import vmp_partial_lift

                text, ev = vmp_partial_lift(path)
                return AskResult(
                    ok=True,
                    want=hint.want.value,
                    answer="lift via entry/vmp fallback",
                    readable=text,
                    evidence=ev,
                    certificate={"proven": False},
                    notes=notes + ["lift_fallback"],
                )
            except Exception as e2:
                notes.append(f"lift_fallback_fail: {e2}")
                return AskResult(ok=False, want=hint.want.value, notes=notes)
        conf = ev.get("confidence", "low")
        return AskResult(
            ok=True,
            want=hint.want.value,
            answer=f"lifted {ev.get('function', fn)} ({ev.get('shown_blocks', ev.get('blocks'))} blocks, confidence={conf})",
            readable=text,
            evidence=ev,
            certificate={"proven": False, "notes": ["pseudo-C structural lift", f"confidence={conf}"]},
            notes=notes,
        )

    if hint.want == Want.IR:
        text, ev = _ir_blocks(path, fn)
        return AskResult(
            ok=True,
            want=hint.want.value,
            answer=f"ir {fn} blocks={ev['blocks']}",
            readable=text,
            evidence=ev,
            certificate={"proven": False},
            notes=notes,
        )

    if hint.want == Want.DEOBF:
        out = hint.output or (str(path) + ".deobf")
        fns = [fn]
        # companions only from hint.note (comma/space names) — no hardcoded crackme names
        if hint.note:
            for tok in re.split(r"[\s,;]+", hint.note):
                if tok in img.symbols and tok not in fns:
                    fns.append(tok)
        result = deobf_and_patch(path, fns, out)
        # also apply MBA/bogus certs into notes
        try:
            from argus.deobf.bogus import analyze_bogus_cf
            from argus.disasm import build_function_cfg
            from argus.patch import Patcher

            cfg = build_function_cfg(img, fn)
            patcher = Patcher.from_path(out if Path(out).exists() else path)
            bog = analyze_bogus_cf(cfg, patcher)
            if bog.patched:
                patcher.save(out)
                notes.append(f"bogus_patched={bog.patched}")
        except Exception as e:
            notes.append(f"bogus_skip: {e}")
        return AskResult(
            ok=result.patches_applied > 0 or Path(out).exists(),
            want=hint.want.value,
            answer=f"unflatten patches={result.patches_applied}",
            patched_path=out,
            certificate=result.certificate.to_dict() if result.certificate else {},
            evidence=result.to_dict(),
            notes=notes + result.notes,
        )

    if hint.want == Want.PATCH:
        kind = hint.patch_kind or PatchKind.ALWAYS_TRUE
        out = hint.output or _default_patch_out(path, kind.value)
        if kind == PatchKind.ALWAYS_TRUE:
            ok, cert, n = _patch_always_const(path, fn, 1, out)
            ans = "forced return 1" if ok else (n[0] if n else "patch refused")
            return AskResult(
                ok=ok,
                want=hint.want.value,
                answer=ans,
                patched_path=out if ok else None,
                certificate=cert,
                evidence={"safety": (cert or {}).get("safety")},
                notes=notes + n,
            )
        if kind == PatchKind.ALWAYS_FALSE:
            ok, cert, n = _patch_always_const(path, fn, 0, out)
            ans = "forced return 0" if ok else (n[0] if n else "patch refused")
            return AskResult(
                ok=ok,
                want=hint.want.value,
                answer=ans,
                patched_path=out if ok else None,
                certificate=cert,
                evidence={"safety": (cert or {}).get("safety")},
                notes=notes + n,
            )
        if kind == PatchKind.UNFLATTEN:
            return ask(path, Hint(want=Want.DEOBF, function=fn, output=out, note=hint.note))
        if kind == PatchKind.NOP_PROMPTS:
            ok, cert, n = _nop_prompt_puts(path, out, needles=hint.prompt_needles)
            ans = "nop prompts" if ok else (n[0] if n else "nop_prompts refused")
            return AskResult(
                ok=ok,
                want=hint.want.value,
                answer=ans,
                patched_path=out if ok else None,
                certificate=cert,
                evidence={"safety": (cert or {}).get("safety")},
                notes=notes + n,
            )
        if kind == PatchKind.SKIP_CHECK:
            ok, cert, n = _skip_check_patch(path, fn, out, hint.note, find_query=hint.note or None)
            ans = "skip_check" if ok else (n[0] if n else "skip_check refused")
            return AskResult(
                ok=ok,
                want=hint.want.value,
                answer=ans,
                patched_path=out if ok else None,
                certificate=cert,
                evidence={"safety": (cert or {}).get("safety")},
                notes=notes + n,
            )
        if kind == PatchKind.FORCE_BRANCH:
            from argus.patch.intents import force_branch

            if hint.branch_addr is None and hint.patch_addr is None:
                return AskResult(ok=False, want=hint.want.value, notes=notes + ["branch_addr required"])
            addr = hint.branch_addr if hint.branch_addr is not None else hint.patch_addr
            ok, cert = force_branch(path, int(addr), out, taken=hint.force_taken)
            if ok:
                ok, cert, n2, ans = _seal_patch(path, out, True, cert, [], answer_ok="branch forced")
                return AskResult(
                    ok=ok,
                    want=hint.want.value,
                    answer=ans,
                    patched_path=out if ok else None,
                    certificate=cert,
                    evidence={"safety": (cert or {}).get("safety")},
                    notes=notes + n2,
                )
            return AskResult(ok=False, want=hint.want.value, certificate=cert, notes=notes + ["force_branch failed"])
        if kind == PatchKind.NOP_BYTES:
            from argus.patch.intents import nop_bytes
            from argus.patch.safety import preflight_patch

            addr = hint.patch_addr if hint.patch_addr is not None else hint.branch_addr
            size = hint.patch_size or 5
            if addr is None:
                return AskResult(ok=False, want=hint.want.value, notes=notes + ["patch_addr required for nop_bytes"])
            pre = preflight_patch(path, target_addr=int(addr), label=hex(int(addr)), kind="nop_bytes")
            # nop on entry is suspicious but allowed only if size is small? still check post
            ok, cert = nop_bytes(path, int(addr), int(size), out)
            if ok:
                ok, cert, n2, ans = _seal_patch(
                    path, out, True, cert, [], answer_ok=f"nop {size} bytes @ {hex(int(addr))}"
                )
                return AskResult(
                    ok=ok,
                    want=hint.want.value,
                    answer=ans if ok else (n2[0] if n2 else "unsafe"),
                    patched_path=out if ok else None,
                    certificate=cert,
                    evidence={"safety": (cert or {}).get("safety"), "preflight": pre},
                    notes=notes + n2,
                )
            return AskResult(ok=False, want=hint.want.value, certificate=cert, notes=notes)
        if kind == PatchKind.RET_IMM:
            from argus.patch.intents import ret_imm
            from argus.patch.safety import preflight_patch

            targets: List[tuple[int, str]] = []
            if hint.stub_addrs:
                for a in hint.stub_addrs:
                    targets.append((int(a), hex(int(a))))
            else:
                addr, label = _resolve_addr(img, fn, hint.patch_addr if hint.patch_addr is not None else hint.entry)
                if addr is None:
                    return AskResult(ok=False, want=hint.want.value, notes=notes + ["addr required for ret_imm"])
                targets.append((addr, label))

            # Apply sequentially into same output (first from path, rest from out)
            cur_src = path
            last_cert: dict = {}
            applied: List[str] = []
            for addr, label in targets:
                refuse = _refuse_app_breaking_stub(img, addr, label)
                if refuse:
                    return AskResult(
                        ok=False,
                        want=hint.want.value,
                        answer=refuse,
                        certificate={"proven": False, "notes": [refuse], "safety": {"safe": False, "reason": refuse}},
                        notes=notes + [refuse] + applied,
                    )
                pre = preflight_patch(path, target_addr=addr, label=label, kind="ret_imm")
                if not pre.get("safe"):
                    msg = pre.get("reason") or "preflight refused"
                    return AskResult(
                        ok=False,
                        want=hint.want.value,
                        answer=msg,
                        certificate={"proven": False, "safety": pre},
                        notes=notes + [msg, pre.get("next_hint") or ""] + applied,
                    )
                ok, cert = ret_imm(cur_src, int(addr), int(hint.ret_value), out)
                last_cert = cert if isinstance(cert, dict) else {}
                if not ok:
                    return AskResult(
                        ok=False,
                        want=hint.want.value,
                        certificate=last_cert,
                        notes=notes + [f"ret_imm failed @ {label}"] + applied,
                    )
                applied.append(f"ret_imm {hint.ret_value} @ {label}")
                cur_src = out

            ok, cert, n2, ans = _seal_patch(
                path,
                out,
                True,
                last_cert,
                applied,
                answer_ok="; ".join(applied) if applied else f"ret_imm {hint.ret_value}",
            )
            return AskResult(
                ok=ok,
                want=hint.want.value,
                answer=ans if ok else (n2[0] if n2 else "unsafe"),
                patched_path=out if ok else None,
                certificate=cert,
                evidence={"safety": (cert or {}).get("safety"), "stubs": applied},
                notes=notes + n2,
            )
        if kind == PatchKind.REPLACE_STRING:
            from argus.patch.intents import replace_string

            old_s = hint.old_string or ""
            new_s = hint.new_string if hint.new_string is not None else ""
            if not old_s:
                return AskResult(
                    ok=False,
                    want=hint.want.value,
                    answer="old_string required for replace_string",
                    notes=notes + ["old_string required"],
                )
            ok, cert = replace_string(path, old_s, new_s, out)
            if ok:
                # verify new bytes present
                from argus.binary import load_binary as _lb

                ev = {"replaced": True, "old": old_s[:80], "new": new_s[:80]}
                try:
                    ev["found_new"] = bool(_lb(out).find_string(new_s.encode("utf-8", errors="replace")))
                except Exception:
                    ev["found_new"] = None
                ok, cert, n2, ans = _seal_patch(
                    path, out, True, cert, [], answer_ok=f"replaced string → {new_s[:60]!r}"
                )
                return AskResult(
                    ok=ok,
                    want=hint.want.value,
                    answer=ans if ok else (n2[0] if n2 else "unsafe"),
                    patched_path=out if ok else None,
                    certificate=cert,
                    evidence={"safety": (cert or {}).get("safety"), **ev},
                    notes=notes + n2,
                )
            return AskResult(
                ok=False,
                want=hint.want.value,
                answer=(cert or {}).get("notes", ["replace failed"])[0] if isinstance(cert, dict) else "replace failed",
                certificate=cert if isinstance(cert, dict) else {},
                notes=notes + list((cert or {}).get("notes") or []),
            )
        return AskResult(ok=False, want=hint.want.value, notes=notes + [f"unknown patch_kind {kind}"])

    if hint.want == Want.REPORT:
        from argus.pipeline import run_pipeline

        res = run_pipeline(path, function=fn, do_patch=False)
        return AskResult(
            ok=True,
            want=hint.want.value,
            answer=f"report {prot.kind}",
            readable=res.report.to_json(),
            evidence={"protection": prot.to_dict()},
            certificate=res.report.certificate or {},
            notes=notes + res.report.notes,
        )

    return AskResult(ok=False, want=hint.want.value, notes=notes + ["unsupported want"])
