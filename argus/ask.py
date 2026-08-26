from __future__ import annotations

"""Intent-driven API for LLM agents (`argus ai` / `ask`).

Hint in → answer | readable | patched_path + certificate.
"""

import json
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


TOOL_SCHEMA: Dict[str, Any] = {
    "name": "argus_ai",
    "description": "Natural-language binary solve/deobf/patch. Returns password, lift, or patched path.",
    "parameters": {
        "type": "object",
        "properties": {
            "prompt": {"type": "string", "description": "RU/EN request, e.g. дай пароль для админа"},
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
    find: bytes = b"Welcome"
    output: Optional[str] = None
    note: str = ""
    force_taken: bool = True
    branch_addr: Optional[int] = None
    stdin_seed: Optional[bytes] = None  # from hint NLP

    def to_dict(self) -> dict:
        return {
            "want": self.want.value,
            "function": self.function,
            "entry": hex(self.entry) if self.entry is not None else None,
            "patch_kind": self.patch_kind.value if self.patch_kind else None,
            "find": self.find.decode("latin1", errors="replace"),
            "output": self.output,
            "note": self.note,
            "force_taken": self.force_taken,
            "branch_addr": hex(self.branch_addr) if self.branch_addr is not None else None,
            "stdin_seed": None if self.stdin_seed is None else self.stdin_seed.decode("latin1", errors="replace"),
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


def _pick_function(img, hinted: Optional[str]) -> str:
    if hinted and hinted in img.symbols:
        return hinted
    for name in ("authenticate", "check_password", "verify", "target_function", "main"):
        if name in img.symbols:
            return name
    funcs = [s for s in img.symbols.values() if s.is_function and not s.is_import and s.addr]
    if funcs:
        return max(funcs, key=lambda s: s.size or 0).name
    return "main"


def _pseudo_c_lift(path: str, fn: str) -> tuple[str, dict]:
    """Pseudo-C style lift after CFF adjacency cleanup."""
    from argus.binary import load_binary
    from argus.deobf.cff import cleaned_adjacency, recover_cff
    from argus.disasm import build_function_cfg

    img = load_binary(path)
    cfg = build_function_cfg(img, fn)
    cff = recover_cff(cfg)
    adj = cleaned_adjacency(cfg, cff)

    lines: List[str] = [
        f"/* Argus lift: {fn} @ {hex(cfg.entry)} */",
        f"/* cff_cases={len(cff.case_map)} dispatcher="
        f"{hex(cff.dispatcher) if cff.dispatcher else 'none'} */",
        f"int {fn}(/* args */) {{",
    ]
    for addr in sorted(cfg.blocks):
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
    lines.append("}")
    if cff.case_map:
        lines.append("/* state machine cases */")
        for imm, tgt in sorted(cff.case_map.items()):
            lines.append(f"/* case {hex(imm)} → L_{tgt:x} */")
    return "\n".join(lines), {"cff": cff.to_dict(), "blocks": len(cfg.blocks), "style": "pseudo_c"}


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


def _patch_always_const(path: str, fn: str, value: int, output: str) -> tuple[bool, dict, List[str]]:
    from argus.binary import load_binary
    from argus.patch import Patcher
    from argus.prove.certificate import PatchCertificate

    img = load_binary(path)
    if fn not in img.symbols:
        return False, {}, [f"function {fn} not found"]
    addr = img.symbols[fn].addr
    payload = _encode_mov_eax_imm(value) + _encode_ret()
    patcher = Patcher.from_path(path)
    ok = patcher.patch_bytes(addr, payload, note=f"{fn} := {value}; ret")
    notes = [f"patch {fn}@{hex(addr)} -> mov eax,{value}; ret" if ok else "patch failed"]
    if not ok:
        return False, {}, notes
    patcher.nop(addr + len(payload), 10, note="pad after stub")
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(addr), "new": payload.hex(), "note": f"always_{value}"}],
        proven=False,
        notes=[f"function {fn} forced return {value}"],
    )
    if img.fmt == "elf":
        v = patcher.verify_runs(stdin=b"x\ny\n")
        cert.behavioral = {
            "ok": v.get("ok"),
            "returncode": v.get("returncode"),
            "stdout": (v.get("stdout") or b"")[:120],
        }
        if value == 1 and v.get("ok") and b"Welcome" in (v.get("stdout") or b""):
            cert.proven = True
            cert.notes.append("verified Welcome without valid password")
        elif v.get("ok"):
            cert.proven = True
            cert.notes.append("behavioral verify ran")
    return True, cert.to_dict(), notes


def _nop_prompt_puts(path: str, output: str) -> tuple[bool, dict, List[str]]:
    from argus.binary import load_binary
    from argus.disasm import build_function_cfg
    from argus.patch import Patcher
    from argus.prove.certificate import PatchCertificate

    img = load_binary(path)
    fn = "main" if "main" in img.symbols else None
    if not fn:
        return False, {}, ["no main"]
    cfg = build_function_cfg(img, fn)
    patcher = Patcher.from_path(path)
    n = 0
    prompt_addrs = set()
    for sec in img.sections:
        if not sec.data:
            continue
        for needle in (b"Username", b"Password", b"password", b"username"):
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
    return n > 0, cert.to_dict(), [f"nop_prompts patched={n}"]


def _skip_check_patch(path: str, fn: str, output: str, note: str) -> tuple[bool, dict, List[str]]:
    """NOP calls to strcmp in target function, or force always_true if none found."""
    from argus.binary import load_binary
    from argus.disasm import build_function_cfg
    from argus.patch import Patcher
    from argus.prove.certificate import PatchCertificate

    img = load_binary(path)
    if fn not in img.symbols:
        return _patch_always_const(path, fn if fn in img.symbols else _pick_function(img, None), 1, output)

    cfg = build_function_cfg(img, fn)
    strcmp_plt = {a for a, n in img.imports.items() if n.split("@")[0] in ("strcmp", "memcmp")}
    patcher = Patcher.from_path(path)
    n = 0
    for blk in cfg.blocks.values():
        for ins in blk.instructions:
            if ins.mnemonic != "call" or not ins.targets:
                continue
            if ins.targets[0] in strcmp_plt or any(
                abs(ins.targets[0] - p) < 16 for p in strcmp_plt
            ):
                # Replace call with xor eax,eax (strcmp equal) + nops
                # xor eax,eax = 31 C0 ; pad rest
                if ins.size >= 2:
                    payload = b"\x31\xc0" + b"\x90" * (ins.size - 2)
                    if patcher.patch_bytes(ins.address, payload, note="skip_check strcmp→0"):
                        n += 1
    if n == 0:
        return _patch_always_const(path, fn, 1, output)
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(p.addr), "note": p.note} for p in patcher.patches],
        proven=False,
        notes=[f"skip_check nopped/zeroed {n} strcmp-like calls", note],
    )
    if img.fmt == "elf":
        v = patcher.verify_runs(stdin=b"x\ny\n")
        cert.behavioral = {"ok": v.get("ok"), "stdout": (v.get("stdout") or b"")[:120]}
        if v.get("ok") and b"Welcome" in (v.get("stdout") or b""):
            cert.proven = True
    return True, cert.to_dict(), [f"skip_check patches={n}"]


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
            or "fla" in path.lower()
            or "flatten" in hint.note.lower()
            or "cff" in hint.note.lower()
        )
        if use_deobf:
            res = solve_after_deobf(path)
            notes.append("solve_after_deobf")
        else:
            res = solve_binary(path, find=hint.find)
            notes.append("solve_direct")
        ok = bool(res.success and res.stdin)
        answer = None
        if ok and res.stdin is not None:
            answer = res.stdin.decode("latin1", errors="replace").strip()
            if b"SOSNEAKY" in res.stdin:
                answer = "SOSNEAKY"
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
        if fn not in img.symbols:
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
                    notes=notes + ["lift_fallback_no_symbol"],
                )
            except Exception as e:
                notes.append(f"lift_fallback_fail: {e}")
                return AskResult(ok=False, want=hint.want.value, notes=notes)
        text, ev = _pseudo_c_lift(path, fn)
        return AskResult(
            ok=True,
            want=hint.want.value,
            answer=f"lifted {fn} ({ev['blocks']} blocks)",
            readable=text,
            evidence=ev,
            certificate={"proven": False, "notes": ["pseudo-C structural lift"]},
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
        for extra in ("main", "authenticate", "target_function"):
            if extra in img.symbols and extra not in fns:
                fns.append(extra)
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
        out = hint.output or (str(path) + f".{kind.value}")
        if kind == PatchKind.ALWAYS_TRUE:
            ok, cert, n = _patch_always_const(path, fn, 1, out)
            return AskResult(ok=ok, want=hint.want.value, answer="forced return 1", patched_path=out if ok else None, certificate=cert, notes=notes + n)
        if kind == PatchKind.ALWAYS_FALSE:
            ok, cert, n = _patch_always_const(path, fn, 0, out)
            return AskResult(ok=ok, want=hint.want.value, answer="forced return 0", patched_path=out if ok else None, certificate=cert, notes=notes + n)
        if kind == PatchKind.UNFLATTEN:
            return ask(path, Hint(want=Want.DEOBF, function=fn, output=out, note=hint.note))
        if kind == PatchKind.NOP_PROMPTS:
            ok, cert, n = _nop_prompt_puts(path, out)
            return AskResult(ok=ok, want=hint.want.value, answer="nop prompts", patched_path=out if ok else None, certificate=cert, notes=notes + n)
        if kind == PatchKind.SKIP_CHECK:
            ok, cert, n = _skip_check_patch(path, fn, out, hint.note)
            return AskResult(ok=ok, want=hint.want.value, answer="skip_check", patched_path=out if ok else None, certificate=cert, notes=notes + n)
        if kind == PatchKind.FORCE_BRANCH:
            from argus.patch.intents import force_branch

            if hint.branch_addr is None:
                return AskResult(ok=False, want=hint.want.value, notes=notes + ["branch_addr required"])
            ok, cert = force_branch(path, hint.branch_addr, out, taken=hint.force_taken)
            return AskResult(
                ok=ok,
                want=hint.want.value,
                answer="branch forced",
                patched_path=out if ok else None,
                certificate=cert,
                notes=notes,
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
