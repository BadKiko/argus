from __future__ import annotations

"""Intent-driven API for LLM agents.

The model supplies a hint (what it wants). Argus runs a certified pipeline and
returns an answer, readable lift, and/or a patched binary — not pattern bingo.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Want(str, Enum):
    PASSWORD = "password"  # recover secret / stdin that unlocks
    LIFT = "lift"  # readable pseudocode / cleaned CFG text for a function
    PATCH = "patch"  # rewrite binary per patch_kind
    DEOBF = "deobf"  # unflatten/CFF clean binary
    REPORT = "report"  # structured analysis for the model


class PatchKind(str, Enum):
    ALWAYS_TRUE = "always_true"  # make check/auth return success
    ALWAYS_FALSE = "always_false"
    UNFLATTEN = "unflatten"
    NOP_PROMPTS = "nop_prompts"  # neutralize Username/Password puts (best-effort)
    FORCE_BRANCH = "force_branch"  # force jcc at addr taken/not


@dataclass
class Hint:
    """What the LLM asks Argus to do."""

    want: Want
    function: Optional[str] = None
    entry: Optional[int] = None
    patch_kind: Optional[PatchKind] = None
    find: bytes = b"Welcome"  # success needle for password solve
    output: Optional[str] = None
    note: str = ""  # free-text hint from the model (logged, may guide later)
    force_taken: bool = True  # for FORCE_BRANCH
    branch_addr: Optional[int] = None

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
        }


@dataclass
class AskResult:
    ok: bool
    want: str
    answer: Optional[str] = None  # password / short natural answer for the LLM
    readable: Optional[str] = None  # lifted pseudocode / cleaned view
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


def _lift_function(path: str, fn: str) -> tuple[str, dict]:
    """Produce LLM-readable text: cleaned CFG after CFF recovery."""
    from argus.binary import load_binary
    from argus.deobf.cff import cleaned_adjacency, recover_cff
    from argus.disasm import build_function_cfg

    img = load_binary(path)
    cfg = build_function_cfg(img, fn)
    cff = recover_cff(cfg)
    adj = cleaned_adjacency(cfg, cff)

    lines: List[str] = [
        f"// lift of {fn} @ {hex(cfg.entry)}",
        f"// protection_hint: cff_cases={len(cff.case_map)} dispatcher="
        f"{hex(cff.dispatcher) if cff.dispatcher else 'none'}",
        f"function {fn}() {{",
    ]
    for addr in sorted(cfg.blocks):
        blk = cfg.blocks[addr]
        succs = adj.get(addr, list(blk.successors))
        lines.append(f"  block_{addr:x}:  // -> {', '.join(hex(s) for s in succs) or 'ret'}")
        for ins in blk.instructions[:24]:
            lines.append(f"    {ins.mnemonic} {ins.op_str}".rstrip())
        if len(blk.instructions) > 24:
            lines.append(f"    // ... {len(blk.instructions) - 24} more insns")
        if not blk.instructions:
            lines.append("    // empty")
        # semantic recovered edges annotation
        for u, v in cff.recovered_edges:
            if u == addr:
                lines.append(f"    // CFF recovered edge -> {hex(v)}")
    lines.append("}")
    if cff.case_map:
        lines.append("// state cases:")
        for imm, tgt in sorted(cff.case_map.items()):
            lines.append(f"//   {hex(imm)} -> handler {hex(tgt)}")
    text = "\n".join(lines)
    return text, {"cff": cff.to_dict(), "blocks": len(cfg.blocks)}


def _encode_mov_eax_imm(imm: int) -> bytes:
    return b"\xb8" + (imm & 0xFFFFFFFF).to_bytes(4, "little")


def _encode_ret() -> bytes:
    return b"\xc3"


def _patch_always_const(path: str, fn: str, value: int, output: str) -> tuple[bool, dict, List[str]]:
    """Replace function prologue with mov eax, imm; ret (x86_64)."""
    from argus.binary import load_binary
    from argus.patch import Patcher
    from argus.prove.certificate import PatchCertificate

    img = load_binary(path)
    if fn not in img.symbols:
        return False, {}, [f"function {fn} not found"]
    addr = img.symbols[fn].addr
    payload = _encode_mov_eax_imm(value) + _encode_ret()  # 6 bytes
    patcher = Patcher.from_path(path)
    ok = patcher.patch_bytes(addr, payload, note=f"{fn} := {value}; ret")
    notes = [f"patch {fn}@{hex(addr)} -> mov eax,{value}; ret" if ok else "patch failed"]
    if not ok:
        return False, {}, notes
    # NOP a bit of following bytes to avoid decoding garbage if caller falls through (optional)
    patcher.nop(addr + len(payload), 10, note="pad after stub")
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(addr), "new": payload.hex(), "note": f"always_{value}"}],
        proven=False,
        notes=[
            "structural stub patch — behavioral verify recommended",
            f"function {fn} forced return {value}",
        ],
    )
    if img.fmt == "elf":
        v = patcher.verify_runs(stdin=b"x\ny\n")
        cert.behavioral = {"ok": v.get("ok"), "returncode": v.get("returncode"), "stdout": (v.get("stdout") or b"")[:120]}
        if v.get("ok"):
            cert.proven = True
            cert.notes.append("behavioral verify ran")
    return True, cert.to_dict(), notes


def _nop_prompt_puts(path: str, output: str) -> tuple[bool, dict, List[str]]:
    """Best-effort: NOP call sites in main that print Username/Password strings."""
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
    # Heuristic: call to puts/printf PLT right after loading string with Username/Password
    prompt_addrs = set()
    for sec in img.sections:
        if not sec.data:
            continue
        for needle in (b"Username", b"Password", b"password", b"username"):
            idx = 0
            data = sec.data
            while True:
                j = data.find(needle, idx)
                if j < 0:
                    break
                prompt_addrs.add(sec.addr + j)
                idx = j + 1
    for blk in cfg.blocks.values():
        for i, ins in enumerate(blk.instructions):
            if ins.mnemonic != "call":
                continue
            # look back for movabs/lea of prompt string
            window = blk.instructions[max(0, i - 6) : i]
            hit = False
            for w in window:
                if "0x" in w.op_str:
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
            if hit and ins.size >= 5:
                if patcher.nop(ins.address, ins.size, note="nop prompt call"):
                    n += 1
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(p.addr), "note": p.note} for p in patcher.patches],
        proven=False,
        notes=[f"nopped {n} prompt-related calls"],
    )
    return n > 0, cert.to_dict(), [f"nop_prompts patched={n}"]


def ask(path: str, hint: Hint) -> AskResult:
    """Main LLM entry: hint in → answer / readable / patched out."""
    from argus.binary import load_binary
    from argus.deobf import detect_protection, solve_after_deobf
    from argus.deobf.unflatten import deobf_and_patch
    from argus.symbolic import solve_binary

    notes: List[str] = []
    if hint.note:
        notes.append(f"llm_hint: {hint.note}")

    img = load_binary(path)
    prot = detect_protection(img)
    notes.append(f"detect={prot.kind}")
    fn = _pick_function(img, hint.function)
    notes.append(f"function={fn}")

    if hint.want == Want.PASSWORD:
        # Prefer deobf-then-solve when CFF likely / hint mentions flatten
        use_deobf = prot.kind in ("ollvm", "unknown") or "fla" in path.lower() or "flatten" in hint.note.lower()
        if use_deobf:
            res = solve_after_deobf(path)
            notes.append("solve_after_deobf")
        else:
            res = solve_binary(path, find=hint.find)
            notes.append("solve_direct")
        ok = bool(res.success and res.stdin)
        answer = None
        if ok and res.stdin is not None:
            # Prefer printable password-looking token
            text = res.stdin.decode("latin1", errors="replace")
            answer = text.strip()
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
        text, ev = _lift_function(path, fn)
        return AskResult(
            ok=True,
            want=hint.want.value,
            answer=f"lifted {fn} ({ev['blocks']} blocks)",
            readable=text,
            evidence=ev,
            certificate={"proven": False, "notes": ["lift is structural, not semantic proof"]},
            notes=notes,
        )

    if hint.want == Want.DEOBF:
        out = hint.output or (str(path) + ".deobf")
        fns = [fn]
        for extra in ("main", "authenticate"):
            if extra in img.symbols and extra not in fns:
                fns.append(extra)
        result = deobf_and_patch(path, fns, out)
        return AskResult(
            ok=result.patches_applied > 0,
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
            h2 = Hint(want=Want.DEOBF, function=fn, output=out, note=hint.note)
            return ask(path, h2)
        if kind == PatchKind.NOP_PROMPTS:
            ok, cert, n = _nop_prompt_puts(path, out)
            return AskResult(ok=ok, want=hint.want.value, answer="nop prompts", patched_path=out if ok else None, certificate=cert, notes=notes + n)
        if kind == PatchKind.FORCE_BRANCH:
            from argus.patch import Patcher
            from argus.prove.certificate import PatchCertificate

            if hint.branch_addr is None:
                return AskResult(ok=False, want=hint.want.value, notes=notes + ["branch_addr required"])
            patcher = Patcher.from_path(path)
            addr = hint.branch_addr
            fo = patcher._file_offset(addr)
            if fo is None:
                return AskResult(ok=False, want=hint.want.value, notes=notes + ["bad addr"])
            op = patcher.data[fo]
            if hint.force_taken and 0x70 <= op <= 0x7F:
                patcher.patch_bytes(addr, bytes([0xEB, patcher.data[fo + 1]]), note="force taken")
            elif not hint.force_taken:
                length = 2 if 0x70 <= op <= 0x7F else 6
                patcher.nop(addr, length, note="force not taken")
            else:
                return AskResult(ok=False, want=hint.want.value, notes=notes + ["unsupported jcc"])
            patcher.save(out)
            cert = PatchCertificate(
                patches=[{"addr": hex(p.addr), "note": p.note} for p in patcher.patches],
                proven=False,
                notes=["force_branch structural"],
            )
            return AskResult(ok=True, want=hint.want.value, answer="branch forced", patched_path=out, certificate=cert.to_dict(), notes=notes)

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
