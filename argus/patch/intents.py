from __future__ import annotations

"""Certified patch intents used by ask/ai."""

from typing import Any, Dict, Tuple

from argus.patch.patcher import Patcher
from argus.prove.certificate import PatchCertificate


def force_branch(path: str, addr: int, output: str, taken: bool = True) -> Tuple[bool, Dict[str, Any]]:
    patcher = Patcher.from_path(path)
    fo = patcher._file_offset(addr)
    if fo is None:
        return False, {"notes": ["bad addr"]}

    # Strict instruction verification via Capstone
    try:
        import capstone as cs
        md64 = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        raw = patcher.data[fo : fo + 16]
        insns = list(md64.disasm(raw, addr))
        is_jcc = bool(insns and insns[0].mnemonic.startswith("j") and insns[0].mnemonic not in ("jmp", "jecxz", "jrcxz"))
        if not is_jcc:
            md32 = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
            insns32 = list(md32.disasm(raw, addr))
            is_jcc = bool(insns32 and insns32[0].mnemonic.startswith("j") and insns32[0].mnemonic not in ("jmp", "jecxz", "jrcxz"))
        if not is_jcc:
            found_mnem = insns[0].mnemonic if insns else "non-code"
            return False, {"notes": [f"addr {hex(addr)} is not a conditional branch (found {found_mnem})"]}
    except Exception:
        pass

    op = patcher.data[fo]
    ok = False
    if taken and 0x70 <= op <= 0x7F:
        ok = patcher.patch_bytes(addr, bytes([0xEB, patcher.data[fo + 1]]), note="force taken")
    elif taken and op == 0xEB:
        ok = patcher.patch_bytes(addr, bytes([0xEB, 0x00]), note="redirect jmp to fallthrough")
    elif taken and op == 0x0F and patcher.data[fo + 1] in (0x84, 0x85):
        rel = bytes(patcher.data[fo + 2 : fo + 6])
        ok = patcher.patch_bytes(addr, b"\xe9" + rel + b"\x90", note="force taken near")
    elif not taken:
        length = 2 if 0x70 <= op <= 0x7F else (6 if op == 0x0F else 0)
        if length:
            ok = patcher.nop(addr, length, note="force not taken")
    if not ok:
        return False, {"notes": ["unsupported jcc"]}
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(p.addr), "note": p.note} for p in patcher.patches],
        proven=False,
        notes=["force_branch structural"],
    )
    return True, cert.to_dict()


def ret_imm(path: str, fn_addr: int, value: int, output: str) -> Tuple[bool, Dict[str, Any]]:
    patcher = Patcher.from_path(path)
    payload = b"\xb8" + (value & 0xFFFFFFFF).to_bytes(4, "little") + b"\xc3"
    ok = patcher.patch_bytes(fn_addr, payload, note=f"ret {value}")
    if ok:
        patcher.nop(fn_addr + len(payload), 8, note="pad")
        patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(fn_addr), "note": f"ret_imm {value}"}],
        proven=False,
        notes=["ret_imm stub"],
    )
    return ok, cert.to_dict()


def force_flag(path: str, addr: int, output: str) -> Tuple[bool, Dict[str, Any]]:
    """Replace setcc on a memory byte with mov byte ptr [same], 1 (same length when disp8)."""
    import capstone as cs

    patcher = Patcher.from_path(path)
    fo = patcher._file_offset(addr)
    if fo is None:
        return False, {"notes": ["bad addr"]}

    mode = cs.CS_MODE_64
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    raw = patcher.data[fo : fo + 16]
    insns = list(md.disasm(raw, addr))
    if not insns:
        md32 = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        insns = list(md32.disasm(raw, addr))
    if not insns or not insns[0].mnemonic.startswith("set"):
        return False, {"notes": [f"addr {hex(addr)} is not setcc"]}

    insn = insns[0]
    if "ptr" not in insn.op_str:
        return False, {"notes": ["setcc does not target memory"]}

    # setcc mem is 4 bytes for [reg+disp8]; mov imm8 same size: c6 /r disp8 01
    if insn.size != 4:
        return False, {"notes": [f"unsupported setcc size {insn.size}"]}

    # Re-use ModRM from setcc (0f 94/95 xx) → mov (c6 xx 01)
    modrm = raw[2]
    payload = bytes([0xC6, modrm, raw[3], 0x01])
    ok = patcher.patch_bytes(addr, payload, note="force_flag mov byte,1")
    if ok:
        patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(addr), "note": "force_flag"}],
        proven=False,
        notes=["setcc→mov byte 1"],
    )
    return ok, cert.to_dict()


def nop_call(path: str, addr: int, size: int, output: str) -> Tuple[bool, Dict[str, Any]]:
    patcher = Patcher.from_path(path)
    ok = patcher.nop(addr, size, note="nop_call")
    if ok:
        patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(addr), "note": "nop_call"}],
        proven=False,
        notes=["nop_call"],
    )
    return ok, cert.to_dict()


def nop_bytes(path: str, addr: int, size: int, output: str) -> Tuple[bool, Dict[str, Any]]:
    """NOP `size` bytes at VA (alias of nop_call with clearer name)."""
    patcher = Patcher.from_path(path)
    ok = patcher.nop(addr, size, note="nop_bytes")
    if ok:
        patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(addr), "size": size, "note": "nop_bytes"}],
        proven=False,
        notes=[f"nop_bytes size={size}"],
    )
    return ok, cert.to_dict()


def replace_string(
    path: str,
    old: str,
    new: str,
    output: str,
    *,
    all_occurrences: bool = False,
) -> Tuple[bool, Dict[str, Any]]:
    """
    In-place ASCII/UTF-8 replace of the exact `old` match only.
    Slot is always len(old) bytes — never extend to the rest of a C-string
    (mid-string hits must not wipe the tail after the match).
    """
    from argus.binary import load_binary

    if not old:
        return False, {"notes": ["old string empty"]}
    old_b = old.encode("utf-8", errors="replace")
    new_b = new.encode("utf-8", errors="replace")
    slot = len(old_b)
    if len(new_b) > slot:
        return False, {
            "notes": [
                f"new string too long ({len(new_b)} > old {slot}); shorten or pad old query"
            ]
        }
    img = load_binary(path)
    addrs = img.find_string(old_b)
    if not addrs:
        addrs = img.find_string(old.encode("latin1", errors="replace"))
    if not addrs:
        return False, {"notes": [f"string not found: {old[:60]!r}"]}

    patcher = Patcher.from_path(path)
    applied = 0
    applied_addrs: list[str] = []
    targets = addrs if all_occurrences else addrs[:1]
    # Pad with spaces so we do not insert an early NUL mid-phrase C-string
    payload = new_b + (b" " * (slot - len(new_b)))
    for addr in targets:
        if not patcher.patch_bytes(addr, payload, note=f"str→{new[:40]!r}"):
            continue
        applied += 1
        applied_addrs.append(hex(addr))

    if applied == 0:
        return False, {"notes": ["replace_string patch_bytes failed"]}
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(p.addr), "note": p.note} for p in patcher.patches],
        proven=False,
        notes=[
            f"replace_string applied={applied} old={old[:40]!r} new={new[:40]!r} slot={slot}"
        ],
    )
    d = cert.to_dict()
    d["replace"] = {
        "addrs": applied_addrs,
        "slot": slot,
        "old_len": slot,
        "new_len": len(new_b),
    }
    return True, d

