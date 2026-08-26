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
    op = patcher.data[fo]
    ok = False
    if taken and 0x70 <= op <= 0x7F:
        ok = patcher.patch_bytes(addr, bytes([0xEB, patcher.data[fo + 1]]), note="force taken")
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
    In-place ASCII/UTF-8 string replace. `new` must fit in the old C-string slot
    (len(new) <= len(matched span)); remainder zero-padded.
    """
    from argus.binary import load_binary

    if not old:
        return False, {"notes": ["old string empty"]}
    old_b = old.encode("utf-8", errors="replace")
    new_b = new.encode("utf-8", errors="replace")
    img = load_binary(path)
    addrs = img.find_string(old_b)
    if not addrs:
        # try latin1 / partial
        addrs = img.find_string(old.encode("latin1", errors="replace"))
    if not addrs:
        return False, {"notes": [f"string not found: {old[:60]!r}"]}

    patcher = Patcher.from_path(path)
    applied = 0
    targets = addrs if all_occurrences else addrs[:1]
    for addr in targets:
        # measure existing C-string length (until NUL), require new fits
        span = 0
        while True:
            b = img.read_bytes(addr + span, 1)
            if not b or b[0] == 0:
                break
            span += 1
            if span > 4096:
                break
        # allow replacing just the matched prefix if full span is huge HTML
        slot = max(span, len(old_b))
        if len(new_b) > slot:
            return False, {
                "notes": [
                    f"new string too long ({len(new_b)} > slot {slot}) at {hex(addr)}; shorten it"
                ]
            }
        payload = new_b + b"\x00" * (slot - len(new_b))
        # keep a trailing NUL inside slot
        if len(payload) < slot + 1:
            # ensure at least one NUL after new text if room in original
            pass
        if not patcher.patch_bytes(addr, payload[:slot], note=f"str→{new[:40]!r}"):
            continue
        # write explicit NUL at end of new text if we didn't fill entire slot with NULs
        if len(new_b) < slot:
            patcher.patch_bytes(addr + len(new_b), b"\x00", note="str nul")
        applied += 1

    if applied == 0:
        return False, {"notes": ["replace_string patch_bytes failed"]}
    patcher.save(output)
    cert = PatchCertificate(
        patches=[{"addr": hex(p.addr), "note": p.note} for p in patcher.patches],
        proven=False,
        notes=[f"replace_string applied={applied} old={old[:40]!r} new={new[:40]!r}"],
    )
    return True, cert.to_dict()

