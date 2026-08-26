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
