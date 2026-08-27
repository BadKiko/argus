from __future__ import annotations

"""Resolve indirect call/jmp targets via short Unicorn run (ELF x86_64 only)."""

from typing import Any, Dict, List, Optional


def resolve_indirect(
    path: str,
    call_site_or_entry: int,
    *,
    max_steps: int = 8_000,
) -> Dict[str, Any]:
    """
    Map ELF and run from function covering `call_site_or_entry` until an
    indirect call/jmp or max_steps. Does not launch full GUI apps: caller
    must pass an explicit code VA (not program entry of huge binaries).
    """
    from argus.binary import load_binary
    from argus.concrete import unicorn_available
    from argus.disasm.recovery import function_covering

    if not unicorn_available():
        return {"ok": False, "reason": "unicorn not installed", "targets": []}

    img = load_binary(path)
    if img.fmt != "elf" or img.arch != "x86_64":
        return {"ok": False, "reason": "ELF x86_64 only", "targets": []}

    # Refuse program-entry of huge .text (GUI) — need focused VA
    text_sz = sum(len(s.data) for s in img.sections if s.executable and s.data)
    if call_site_or_entry == img.entry and text_sz > 400_000:
        return {
            "ok": False,
            "reason": "refusing program entry on large binary — pass function VA",
            "targets": [],
        }

    bound = function_covering(img, call_site_or_entry)
    start = bound.start if bound else call_site_or_entry

    try:
        from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
        from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP
    except ImportError:
        return {"ok": False, "reason": "unicorn import failed", "targets": []}

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    # Map pages from image memory sparsely
    mapped = set()
    for addr in sorted(img.memory.keys()):
        page = addr & ~0xFFF
        if page in mapped:
            continue
        try:
            mu.mem_map(page, 0x1000)
            mapped.add(page)
        except UcError:
            pass
    for addr, b in img.memory.items():
        try:
            mu.mem_write(addr, bytes([b]))
        except UcError:
            pass

    STACK = 0x7FFFFFFF0000
    try:
        mu.mem_map(STACK - 0x20000, 0x20000)
    except UcError:
        pass
    mu.reg_write(UC_X86_REG_RSP, STACK - 0x1000)
    mu.reg_write(UC_X86_REG_RIP, start)

    targets: List[int] = []
    steps = [0]
    stop = [False]

    def hook_code(uc, address, size, user_data):
        steps[0] += 1
        if steps[0] > max_steps:
            stop[0] = True
            uc.emu_stop()
            return
        try:
            raw = uc.mem_read(address, min(size, 15))
        except UcError:
            return
        # call r/m (FF /2) or jmp r/m (FF /4) — coarse: FF with modrm
        if raw and raw[0] == 0xFF and len(raw) >= 2:
            modrm = raw[1]
            reg = (modrm >> 3) & 7
            if reg in (2, 4):  # call/jmp r/m
                # read target from RIP-relative or register — best effort via Capstone
                try:
                    import capstone as cs

                    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
                    md.detail = True
                    for insn in md.disasm(bytes(raw), address):
                        if insn.mnemonic in ("call", "jmp") and insn.operands:
                            op = insn.operands[0]
                            if op.type == cs.CS_OP_IMM:
                                targets.append(int(op.imm))
                                stop[0] = True
                                uc.emu_stop()
                            elif op.type == cs.CS_OP_MEM:
                                # try rip-relative
                                if insn.reg_name(op.mem.base) == "rip":
                                    ea = address + insn.size + op.mem.disp
                                    try:
                                        val = int.from_bytes(uc.mem_read(ea, 8), "little")
                                        if val:
                                            targets.append(val)
                                            stop[0] = True
                                            uc.emu_stop()
                                    except UcError:
                                        pass
                        break
                except Exception:
                    pass
        if address == call_site_or_entry and steps[0] > 4 and not targets:
            # reached site without resolve — stop soon
            pass

    mu.hook_add(UC_HOOK_CODE, hook_code)
    try:
        mu.emu_start(start, start + 0x100000, count=max_steps)
    except UcError as e:
        return {
            "ok": bool(targets),
            "reason": str(e),
            "targets": targets[:16],
            "steps": steps[0],
            "start": hex(start),
        }

    return {
        "ok": bool(targets),
        "reason": "ok" if targets else "no_indirect_resolved",
        "targets": targets[:16],
        "steps": steps[0],
        "start": hex(start),
    }
