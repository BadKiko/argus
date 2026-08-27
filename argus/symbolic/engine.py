from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

import capstone as cs
import z3

from argus.binary.image import BinaryImage
from argus.symbolic.state import (
    REG64,
    SimState,
    SymMemory,
    Value,
    as_bv,
    conc_or_none,
    is_symbolic,
)

HookFn = Callable[["Engine", SimState], None]


class Engine:
    """Lightweight symbolic/concrete x86_64 interpreter for ELF crackmes."""

    def __init__(self, image: BinaryImage):
        if image.arch != "x86_64":
            raise ValueError("Only x86_64 supported in v1")
        self.image = image
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.md.detail = True
        self.hooks: Dict[int, HookFn] = {}
        self._install_plt_hooks()

    def _install_plt_hooks(self) -> None:
        mapping = {
            "puts": self.hook_puts,
            "printf": self.hook_printf,
            "read": self.hook_read,
            "strcmp": self.hook_strcmp,
            "memcmp": self.hook_memcmp,
            "strlen": self.hook_strlen,
            "fgets": self.hook_fgets,
            "open": self.hook_open,
            "exit": self.hook_exit,
            "__libc_start_main": self.hook_libc_start_main,
        }
        for addr, name in self.image.imports.items():
            base = name.split("@")[0]
            if base in mapping:
                self.hooks[addr] = mapping[base]

    def make_entry_state(
        self,
        entry: Optional[int] = None,
        stdin_len: int = 32,
        concrete_stdin: Optional[bytes] = None,
    ) -> SimState:
        entry = entry or self.image.symbols.get("main", type("S", (), {"addr": self.image.entry})).addr
        if "main" in self.image.symbols:
            entry = self.image.symbols["main"].addr

        mem = SymMemory()
        for a, b in self.image.memory.items():
            mem.concrete[a] = b

        # Stack
        stack_base = 0x7FFFFFFF0000
        stack_size = 0x10000
        for i in range(stack_size):
            mem.concrete[stack_base - stack_size + i] = 0

        regs: Dict[str, Value] = {r: 0 for r in REG64}
        regs["rsp"] = stack_base - 0x100
        regs["rbp"] = 0
        regs["rdi"] = 1  # argc
        regs["rsi"] = 0  # argv (unused)

        stdin: List[Value]
        if concrete_stdin is not None:
            stdin = list(concrete_stdin)
        else:
            stdin = [z3.BitVec(f"stdin_{i}", 8) for i in range(stdin_len)]

        # Fake return address
        mem.store_int(regs["rsp"], 0xDEAD0000, 8)

        return SimState(ip=entry, regs=regs, mem=mem, stdin=stdin)

    def step(self, state: SimState) -> List[SimState]:
        if state.halted or state.exited:
            return []
        if state.ip in self.hooks:
            self.hooks[state.ip](self, state)
            return [] if state.halted or state.exited else [state]
        if state.ip == 0xDEAD0000:
            state.halted = True
            return []

        raw = bytes(state.mem.concrete.get(state.ip + i, self.image.memory.get(state.ip + i, 0)) for i in range(15))
        insns = list(self.md.disasm(raw, state.ip))
        if not insns:
            state.halted = True
            return []
        insn = insns[0]
        return self._exec(state, insn)

    def _exec(self, state: SimState, insn: cs.CsInsn) -> List[SimState]:
        mnem = insn.mnemonic.lower()
        op_str = insn.op_str
        nxt = state.ip + insn.size

        def finish(st: SimState) -> List[SimState]:
            st.ip = nxt
            return [st]

        # Control flow
        if mnem == "ret":
            rsp = conc_or_none(state.get_reg("rsp"))
            if rsp is None:
                state.halted = True
                return []
            ret = state.mem.load_int(rsp, 8)
            rc = conc_or_none(ret)
            state.set_reg("rsp", rsp + 8)
            if rc is None:
                state.halted = True
                return []
            state.ip = rc
            return [state]

        if mnem == "call":
            target = self._imm_target(insn)
            rsp = conc_or_none(state.get_reg("rsp"))
            if rsp is None or target is None:
                state.halted = True
                return []
            state.set_reg("rsp", rsp - 8)
            state.mem.store_int(rsp - 8, nxt, 8)
            state.ip = target
            if target in self.hooks:
                self.hooks[target](self, state)
            return [] if state.halted or state.exited else [state]

        if mnem == "jmp":
            target = self._imm_target(insn)
            if target is None:
                # register/indirect — unsupported
                state.halted = True
                return []
            state.ip = target
            if target in self.hooks:
                self.hooks[target](self, state)
            return [] if state.halted or state.exited else [state]

        if mnem in ("je", "jz", "jne", "jnz"):
            return self._cond_jump(state, insn, mnem, nxt)

        if mnem == "leave":
            # mov rsp, rbp; pop rbp
            rbp = conc_or_none(state.get_reg("rbp"))
            if rbp is None:
                state.halted = True
                return []
            state.set_reg("rsp", rbp)
            val = state.mem.load_int(rbp, 8)
            state.set_reg("rbp", val)
            state.set_reg("rsp", rbp + 8)
            return finish(state)

        if mnem == "push":
            val = self._read_operand(state, insn, 0)
            rsp = conc_or_none(state.get_reg("rsp"))
            if rsp is None:
                state.halted = True
                return []
            size = self._op_size(insn, 0)
            state.set_reg("rsp", rsp - size)
            state.mem.store_int(rsp - size, val, size)
            return finish(state)

        if mnem == "pop":
            rsp = conc_or_none(state.get_reg("rsp"))
            if rsp is None:
                state.halted = True
                return []
            size = self._op_size(insn, 0)
            val = state.mem.load_int(rsp, size)
            self._write_operand(state, insn, 0, val)
            state.set_reg("rsp", rsp + size)
            return finish(state)

        if mnem == "nop":
            return finish(state)

        if mnem in ("mov", "movabs"):
            val = self._read_operand(state, insn, 1)
            self._write_operand(state, insn, 0, val)
            return finish(state)

        if mnem in ("cmove", "cmovz", "cmovne", "cmovnz"):
            # conditional move based on ZF
            zf = state.regs.get("_zf", 0)
            zfc = conc_or_none(zf)
            src = self._read_operand(state, insn, 1)
            take_if_eq = mnem in ("cmove", "cmovz")
            if zfc is not None:
                if (zfc == 1) if take_if_eq else (zfc == 0):
                    self._write_operand(state, insn, 0, src)
                return finish(state)
            # symbolic: fork
            s_t = state.clone()
            s_f = state.clone()
            zf_bv = as_bv(zf, 8)
            if take_if_eq:
                s_t.constraints.append(zf_bv == 1)
                s_f.constraints.append(zf_bv == 0)
            else:
                s_t.constraints.append(zf_bv == 0)
                s_f.constraints.append(zf_bv == 1)
            self._write_operand(s_t, insn, 0, src)
            s_t.ip = nxt
            s_f.ip = nxt
            return [s_t, s_f]

        if mnem == "lea":
            # lea reg, [mem]
            addr = self._effective_addr(state, insn, 1)
            self._write_operand(state, insn, 0, addr)
            return finish(state)

        if mnem in ("add", "sub", "xor", "and", "or"):
            dst = self._read_operand(state, insn, 0)
            src = self._read_operand(state, insn, 1)
            size = self._op_size(insn, 0)
            ops = {
                "add": lambda a, b: a + b,
                "sub": lambda a, b: a - b,
                "xor": lambda a, b: a ^ b,
                "and": lambda a, b: a & b,
                "or": lambda a, b: a | b,
            }
            dc, sc = conc_or_none(dst), conc_or_none(src)
            if dc is not None and sc is not None:
                mask = (1 << (8 * size)) - 1
                if mnem == "add":
                    res = (dc + sc) & mask
                elif mnem == "sub":
                    res = (dc - sc) & mask
                elif mnem == "xor":
                    res = (dc ^ sc) & mask
                elif mnem == "and":
                    res = (dc & sc) & mask
                else:
                    res = (dc | sc) & mask
            else:
                res = ops[mnem](as_bv(dst, 8 * size), as_bv(src, 8 * size))
            self._write_operand(state, insn, 0, res)
            # flags approx for test/jcc: store ZF in regs['_zf']
            if mnem == "xor" and self._same_operands(insn):
                state.regs["_zf"] = 1
            return finish(state)

        if mnem == "test":
            a = self._read_operand(state, insn, 0)
            b = self._read_operand(state, insn, 1)
            size = self._op_size(insn, 0)
            ac, bc = conc_or_none(a), conc_or_none(b)
            if ac is not None and bc is not None:
                state.regs["_zf"] = 1 if (ac & bc) == 0 else 0
                state.regs["_sf"] = 1 if (ac & bc) & (1 << (8 * size - 1)) else 0
            else:
                res = as_bv(a, 8 * size) & as_bv(b, 8 * size)
                state.regs["_zf"] = z3.If(res == 0, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8))
            return finish(state)

        if mnem == "cmp":
            a = self._read_operand(state, insn, 0)
            b = self._read_operand(state, insn, 1)
            size = self._op_size(insn, 0)
            ac, bc = conc_or_none(a), conc_or_none(b)
            if ac is not None and bc is not None:
                state.regs["_zf"] = 1 if ((ac - bc) & ((1 << (8 * size)) - 1)) == 0 else 0
            else:
                res = as_bv(a, 8 * size) - as_bv(b, 8 * size)
                state.regs["_zf"] = z3.If(res == 0, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8))
            return finish(state)

        if mnem.startswith("movz") or mnem.startswith("movs"):
            # treat as mov of src sized into dst
            val = self._read_operand(state, insn, 1)
            self._write_operand(state, insn, 0, val)
            return finish(state)

        # Unsupported — skip conservatively for non-critical opcodes
        if mnem in ("cdqe", "cqo", "clc", "cld", "endbr64"):
            return finish(state)

        # Unknown: halt this path
        state.halted = True
        return []

    def _same_operands(self, insn: cs.CsInsn) -> bool:
        if len(insn.operands) < 2:
            return False
        return insn.op_str.split(",")[0].strip() == insn.op_str.split(",")[1].strip()

    def _cond_jump(self, state: SimState, insn: cs.CsInsn, mnem: str, nxt: int) -> List[SimState]:
        target = self._imm_target(insn)
        if target is None:
            state.halted = True
            return []
        zf = state.regs.get("_zf", 0)
        zfc = conc_or_none(zf)
        take_if_zero = mnem in ("je", "jz")
        if zfc is not None:
            taken = (zfc == 1) if take_if_zero else (zfc == 0)
            state.ip = target if taken else nxt
            return [state]

        # symbolic fork
        s_true = state.clone()
        s_false = state.clone()
        zf_bv = as_bv(zf, 8)
        if take_if_zero:
            s_true.constraints.append(zf_bv == 1)
            s_false.constraints.append(zf_bv == 0)
        else:
            s_true.constraints.append(zf_bv == 0)
            s_false.constraints.append(zf_bv == 1)
        s_true.ip = target
        s_false.ip = nxt
        return [s_true, s_false]

    def _imm_target(self, insn: cs.CsInsn) -> Optional[int]:
        for op in insn.operands:
            if op.type == cs.x86.X86_OP_IMM:
                return int(op.imm)
        return None

    def _op_size(self, insn: cs.CsInsn, idx: int) -> int:
        if idx < len(insn.operands):
            return int(insn.operands[idx].size)
        return 8

    def _read_operand(self, state: SimState, insn: cs.CsInsn, idx: int) -> Value:
        op = insn.operands[idx]
        if op.type == cs.x86.X86_OP_IMM:
            return int(op.imm)
        if op.type == cs.x86.X86_OP_REG:
            name = insn.reg_name(op.reg)
            val = state.get_reg(name)
            # narrow for 32-bit regs written as eax etc — we store full rax
            if name and name.endswith("d") and len(name) <= 4:
                c = conc_or_none(val)
                return (c & 0xFFFFFFFF) if c is not None else z3.Extract(31, 0, as_bv(val, 64))
            if name in ("al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl"):
                c = conc_or_none(val)
                return (c & 0xFF) if c is not None else z3.Extract(7, 0, as_bv(val, 64))
            return val
        if op.type == cs.x86.X86_OP_MEM:
            addr = self._mem_addr(state, insn, op)
            return state.mem.load_int(addr, op.size)
        raise NotImplementedError(f"operand type {op.type}")

    def _write_operand(self, state: SimState, insn: cs.CsInsn, idx: int, val: Value) -> None:
        op = insn.operands[idx]
        if op.type == cs.x86.X86_OP_REG:
            name = insn.reg_name(op.reg)
            # Writing eax clears upper 32 of rax in x64 — approximate by storing value
            if name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp") or (
                name and name.endswith("d") and name.startswith("r")
            ):
                c = conc_or_none(val)
                if c is not None:
                    state.set_reg(name, c & 0xFFFFFFFF)
                else:
                    state.set_reg(name, z3.ZeroExt(32, as_bv(val, 32)))
            elif name in ("al", "bl", "cl", "dl"):
                full = state.get_reg(name)
                fc = conc_or_none(full)
                vc = conc_or_none(val)
                if fc is not None and vc is not None:
                    state.set_reg(name, (fc & ~0xFF) | (vc & 0xFF))
                else:
                    state.set_reg(name, val)
            else:
                state.set_reg(name, val)
            return
        if op.type == cs.x86.X86_OP_MEM:
            addr = self._mem_addr(state, insn, op)
            state.mem.store_int(addr, val, op.size)
            return
        raise NotImplementedError("write operand")

    def _effective_addr(self, state: SimState, insn: cs.CsInsn, idx: int) -> Value:
        return self._mem_addr(state, insn, insn.operands[idx])

    def _mem_addr(self, state: SimState, insn: cs.CsInsn, op: cs.x86.X86Op) -> Value:
        mem = op.mem
        addr: Value = int(mem.disp)
        if mem.base != 0:
            base_name = self.md.reg_name(mem.base)
            if base_name == "rip":
                # RIP-relative: next instruction address + disp
                rip = insn.address + insn.size
                addr = (rip + int(mem.disp)) & 0xFFFFFFFFFFFFFFFF
            else:
                base = state.get_reg(base_name)
                bc, ac = conc_or_none(base), conc_or_none(addr)
                if bc is not None and ac is not None:
                    addr = (bc + ac) & 0xFFFFFFFFFFFFFFFF
                else:
                    addr = as_bv(base, 64) + as_bv(addr, 64)
        if mem.index != 0:
            idx_name = self.md.reg_name(mem.index)
            idx = state.get_reg(idx_name)
            scale = mem.scale
            ic, ac = conc_or_none(idx), conc_or_none(addr)
            if ic is not None and ac is not None:
                addr = (ac + ic * scale) & 0xFFFFFFFFFFFFFFFF
            else:
                addr = as_bv(addr, 64) + as_bv(idx, 64) * scale
        return addr

    # --- libc hooks ---
    def hook_puts(self, eng: "Engine", state: SimState) -> None:
        ptr = conc_or_none(state.get_reg("rdi"))
        if ptr is not None:
            chars = []
            for i in range(256):
                b = state.mem.load_byte(ptr + i)
                bc = conc_or_none(b)
                if bc is None or bc == 0:
                    break
                chars.append(bc)
            state.stdout += bytes(chars) + b"\n"
        state.set_reg("rax", 1)
        self._return(state)

    def hook_printf(self, eng: "Engine", state: SimState) -> None:
        # ignore formatting; treat like puts of format string
        self.hook_puts(eng, state)

    def hook_read(self, eng: "Engine", state: SimState) -> None:
        fd = conc_or_none(state.get_reg("rdi"))
        buf = conc_or_none(state.get_reg("rsi"))
        count = conc_or_none(state.get_reg("rdx"))
        if buf is None or count is None:
            state.halted = True
            return
        n = min(count, 64)
        for i in range(n):
            if state.stdin_pos < len(state.stdin):
                byte = state.stdin[state.stdin_pos]
                state.stdin_pos += 1
            else:
                byte = 0
            state.mem.store_byte(buf + i, byte)
        state.set_reg("rax", n)
        self._return(state)

    def hook_strcmp(self, eng: "Engine", state: SimState) -> None:
        a = conc_or_none(state.get_reg("rdi"))
        b = conc_or_none(state.get_reg("rsi"))
        if a is None or b is None:
            state.halted = True
            return
        eqs = []
        concrete_diff = 0
        fully_concrete = True
        for i in range(64):
            ca = state.mem.load_byte(a + i)
            cb = state.mem.load_byte(b + i)
            cac, cbc = conc_or_none(ca), conc_or_none(cb)
            if cac is not None and cbc is not None:
                if cac != cbc:
                    concrete_diff = (cac - cbc)
                    break
                if cac == 0:
                    concrete_diff = 0
                    break
                continue
            fully_concrete = False
            av = ca if isinstance(ca, z3.ExprRef) else z3.BitVecVal(int(ca) & 0xFF, 8)
            bv = cb if isinstance(cb, z3.ExprRef) else z3.BitVecVal(int(cb) & 0xFF, 8)
            if av.size() != 8:
                av = z3.Extract(7, 0, as_bv(av, 64))
            if bv.size() != 8:
                bv = z3.Extract(7, 0, as_bv(bv, 64))
            eqs.append(av == bv)
            # Stop when either side is concrete NUL
            if cac == 0 or cbc == 0:
                break
        if fully_concrete:
            state.set_reg("rax", concrete_diff & 0xFFFFFFFFFFFFFFFF)
            state.regs["_zf"] = 1 if concrete_diff == 0 else 0
        else:
            equal = z3.And(*eqs) if eqs else z3.BoolVal(True)
            state.set_reg("rax", z3.If(equal, z3.BitVecVal(0, 64), z3.BitVecVal(1, 64)))
            state.regs["_zf"] = z3.If(equal, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8))
        self._return(state)

    def hook_strlen(self, eng: "Engine", state: SimState) -> None:
        ptr = conc_or_none(state.get_reg("rdi"))
        if ptr is None:
            state.halted = True
            return
        n = 0
        for i in range(4096):
            b = conc_or_none(state.mem.load_byte(ptr + i))
            if b is None:
                # symbolic length unknown — constrain weakly
                state.set_reg("rax", z3.BitVec("strlen_ret", 64))
                self._return(state)
                return
            if b == 0:
                break
            n += 1
        state.set_reg("rax", n)
        self._return(state)

    def hook_memcmp(self, eng: "Engine", state: SimState) -> None:
        # treat like strcmp but bounded by rdx
        a = conc_or_none(state.get_reg("rdi"))
        b = conc_or_none(state.get_reg("rsi"))
        n = conc_or_none(state.get_reg("rdx")) or 64
        if a is None or b is None:
            state.halted = True
            return
        eqs = []
        concrete_diff = 0
        fully_concrete = True
        for i in range(min(int(n), 256)):
            ca = state.mem.load_byte(a + i)
            cb = state.mem.load_byte(b + i)
            cac, cbc = conc_or_none(ca), conc_or_none(cb)
            if cac is not None and cbc is not None:
                if cac != cbc:
                    concrete_diff = cac - cbc
                    break
                continue
            fully_concrete = False
            av = ca if isinstance(ca, z3.ExprRef) else z3.BitVecVal(int(ca) & 0xFF, 8)
            bv = cb if isinstance(cb, z3.ExprRef) else z3.BitVecVal(int(cb) & 0xFF, 8)
            if av.size() != 8:
                av = z3.Extract(7, 0, as_bv(av, 64))
            if bv.size() != 8:
                bv = z3.Extract(7, 0, as_bv(bv, 64))
            eqs.append(av == bv)
        if fully_concrete:
            state.set_reg("rax", concrete_diff & 0xFFFFFFFFFFFFFFFF)
            state.regs["_zf"] = 1 if concrete_diff == 0 else 0
        else:
            equal = z3.And(*eqs) if eqs else z3.BoolVal(True)
            state.set_reg("rax", z3.If(equal, z3.BitVecVal(0, 64), z3.BitVecVal(1, 64)))
            state.regs["_zf"] = z3.If(equal, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8))
        self._return(state)

    def hook_fgets(self, eng: "Engine", state: SimState) -> None:
        buf = conc_or_none(state.get_reg("rdi"))
        size = conc_or_none(state.get_reg("rsi")) or 64
        if buf is None:
            state.halted = True
            return
        n = max(0, min(int(size) - 1, 128))
        wrote = 0
        for i in range(n):
            if state.stdin_pos >= len(state.stdin):
                break
            byte = state.stdin[state.stdin_pos]
            state.stdin_pos += 1
            state.mem.store_byte(buf + i, byte)
            wrote += 1
            bc = conc_or_none(byte)
            if bc == 0x0A:
                break
        state.mem.store_byte(buf + wrote, 0)
        state.set_reg("rax", buf)
        self._return(state)

    def hook_open(self, eng: "Engine", state: SimState) -> None:
        # Neutral: fail open (ENFILE-style). Do not force a password/backdoor path.
        state.set_reg("rax", -1)
        self._return(state)

    def hook_exit(self, eng: "Engine", state: SimState) -> None:
        code = conc_or_none(state.get_reg("rdi")) or 0
        state.exit_code = int(code)
        state.exited = True
        state.halted = True

    def hook_libc_start_main(self, eng: "Engine", state: SimState) -> None:
        main = conc_or_none(state.get_reg("rdi"))
        if main is None:
            state.halted = True
            return
        state.ip = main

    def _return(self, state: SimState) -> None:
        rsp = conc_or_none(state.get_reg("rsp"))
        if rsp is None:
            state.halted = True
            return
        ret = conc_or_none(state.mem.load_int(rsp, 8))
        state.set_reg("rsp", rsp + 8)
        if ret is None:
            state.halted = True
            return
        state.ip = ret
