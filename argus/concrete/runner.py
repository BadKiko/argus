from __future__ import annotations

"""Unicorn-backed concrete runner for fast seeds and verify."""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from argus.binary.image import BinaryImage
from argus.concrete import unicorn_available


@dataclass
class ConcreteResult:
    ok: bool
    stdout: bytes = b""
    stdin_consumed: int = 0
    exit_code: Optional[int] = None
    steps: int = 0
    message: str = ""
    hit_addresses: List[int] = field(default_factory=list)


class UnicornRunner:
    """Concrete x86_64 ELF execution with libc stubs (read/strcmp/puts)."""

    def __init__(self, image: BinaryImage, max_steps: int = 200_000):
        if not unicorn_available():
            raise RuntimeError("unicorn not installed")
        if image.fmt != "elf" or image.arch != "x86_64":
            raise ValueError("UnicornRunner supports ELF x86_64 only")
        self.image = image
        self.max_steps = max_steps

    def run(
        self,
        stdin: bytes = b"",
        entry: Optional[int] = None,
        until: Optional[int] = None,
    ) -> ConcreteResult:
        from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
        from unicorn.x86_const import (
            UC_X86_REG_RAX,
            UC_X86_REG_RBP,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDI,
            UC_X86_REG_RDX,
            UC_X86_REG_RIP,
            UC_X86_REG_RSI,
            UC_X86_REG_RSP,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
        )

        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        # Map a generous low and high region
        BASE = 0x400000
        mu.mem_map(BASE, 0x200000)
        STACK = 0x7FFFFFFF0000
        mu.mem_map(STACK - 0x20000, 0x20000)

        for addr, b in self.image.memory.items():
            try:
                mu.mem_write(addr, bytes([b]))
            except UcError:
                page = addr & ~0xFFF
                try:
                    mu.mem_map(page, 0x1000)
                    mu.mem_write(addr, bytes([b]))
                except UcError:
                    pass

        stdout = bytearray()
        stdin_buf = memoryview(stdin)
        stdin_pos = [0]
        steps = [0]
        hits: List[int] = []

        def read_reg(reg):
            return mu.reg_read(reg)

        def write_reg(reg, val):
            mu.reg_write(reg, val & 0xFFFFFFFFFFFFFFFF)

        hooks: Dict[int, Callable] = {}

        def hook_puts(mu_):
            ptr = read_reg(UC_X86_REG_RDI)
            data = bytearray()
            while True:
                ch = mu_.mem_read(ptr, 1)[0]
                if ch == 0:
                    break
                data.append(ch)
                ptr += 1
                if len(data) > 4096:
                    break
            stdout.extend(data)
            stdout.append(0x0A)
            write_reg(UC_X86_REG_RAX, len(data))
            _ret(mu_)

        def hook_printf(mu_):
            # best-effort: treat as puts of format string
            hook_puts(mu_)

        def hook_read(mu_):
            fd = read_reg(UC_X86_REG_RDI)
            buf = read_reg(UC_X86_REG_RSI)
            n = read_reg(UC_X86_REG_RDX)
            take = min(n, len(stdin_buf) - stdin_pos[0])
            if take > 0:
                chunk = bytes(stdin_buf[stdin_pos[0] : stdin_pos[0] + take])
                mu_.mem_write(buf, chunk)
                stdin_pos[0] += take
            write_reg(UC_X86_REG_RAX, take if take > 0 else 0)
            _ret(mu_)

        def hook_strcmp(mu_):
            a = read_reg(UC_X86_REG_RDI)
            b = read_reg(UC_X86_REG_RSI)

            def cstr(ptr: int) -> bytes:
                out = bytearray()
                p = ptr
                while True:
                    ch = mu_.mem_read(p, 1)[0]
                    if ch == 0:
                        break
                    out.append(ch)
                    p += 1
                    if len(out) > 256:
                        break
                return bytes(out)

            sa, sb = cstr(a), cstr(b)
            if sa == sb:
                write_reg(UC_X86_REG_RAX, 0)
            else:
                for i in range(max(len(sa), len(sb)) + 1):
                    x = sa[i] if i < len(sa) else 0
                    y = sb[i] if i < len(sb) else 0
                    if x != y:
                        write_reg(UC_X86_REG_RAX, (x - y) & 0xFFFFFFFF)
                        break
            _ret(mu_)

        def hook_strlen(mu_):
            ptr = read_reg(UC_X86_REG_RDI)
            n = 0
            while n < 4096:
                if mu_.mem_read(ptr + n, 1)[0] == 0:
                    break
                n += 1
            write_reg(UC_X86_REG_RAX, n)
            _ret(mu_)

        def hook_memcmp(mu_):
            a = read_reg(UC_X86_REG_RDI)
            b = read_reg(UC_X86_REG_RSI)
            n = read_reg(UC_X86_REG_RDX)
            diff = 0
            for i in range(min(n, 256)):
                x = mu_.mem_read(a + i, 1)[0]
                y = mu_.mem_read(b + i, 1)[0]
                if x != y:
                    diff = x - y
                    break
            write_reg(UC_X86_REG_RAX, diff & 0xFFFFFFFF)
            _ret(mu_)

        def hook_fgets(mu_):
            buf = read_reg(UC_X86_REG_RDI)
            size = read_reg(UC_X86_REG_RSI)
            stream = read_reg(UC_X86_REG_RDX)
            _ = stream
            take = min(size - 1, len(stdin_buf) - stdin_pos[0]) if size > 1 else 0
            if take > 0:
                chunk = bytes(stdin_buf[stdin_pos[0] : stdin_pos[0] + take])
                mu_.mem_write(buf, chunk + b"\x00")
                stdin_pos[0] += take
                write_reg(UC_X86_REG_RAX, buf)
            else:
                write_reg(UC_X86_REG_RAX, 0)
            _ret(mu_)

        def hook_exit(mu_):
            code = read_reg(UC_X86_REG_RDI) & 0xFF
            mu_.emu_stop()
            write_reg(UC_X86_REG_RAX, code)

        def _ret(mu_):
            rsp = read_reg(UC_X86_REG_RSP)
            ret = int.from_bytes(mu_.mem_read(rsp, 8), "little")
            write_reg(UC_X86_REG_RSP, rsp + 8)
            write_reg(UC_X86_REG_RIP, ret)

        mapping = {
            "puts": hook_puts,
            "printf": hook_printf,
            "read": hook_read,
            "fgets": hook_fgets,
            "strcmp": hook_strcmp,
            "strlen": hook_strlen,
            "memcmp": hook_memcmp,
            "exit": hook_exit,
            "__libc_start_main": None,
        }
        for addr, name in self.image.imports.items():
            base = name.split("@")[0]
            if base in mapping and mapping[base] is not None:
                hooks[addr] = mapping[base]

        def on_code(mu_, address, size, user_data):
            steps[0] += 1
            if steps[0] > self.max_steps:
                mu_.emu_stop()
                return
            if until is not None and address == until:
                hits.append(address)
                mu_.emu_stop()
                return
            if address in hooks:
                hooks[address](mu_)

        mu.hook_add(UC_HOOK_CODE, on_code)

        # entry: prefer main
        start = entry
        if start is None:
            if "main" in self.image.symbols:
                start = self.image.symbols["main"].addr
            else:
                start = self.image.entry

        write_reg(UC_X86_REG_RSP, STACK - 0x100)
        write_reg(UC_X86_REG_RBP, 0)
        write_reg(UC_X86_REG_RDI, 1)
        write_reg(UC_X86_REG_RSI, 0)
        # fake return
        mu.mem_write(STACK - 0x100, (0xDEAD0000).to_bytes(8, "little"))

        try:
            mu.emu_start(start, 0xDEAD0000, count=self.max_steps)
            rax = read_reg(UC_X86_REG_RAX)
            return ConcreteResult(
                ok=True,
                stdout=bytes(stdout),
                stdin_consumed=stdin_pos[0],
                exit_code=rax & 0xFF,
                steps=steps[0],
                message="ok",
                hit_addresses=hits,
            )
        except UcError as e:
            return ConcreteResult(
                ok=False,
                stdout=bytes(stdout),
                stdin_consumed=stdin_pos[0],
                steps=steps[0],
                message=str(e),
                hit_addresses=hits,
            )


def concrete_run(path: str, stdin: bytes = b"") -> ConcreteResult:
    from argus.binary import load_binary

    if not unicorn_available():
        return ConcreteResult(False, message="unicorn unavailable")
    img = load_binary(path)
    return UnicornRunner(img).run(stdin=stdin)
