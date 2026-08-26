from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from argus.binary.image import BinaryImage, load_binary


@dataclass
class PatchRecord:
    addr: int
    old: bytes
    new: bytes
    note: str = ""


@dataclass
class Patcher:
    image: BinaryImage
    data: bytearray = field(default_factory=bytearray)
    patches: List[PatchRecord] = field(default_factory=list)

    @classmethod
    def from_path(cls, path: str) -> "Patcher":
        image = load_binary(path)
        raw = Path(path).read_bytes()
        return cls(image=image, data=bytearray(raw))

    def _file_offset(self, vaddr: int) -> Optional[int]:
        """Best-effort VA -> file offset using section mapping."""
        if self.image.fmt == "elf":
            from elftools.elf.elffile import ELFFile
            import io

            elf = ELFFile(io.BytesIO(bytes(self.data)))
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                start = int(seg["p_vaddr"])
                filesz = int(seg["p_filesz"])
                off = int(seg["p_offset"])
                if start <= vaddr < start + filesz:
                    return off + (vaddr - start)
            return None
        # PE
        import pefile

        pe = pefile.PE(data=bytes(self.data))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        rva = vaddr - image_base
        try:
            return pe.get_offset_from_rva(rva)
        finally:
            pe.close()

    def patch_bytes(self, vaddr: int, new: bytes, note: str = "") -> bool:
        off = self._file_offset(vaddr)
        if off is None or off + len(new) > len(self.data):
            return False
        old = bytes(self.data[off : off + len(new)])
        self.data[off : off + len(new)] = new
        self.patches.append(PatchRecord(vaddr, old, new, note))
        # Update in-memory image too
        self.image.write_bytes(vaddr, new)
        return True

    def nop(self, vaddr: int, length: int, note: str = "nop") -> bool:
        return self.patch_bytes(vaddr, b"\x90" * length, note=note)

    def invert_short_jz(self, vaddr: int) -> bool:
        off = self._file_offset(vaddr)
        if off is None:
            return False
        op = self.data[off]
        inv = {0x74: 0x75, 0x75: 0x74, 0x76: 0x77, 0x77: 0x76}
        if op not in inv:
            return False
        return self.patch_bytes(vaddr, bytes([inv[op]]), note="invert branch")

    def save(self, path: str) -> str:
        Path(path).write_bytes(bytes(self.data))
        return path

    def verify_runs(self, argv_extra: Optional[List[str]] = None, stdin: bytes = b"", timeout: float = 2.0) -> dict:
        """Run current buffer as a temp executable (ELF only)."""
        import os
        import subprocess
        import tempfile

        if self.image.fmt != "elf":
            return {"ok": False, "reason": "verify only for ELF in v1"}
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(self.data)
            tmp = f.name
        os.chmod(tmp, 0o755)
        try:
            p = subprocess.run(
                [tmp],
                input=stdin,
                capture_output=True,
                timeout=timeout,
            )
            return {
                "ok": True,
                "returncode": p.returncode,
                "stdout": p.stdout,
                "stderr": p.stderr,
            }
        except Exception as e:
            return {"ok": False, "reason": str(e)}
        finally:
            os.unlink(tmp)
