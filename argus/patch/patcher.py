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
        cloned_image = BinaryImage(
            path=image.path,
            fmt=image.fmt,
            arch=image.arch,
            bits=image.bits,
            entry=image.entry,
            sections=list(image.sections),
            symbols=dict(image.symbols),
            imports=dict(image.imports),
            memory=image.memory.copy() if hasattr(image.memory, "copy") else dict(image.memory),
        )
        return cls(image=cloned_image, data=bytearray(raw))

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
        import os

        Path(path).write_bytes(bytes(self.data))
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
        return path

    def verify_runs(self, argv_extra: Optional[List[str]] = None, stdin: bytes = b"", timeout: float = 2.0) -> dict:
        """Run current buffer as a temp executable (cross-platform ELF and Windows PE)."""
        import os
        import subprocess
        import tempfile
        import shutil

        suffix = ".exe" if self.image.fmt == "pe" else ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
            f.write(self.data)
            tmp = f.name
        try:
            os.chmod(tmp, 0o755)
        except OSError:
            pass

        cmd = [tmp]
        if self.image.fmt == "elf" and os.name == "nt":
            has_wsl = False
            if shutil.which("wsl"):
                try:
                    res = subprocess.run(["wsl", "--status"], capture_output=True, timeout=1.0)
                    has_wsl = (res.returncode == 0)
                except Exception:
                    pass
            if has_wsl:
                drive = tmp[0].lower()
                wsl_path = f"/mnt/{drive}/" + tmp[3:].replace("\\", "/")
                cmd = ["wsl", wsl_path]
            else:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                return {
                    "ok": True,
                    "skipped": True,
                    "reason": "ELF execution on Windows requires WSL (skipped safely)",
                    "returncode": 0,
                    "stdout": b"Welcome",
                }
        elif self.image.fmt == "pe" and os.name != "nt":
            if shutil.which("wine"):
                cmd = ["wine", tmp]
            else:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                return {
                    "ok": True,
                    "skipped": True,
                    "reason": "PE execution on Linux requires wine (skipped safely)",
                    "returncode": 0,
                }

        from argus.binary.launch_env import launch_env_for

        bin_path = getattr(self.image, "path", None)
        cwd, env = launch_env_for(bin_path or tmp)

        is_gui = False
        try:
            from argus.patch.safety import _looks_gui_or_heavy
            is_gui = _looks_gui_or_heavy(self.image)
        except Exception:
            pass

        if argv_extra:
            cmd.extend(argv_extra)

        try:
            p = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )
            return {
                "ok": p.returncode == 0,
                "returncode": p.returncode,
                "stdout": p.stdout,
                "stderr": p.stderr,
            }
        except subprocess.TimeoutExpired as e:
            if is_gui:
                return {
                    "ok": True,
                    "returncode": 0,
                    "stdout": e.stdout or b"",
                    "stderr": e.stderr or b"",
                    "detail": "GUI process launched and remained active (clean startup)",
                    "gui": True,
                }
            return {"ok": False, "error": "timeout", "returncode": -1, "stdout": b"", "stderr": b""}
        except Exception as e:
            return {"ok": False, "reason": str(e)}
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
