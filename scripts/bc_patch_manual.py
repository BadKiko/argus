#!/usr/bin/env python3
"""Beyond Compare — manual in-place patches. No Argus tooling.

Usage:
  python3 bc_patch_manual.py          # patch SO only (safe)
  python3 bc_patch_manual.py --restore  # restore from orig-argus/
  python3 bc_patch_manual.py --so-only  # SO without exe register fixes
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

INSTALL = Path("/usr/lib/beyondcompare")
BACKUP = INSTALL / "orig-argus"
SO = INSTALL / "libcloudstorage.so.22.0"
EXE = INSTALL / "BCompare"

# addr -> (expected_prefix_hex, new_bytes, note)
SO_PATCHES: list[tuple[int, bytes, bytes, str]] = [
    # trial startup: jne -> jmp
    (0x23D735, bytes([0x75, 0x1E]), bytes([0xEB, 0x1E]), "trial bypass"),
    # char validator jumps -> unconditional
    (0x23AD34, bytes([0x74, 0x0C]), bytes([0xEB, 0x0C]), "char gate"),
    (0x23AD3A, bytes([0x74, 0x06]), bytes([0xEB, 0x06]), "char gate"),
    (0x23AD40, bytes([0x75, 0x07]), bytes([0x90, 0x90]), "char gate fallthrough"),
    # sub_14f310 apply-key: skip error exits
    (0x14F376, bytes([0x74, 0x08]), bytes([0xEB, 0x08]), "apply"),
    (0x14F3A2, bytes([0x74, 0x08]), bytes([0xEB, 0x08]), "apply"),
    (0x14F405, bytes([0x74, 0x10]), bytes([0xEB, 0x10]), "apply"),
    (0x14F42F, bytes([0x74, 0x0E]), bytes([0xEB, 0x0E]), "apply"),
    (0x14F462, bytes([0x0F, 0x84, 0x07, 0x01, 0x00, 0x00]), bytes([0x90] * 6), "apply je near"),
    (0x14F490, bytes([0x74, 0x0E]), bytes([0xEB, 0x0E]), "apply"),
    (0x14F504, bytes([0x74, 0x0B]), bytes([0xEB, 0x0B]), "apply"),
    (0x14F594, bytes([0x0F, 0x85, 0xD1, 0x00, 0x00, 0x00]), bytes([0x90] * 6), "apply jne near"),
    (0x14F5B2, bytes([0x0F, 0x85, 0x12, 0xFE, 0xFF, 0xFF]), bytes([0x90] * 6), "apply jne near"),
    (0x14F5CE, bytes([0x74, 0x7E]), bytes([0xEB, 0x7E]), "apply"),
    (0x14F5F2, bytes([0x74, 0x05]), bytes([0xEB, 0x05]), "apply"),
    (0x14F61E, bytes([0x74, 0x05]), bytes([0xEB, 0x05]), "apply"),
    (0x14F647, bytes([0x74, 0x05]), bytes([0xEB, 0x05]), "apply commit"),
    # char validator -> mov eax,1; ret
    (
        0x23AC59,
        bytes([0x55, 0x48, 0x89, 0xE5, 0x89, 0xF8]),
        bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]),
        "char fn ret 1",
    ),
    (0x1804FE, bytes([0x55, 0x48, 0x89, 0xE5, 0x48, 0x89]), bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]), "licensed getter"),
    (0x180512, bytes([0x55, 0x48, 0x89, 0xE5, 0x48, 0x89]), bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]), "trial getter"),
    # sub_14f310: after key copy, jump straight to commit (1804b8 @ 14f664)
    (0x14F3C5, bytes([0xE9, 0xD0, 0x01, 0x00, 0x00]), bytes([0xE9, 0x84, 0x02, 0x00, 0x00]), "apply force commit"),
    # commit returns esi; was -1 -> exe jl error path (Error 6)
    (0x14F65C, bytes([0xBE, 0xFF, 0xFF, 0xFF, 0xFF]), bytes([0xBE, 0x00, 0x00, 0x00, 0x00]), "commit ret 0 not -1"),
    # Parsers: accept any input (success without validation)
    (0x19D562, bytes([0x55, 0x48, 0x89, 0xE5, 0x53, 0x48]), bytes([0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]), "hash scan parser ret 0"),
    (0x19DB75, bytes([0x55, 0x48, 0x89, 0xE5, 0x53, 0x48]), bytes([0xB8, 0xD1, 0x07, 0x00, 0x00, 0xC3]), "license parse ret OK"),
    # Crypto apply helper on Enter Key path (216896 -> 216b9a)
    (0x216896, bytes([0x55, 0x48, 0x89, 0xE5, 0x53, 0x48]), bytes([0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]), "crypto apply ret 0"),
]

# Error 6 fail body -> persist+thanks. Boot currently does not hit this
# (original EXE opens Home without Error). Enter Key checksum miss does.
EXE_PATCHES: list[tuple[int, bytes, bytes, str]] = [
    (0xD794CC, bytes([0x48, 0x8B, 0x45, 0xE8, 0xC7]), bytes([0xE9, 0xC7, 0x16, 0x00, 0x00]), "Error6: jmp persist+thanks d7ab98"),
]

def run_elevated(args: list[str]) -> subprocess.CompletedProcess:
    for cmd in (["pkexec"] + args, ["sudo", "-n"] + args):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            return r
    raise PermissionError(f"elevated command failed: {args}")


def backup(files: list[Path]) -> None:
    BACKUP.mkdir(parents=True, exist_ok=True)
    for f in files:
        dst = BACKUP / f.name
        if dst.is_file():
            print(f"  backup exists: {dst}", flush=True)
            continue
        tmp = Path(tempfile.mkdtemp()) / f.name
        shutil.copy2(f, tmp)
        run_elevated(["cp", str(tmp), str(dst)])
        print(f"  backed up {f.name} -> {dst}", flush=True)


def patch_file(path: Path, patches: list[tuple[int, bytes, bytes, str]], *, label: str) -> Path:
    src = BACKUP / "original" / path.name
    if not src.is_file():
        src = BACKUP / path.name
    if src.is_file():
        data = bytearray(src.read_bytes())
    else:
        data = bytearray(path.read_bytes())
    applied = 0
    for addr, expect, new, note in patches:
        cur = bytes(data[addr : addr + len(expect)])
        if cur == new:
            print(f"  {label} {addr:#x} already patched ({note})", flush=True)
            continue
        if cur != expect:
            print(f"  ! {label} {addr:#x} unexpected {cur.hex()} (wanted {expect.hex()}) — {note}", flush=True)
            continue
        data[addr : addr + len(new)] = new
        applied += 1
        print(f"  {label} {addr:#x} ok ({note})", flush=True)
    if applied == 0 and not any(bytes(data[a : a + len(n)]) == n for a, _, n, _ in patches):
        print(f"  {label}: nothing new to apply", flush=True)
    out = Path(tempfile.mkdtemp(prefix="bc-patch-")) / path.name
    out.write_bytes(data)
    return out


def bcompare_running() -> bool:
    return subprocess.run(["pgrep", "-x", "BCompare"], capture_output=True).returncode == 0


def deploy(tmp: Path, dst: Path) -> None:
    if bcompare_running():
        print(
            f"  ! BCompare is running — stop it first (pkill -x BCompare) then re-run",
            file=sys.stderr,
            flush=True,
        )
        raise OSError(f"Text file busy: {dst}")
    try:
        test = dst.open("rb+")
        test.close()
        shutil.copy2(tmp, dst)
    except (PermissionError, OSError) as exc:
        if bcompare_running():
            raise OSError(f"Text file busy: {dst}") from exc
        run_elevated(["cp", str(tmp), str(dst)])
    if dst.name in ("BCompare", "bcompare"):
        dst.chmod(dst.stat().st_mode | 0o111)
    print(f"  deployed -> {dst}", flush=True)


def write_launcher() -> None:
    sh = INSTALL / "run-BCompare.sh"
    sh.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
        'export LD_LIBRARY_PATH="${ROOT}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"\n'
        'exec "${ROOT}/BCompare" "$@"\n',
        encoding="utf-8",
    )
    sh.chmod(0o755)
    print(f"launcher: {sh}", flush=True)


def restore() -> int:
    print("restore from orig-argus/ ...", flush=True)
    for name in ("libcloudstorage.so.22.0", "BCompare"):
        src = BACKUP / name
        dst = INSTALL / name
        if not src.is_file():
            print(f"  missing backup {src}", file=sys.stderr)
            return 1
        deploy(src, dst)
    print("restored.", flush=True)
    return 0


def main() -> int:
    if "--restore" in sys.argv:
        return restore()
    so_only = "--so-only" in sys.argv
    for f in (SO, EXE):
        if not f.is_file():
            print(f"missing: {f}", file=sys.stderr)
            return 1

    print(f"install={INSTALL}", flush=True)
    print("backup -> orig-argus/ ...", flush=True)
    backup([SO, EXE])

    print("patch libcloudstorage.so.22.0 ...", flush=True)
    tmp_so = patch_file(SO, SO_PATCHES, label="SO")
    deploy(tmp_so, SO)

    if bcompare_running():
        print("warning: BCompare is running — exe deploy will fail until you pkill -x BCompare", flush=True)

    if not so_only:
        print("patch BCompare (all register choke points) ...", flush=True)
        tmp_exe = patch_file(EXE, EXE_PATCHES, label="EXE")
        deploy(tmp_exe, EXE)
    else:
        print("BCompare: left untouched (--so-only)", flush=True)

    write_launcher()
    print("\nDone. Launch:", flush=True)
    print(f"  {INSTALL / 'run-BCompare.sh'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
