"""Beyond Compare: SO in-place (install) + EXE patches in .argus-work (no sudo for exe)."""

import json
import sys
from pathlib import Path

from argus.binary.launch_env import write_install_launcher
from argus.binary.file_io import copy_binary_resilient, release_binary_lock
from argus.llm.session import reset_session
from argus.llm.tools import dispatch_tool
from argus.llm.workspace import prepare_work_binary
from argus.patch.deploy import ensure_original_backup, install_replace, in_place_enabled
from argus.patch.intents import force_branch, ret_imm
from argus.patch.patcher import Patcher

INSTALL = Path("/usr/lib/beyondcompare")
WORK = INSTALL / ".argus-work"

SO_BRANCHES = [
    (0x23D735, True),
    (0x23AD34, True),
    (0x23AD3A, True),
    (0x23AD40, False),
    (0x14F376, True),
    (0x14F3A2, True),
    (0x14F42F, True),
    (0x14F462, False),
    (0x14F490, True),
    (0x14F504, True),
    (0x14F594, False),
    (0x14F5B2, False),
    (0x14F5CE, True),
    (0x14F5F2, True),
    (0x14F61E, True),
    (0x14F647, True),
]

SO_RET_STUBS = [
    (0x23AC59, 1),
    # Keep sub_14f310 body — ret_imm here skips license commit → Error 5 / trial footer
    (0x1804FE, 1),
    (0x180512, 1),
]

# EXE: do not patch 114f680 / d30fd8 — breaks startup (30-day) or window geometry.
# Error 5 fixed via full SO apply path (no ret_imm @ 0x14f310).
EXE_PATCHES: list = []


def patch_so_install() -> None:
    so = INSTALL / "libcloudstorage.so.22.0"
    ensure_original_backup(so)
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="argus-so-")) / so.name
    copy_binary_resilient(so, tmp)
    path = str(tmp)
    for addr, taken in SO_BRANCHES:
        ok, detail = force_branch(path, addr=addr, taken=taken, output=path)
        print(f"  SO branch {hex(addr)} taken={taken} ok={ok}", flush=True)
        if not ok:
            print(f"    ! {detail}", flush=True)
    for fn, val in SO_RET_STUBS:
        ok, _ = ret_imm(path, fn_addr=fn, value=val, output=path)
        print(f"  SO ret_imm {hex(fn)}={val} ok={ok}", flush=True)
    r = install_replace(tmp, so, elevate=True)
    print(f"  SO deploy ok={r.ok} detail={r.detail}", flush=True)
    if not r.ok:
        # fallback: user-writable copy for LD_PRELOAD if sudo unavailable
        work_so = WORK / so.name
        WORK.mkdir(parents=True, exist_ok=True)
        copy_binary_resilient(tmp, work_so)
        print(f"  SO fallback copy → {work_so} (use LD_PRELOAD)", flush=True)


def patch_exe_work() -> str:
    WORK.mkdir(parents=True, exist_ok=True)
    exe_work = WORK / "BCompare"
    release_binary_lock(exe_work)
    copy_binary_resilient(INSTALL / "BCompare", exe_work)
    ensure_original_backup(INSTALL / "BCompare")
    if not EXE_PATCHES:
        print("  EXE: clean copy (no exe patches)", flush=True)
        return str(exe_work)
    for item in EXE_PATCHES:
        addr, val, kind, note = item
        if kind == "force_branch":
            ok, detail = force_branch(str(exe_work), addr=addr, taken=val, output=str(exe_work))
            print(f"  EXE branch {hex(addr)} taken={val} ok={ok} ({note})", flush=True)
            if not ok:
                print(f"    ! {detail}", flush=True)
        else:
            patcher = Patcher.from_path(str(exe_work))
            ok = patcher.patch_bytes(addr, val, note=note)
            print(f"  EXE patch {hex(addr)} ok={ok} ({note})", flush=True)
            patcher.save(str(exe_work))
    return str(exe_work)


def write_launcher() -> Path:
    launcher = INSTALL / "run-BCompare.sh"
    # Install libcloudstorage is patched in-place; LD_PRELOAD breaks BC (10x10 window).
    launcher.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "ROOT=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
        "export LD_LIBRARY_PATH=\"${ROOT}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}\"\n"
        'exec "${ROOT}/.argus-work/BCompare" "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    return launcher


def main() -> int:
    reset_session()
    assert in_place_enabled()
    print(f"install={INSTALL} backup={INSTALL / 'original'}", flush=True)
    print("SO patches → install libcloudstorage (sudo if needed)...", flush=True)
    patch_so_install()
    print("EXE patches → .argus-work/BCompare...", flush=True)
    work = patch_exe_work()
    launcher = write_launcher()
    print(f"launcher: {launcher}", flush=True)

    g = json.loads(dispatch_tool("argus_gui_oracle", {"binary": work, "for_task": 1}))
    ev = g.get("evidence") or {}
    print("\nLaunch:", g.get("ok"), g.get("summary"), flush=True)
    print("UI:", ev.get("ui_texts"), flush=True)
    print("Reject:", ev.get("reject_hits"), flush=True)
    return 0 if g.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
