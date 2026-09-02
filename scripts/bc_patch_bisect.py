"""Bisect BC patch combinations against gui oracle."""

import json
import time
from pathlib import Path

from argus.binary.file_io import copy_binary_resilient, release_binary_lock
from argus.llm.workspace import prepare_work_binary
from argus.patch.gui_oracle import observe_gui_launch
from argus.patch.intents import force_branch, ret_imm
from argus.patch.patcher import Patcher

INSTALL = Path("/usr/lib/beyondcompare")
STARTUP = [(0x23D735, True), (0x23AD34, True), (0x23AD3A, True), (0x23AD40, False)]
UNLOCK = [(0x14F594, False), (0x14F5CE, False), (0x14F42F, False), (0x14F462, False)]


def force_return_zero(path: str, addr: int, output: str) -> bool:
    patcher = Patcher.from_path(path)
    fo = patcher._file_offset(addr)
    if fo is None or patcher.data[fo : fo + 2] != b"\x89\xd8":
        return False
    ok = patcher.patch_bytes(addr, b"\x31\xc0", note="return 0")
    if ok:
        patcher.save(output)
    return ok


def run(label, so_br=(), so_ret=(), ret0=False, exe=()):
    work, _ = prepare_work_binary(str(INSTALL / "BCompare"))
    wd = Path(work).parent
    so = str(wd / "libcloudstorage.so.22.0")
    for name in ("BCompare", "libcloudstorage.so.22.0"):
        release_binary_lock(wd / name)
        copy_binary_resilient(INSTALL / name, wd / name)
    for a, t in list(so_br):
        force_branch(so, addr=a, taken=t, output=so)
    for fn, v in so_ret:
        ret_imm(so, fn_addr=fn, value=v, output=so)
    if ret0:
        force_return_zero(so, 0x14F689, so)
    for a, t in exe:
        force_branch(work, addr=a, taken=t, output=work)
    r = observe_gui_launch(work, settle_s=3.0, launch_timeout=12.0)
    print(f"{label}: ok={r.get('ok')} detail={r.get('detail')!r}")
    print(f"  ui={r.get('ui_texts')} reject={r.get('reject_hits')}", flush=True)
    time.sleep(1.5)


if __name__ == "__main__":
    run("startup only", STARTUP)
    run("startup + ret23ac59", STARTUP, so_ret=[(0x23AC59, 1)])
    run("startup + unlock branches", STARTUP + UNLOCK)
    run("startup + unlock + ret23ac59", STARTUP + UNLOCK, so_ret=[(0x23AC59, 1)])
    run("startup + unlock + ret0", STARTUP + UNLOCK, ret0=True)
    run("full SO", STARTUP + UNLOCK, so_ret=[(0x23AC59, 1)], ret0=True)
    run("full SO + exe d30fdf", STARTUP + UNLOCK, so_ret=[(0x23AC59, 1)], ret0=True, exe=[(0xD30FDF, False)])
