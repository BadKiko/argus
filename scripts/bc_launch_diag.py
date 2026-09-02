"""Diagnose BC launch and EXE patch impact."""

import subprocess
import time
from pathlib import Path

from argus.binary.file_io import copy_binary_resilient, release_binary_lock
from argus.llm.workspace import prepare_work_binary
from argus.patch.gui_oracle import observe_gui_launch
from argus.patch.intents import force_branch, ret_imm

INSTALL = Path("/usr/lib/beyondcompare")
OUT = Path(__file__).resolve().parents[1] / "tmp_launch_diag.txt"

BASE_SO = [
    (0x23D735, True), (0x23AD34, True), (0x23AD3A, True), (0x23AD40, False),
    (0x14F376, True), (0x14F3A2, True), (0x14F42F, True), (0x14F462, False),
    (0x14F490, True), (0x14F504, True), (0x14F594, False), (0x14F5B2, False),
    (0x14F5CE, True), (0x14F5F2, True), (0x14F61E, True), (0x14F647, True),
]
SO_RETS = [(0x23AC59, 1), (0x14F310, 0), (0x1804FE, 1), (0x180512, 1)]


def patch_combo(exe_rets=()):
    work, _ = prepare_work_binary(str(INSTALL / "BCompare"))
    wd = Path(work).parent
    so = str(wd / "libcloudstorage.so.22.0")
    for n in ("BCompare", "libcloudstorage.so.22.0"):
        release_binary_lock(wd / n)
        copy_binary_resilient(INSTALL / n, wd / n)
    for a, t in BASE_SO:
        force_branch(so, a, so, t)
    for fn, v in SO_RETS:
        ret_imm(so, fn, v, so)
    for fn, v in exe_rets:
        ret_imm(work, fn, v, work)
    return work


def try_launch(work: str, ld_path: str) -> str:
    exe = Path(work)
    cwd = str(INSTALL)
    env = {**subprocess.os.environ, "LD_LIBRARY_PATH": ld_path}
    proc = subprocess.Popen(
        [str(exe)],
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(4)
    poll = proc.poll()
    lines = [f"ld={ld_path!r} poll={poll}"]
    if poll is not None:
        err = proc.stderr.read().decode("utf-8", "replace")[:500]
        lines.append(f"stderr={err!r}")
    else:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        lines.append("alive_after_4s=yes")
    return "\n".join(lines)


def main() -> None:
    lines = []
    for label, exe_rets in [
        ("SO only", ()),
        ("SO+114f680", ((0x114F680, 1),)),
        ("SO+cb7770", ((0xCB7770, 0),)),
        ("SO+both", ((0x114F680, 1), (0xCB7770, 0))),
    ]:
        work = patch_combo(exe_rets)
        lines.append(f"\n=== {label} ===")
        lines.append(try_launch(work, ".argus-work"))
        lines.append(try_launch(work, ".argus-work:."))
        r = observe_gui_launch(work, settle_s=2, launch_timeout=10)
        lines.append(f"oracle ok={r.get('ok')} detail={r.get('detail')!r}")
    OUT.write_text("\n".join(lines))
    print(OUT.read_text())


if __name__ == "__main__":
    main()
