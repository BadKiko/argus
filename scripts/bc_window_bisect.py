"""Find which patch set allows visible BC window."""

import os
import subprocess
import time
from pathlib import Path

from argus.binary.file_io import copy_binary_resilient, release_binary_lock
from argus.llm.workspace import prepare_work_binary
from argus.patch.intents import force_branch, ret_imm

INSTALL = Path("/usr/lib/beyondcompare")
OUT = Path("/home/kiko/petwork/argus/tmp_window_bisect.txt")

BASE_SO = [
    (0x23D735, True), (0x23AD34, True), (0x23AD3A, True), (0x23AD40, False),
    (0x14F376, True), (0x14F3A2, True), (0x14F42F, True), (0x14F462, False),
    (0x14F490, True), (0x14F504, True), (0x14F594, False), (0x14F5B2, False),
    (0x14F5CE, True), (0x14F5F2, True), (0x14F61E, True), (0x14F647, True),
]
SO_RETS = [(0x23AC59, 1), (0x14F310, 0), (0x1804FE, 1), (0x180512, 1)]


def patch(label, exe_rets=()):
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


def launch_and_probe(label, work):
    os.system("pkill -f '/usr/lib/beyondcompare/.argus-work/BCompare' 2>/dev/null")
    time.sleep(1)
    env = {**os.environ, "LD_LIBRARY_PATH": f"{INSTALL}/.argus-work:{INSTALL}"}
    proc = subprocess.Popen([work], cwd=str(INSTALL), env=env, stderr=subprocess.PIPE)
    time.sleep(7)
    poll = proc.poll()
    err = proc.stderr.read().decode("utf-8", "replace")[:300] if poll is not None else ""
    wins = subprocess.check_output(["wmctrl", "-l"], text=True, stderr=subprocess.DEVNULL)
    home = [w for w in wins.splitlines() if "Home - Beyond Compare" in w]
    bcompare = [w for w in wins.splitlines() if w.endswith("BCompare") or " Beyond Compare" in w]
    alive = poll is None
    if alive:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    return f"{label}: alive={alive} poll={poll} home={home} bc={bcompare} err={err!r}"


def main():
    cases = [
        ("SO only", ()),
        ("SO+114f680", ((0x114F680, 1),)),
        ("SO+cb7770", ((0xCB7770, 0),)),
        ("SO+both", ((0x114F680, 1), (0xCB7770, 0))),
        ("SO+startup only", ()),  # minimal
    ]
    # minimal SO only startup patch
    work_min, _ = prepare_work_binary(str(INSTALL / "BCompare"))
    wd = Path(work_min).parent
    so = str(wd / "libcloudstorage.so.22.0")
    for n in ("BCompare", "libcloudstorage.so.22.0"):
        release_binary_lock(wd / n)
        copy_binary_resilient(INSTALL / n, wd / n)
    force_branch(so, 0x23D735, so, True)
    lines = [launch_and_probe("minimal SO 23d735", work_min)]

    for label, exe_rets in cases:
        if label == "SO+startup only":
            continue
        work = patch(label, exe_rets)
        lines.append(launch_and_probe(label, work))

    OUT.write_text("\n".join(lines))
    print(OUT.read_text())


if __name__ == "__main__":
    main()
