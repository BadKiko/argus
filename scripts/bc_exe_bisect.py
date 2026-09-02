"""Quick EXE+SO patch test for BC register path."""

import traceback
from pathlib import Path

from argus.binary.file_io import copy_binary_resilient, release_binary_lock
from argus.llm.workspace import prepare_work_binary
from argus.patch.gui_oracle import observe_gui_launch
from argus.patch.intents import force_branch, ret_imm

INSTALL = Path("/usr/lib/beyondcompare")
OUT = Path(__file__).resolve().parents[1] / "tmp_one.txt"

BASE_SO = [
    (0x23D735, True), (0x23AD34, True), (0x23AD3A, True), (0x23AD40, False),
    (0x14F376, True), (0x14F3A2, True), (0x14F42F, True), (0x14F462, False),
    (0x14F490, True), (0x14F504, True), (0x14F594, False), (0x14F5B2, False),
    (0x14F5CE, True), (0x14F5F2, True), (0x14F61E, True), (0x14F647, True),
]
SO_RETS = [(0x23AC59, 1), (0x14F310, 0), (0x1804FE, 1), (0x180512, 1)]


def run(label: str, exe_br=(), exe_ret=()) -> None:
    work, _ = prepare_work_binary(str(INSTALL / "BCompare"))
    wd = Path(work).parent
    so = str(wd / "libcloudstorage.so.22.0")
    for n in ("BCompare", "libcloudstorage.so.22.0"):
        release_binary_lock(wd / n)
        copy_binary_resilient(INSTALL / n, wd / n)
    for addr, taken in BASE_SO:
        force_branch(so, addr, so, taken)
    for fn, val in SO_RETS:
        ret_imm(so, fn, val, so)
    for addr, taken in exe_br:
        force_branch(work, addr, work, taken)
    for fn, val in exe_ret:
        ret_imm(work, fn, val, work)
    r = observe_gui_launch(work, settle_s=3, launch_timeout=12)
    line = f"{label}: ok={r.get('ok')} detail={r.get('detail')!r} reject={r.get('reject_hits')}\n"
    OUT.write_text(OUT.read_text() + line if OUT.is_file() else line)
    print(line, end="")


def main() -> None:
    OUT.write_text("")
    cases = [
        ("SO only", (), ()),
        ("SO+d30fdf", [(0xD30FDF, False)], ()),
        ("SO+d30fd2", [(0xD30FD2, False)], ()),
        ("SO+d30fd2+d30fdf", [(0xD30FD2, False), (0xD30FDF, False)], ()),
        ("SO+ret114f680", [], [(0x114F680, 1)]),
        ("SO+cb7770=0", [], [(0xCB7770, 0)]),
        ("SO+d30fdf+114f680", [(0xD30FDF, False)], [(0x114F680, 1)]),
    ]
    for label, br, ret in cases:
        try:
            run(label, br, ret)
        except Exception:
            OUT.write_text(OUT.read_text() + traceback.format_exc())
            raise


if __name__ == "__main__":
    main()
