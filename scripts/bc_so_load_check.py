import os
import subprocess
import time
from pathlib import Path

from argus.binary.file_io import copy_binary_resilient, release_binary_lock
from argus.llm.workspace import prepare_work_binary
from argus.patch.intents import force_branch, ret_imm

INSTALL = Path("/usr/lib/beyondcompare")
OUT = Path(__file__).resolve().parents[1] / "tmp_so_load.txt"

work, _ = prepare_work_binary(str(INSTALL / "BCompare"))
wd = Path(work).parent
so = str(wd / "libcloudstorage.so.22.0")
for n in ("BCompare", "libcloudstorage.so.22.0"):
    release_binary_lock(wd / n)
    copy_binary_resilient(INSTALL / n, wd / n)
br = [
    (0x23D735, True), (0x23AD34, True), (0x23AD3A, True), (0x23AD40, False),
    (0x14F376, True), (0x14F3A2, True), (0x14F42F, True), (0x14F462, False),
    (0x14F490, True), (0x14F504, True), (0x14F594, False), (0x14F5B2, False),
    (0x14F5CE, True), (0x14F5F2, True), (0x14F61E, True), (0x14F647, True),
]
for a, t in br:
    force_branch(so, a, so, t)
for fn, v in [(0x23AC59, 1), (0x14F310, 0), (0x1804FE, 1), (0x180512, 1)]:
    ret_imm(so, fn, v, so)

os.system("pkill -f '.argus-work/BCompare' 2>/dev/null")
time.sleep(1)
env = {**os.environ, "LD_LIBRARY_PATH": f"{INSTALL}/.argus-work:{INSTALL}"}
proc = subprocess.Popen([work], cwd=str(INSTALL), env=env)
time.sleep(6)
maps = Path(f"/proc/{proc.pid}/maps").read_text()
cloud = [l for l in maps.splitlines() if "cloudstorage" in l]
home = [l for l in subprocess.check_output(["wmctrl", "-l"], text=True).splitlines() if "Home - Beyond Compare" in l]
proc.terminate()
OUT.write_text(f"HOME={home}\nCLOUD={cloud}\n")
print(OUT.read_text())
