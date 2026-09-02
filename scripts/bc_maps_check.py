import os
import subprocess
import time
from pathlib import Path

from argus.binary.file_io import copy_binary_resilient, release_binary_lock
from argus.llm.workspace import prepare_work_binary
from argus.patch.intents import force_branch, ret_imm

INSTALL = Path("/usr/lib/beyondcompare")
work, _ = prepare_work_binary(str(INSTALL / "BCompare"))
wd = Path(work).parent
so = str(wd / "libcloudstorage.so.22.0")
for n in ("BCompare", "libcloudstorage.so.22.0"):
    release_binary_lock(wd / n)
    copy_binary_resilient(INSTALL / n, wd / n)
for a, t in [(0x23D735, True), (0x23AD34, True), (0x23AD3A, True), (0x23AD40, False)]:
    force_branch(so, a, so, t)

os.system("pkill -f '.argus-work/BCompare' 2>/dev/null")
time.sleep(1)
env = {**os.environ, "LD_LIBRARY_PATH": f"{INSTALL}/.argus-work:{INSTALL}"}
proc = subprocess.Popen([work], cwd=str(INSTALL), env=env)
for wait in (6, 15, 30):
    time.sleep(9 if wait > 6 else 6)
    maps = Path(f"/proc/{proc.pid}/maps").read_text()
    hits = [l for l in maps.splitlines() if "cloud" in l.lower() or "argus-work" in l]
    home = [l for l in subprocess.check_output(["wmctrl", "-l"], text=True).splitlines() if "Home - Beyond Compare" in l]
    print(f"after {wait}s home={bool(home)} cloud/argus maps={hits[:5]}")

# try LD_PRELOAD
proc.terminate()
time.sleep(1)
env = {**os.environ, "LD_LIBRARY_PATH": f"{INSTALL}/.argus-work:{INSTALL}",
       "LD_PRELOAD": str(wd / "libcloudstorage.so.22.0")}
proc = subprocess.Popen([work], cwd=str(INSTALL), env=env)
time.sleep(8)
maps = Path(f"/proc/{proc.pid}/maps").read_text()
hits = [l for l in maps.splitlines() if "cloudstorage" in l]
print("LD_PRELOAD cloud", hits[:3])
proc.terminate()
