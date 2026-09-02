"""Check libcloudstorage mapping when Enter Key path might dlopen again."""
import os
import subprocess
import time
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tmp_dlopen_check.txt"
INSTALL = Path("/usr/lib/beyondcompare")
SO = INSTALL / ".argus-work/libcloudstorage.so.22.0"

lines = []
for label, extra in [
    ("LD_PATH_only", {"LD_LIBRARY_PATH": f"{INSTALL}/.argus-work:{INSTALL}"}),
    ("PRELOAD", {"LD_LIBRARY_PATH": f"{INSTALL}/.argus-work:{INSTALL}", "LD_PRELOAD": str(SO)}),
]:
    os.system("pkill -f '.argus-work/BCompare' 2>/dev/null")
    time.sleep(1)
    env = {**os.environ, **extra}
    p = subprocess.Popen([str(INSTALL / ".argus-work/BCompare")], cwd=str(INSTALL), env=env)
    time.sleep(10)
    maps = Path(f"/proc/{p.pid}/maps").read_text().splitlines()
    cloud = [m for m in maps if "cloudstorage" in m]
    lines.append(f"\n== {label} ==")
    lines.append(f"count={len(cloud)}")
    for m in cloud:
        lines.append(m)
    # read first page of mapping at 14f310 if possible - check patched bytes via gdb? skip
    p.terminate()

OUT.write_text("\n".join(lines))
print(OUT.read_text())
