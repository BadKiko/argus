import os
import subprocess
import time
from pathlib import Path

INSTALL = Path("/usr/lib/beyondcompare")
OUT = Path(__file__).resolve().parents[1] / "tmp_launcher_test.txt"

os.system("pkill -f '.argus-work/BCompare' 2>/dev/null")
time.sleep(1)
subprocess.Popen([str(INSTALL / ".argus-work/run-bcompare.sh")], cwd=str(INSTALL))
time.sleep(7)
pid = subprocess.check_output(["pgrep", "-f", ".argus-work/BCompare"], text=True).strip().split()[0]
maps = Path(f"/proc/{pid}/maps").read_text()
cloud = [l for l in maps.splitlines() if "cloudstorage" in l]
home = [l for l in subprocess.check_output(["wmctrl", "-l"], text=True).splitlines() if "Home - Beyond Compare" in l]
OUT.write_text(f"home={home}\ncloud={cloud[:2]}\n")
os.system(f"kill {pid} 2>/dev/null")
print(OUT.read_text())
