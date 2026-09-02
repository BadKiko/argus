import os, subprocess, time
from pathlib import Path
OUT = Path("/home/kiko/petwork/argus/tmp_home_check.txt")
INSTALL = Path("/usr/lib/beyondcompare")
os.system("pkill -f '.argus-work/BCompare' 2>/dev/null")
time.sleep(1)
env = {**os.environ, "LD_LIBRARY_PATH": f"{INSTALL}/.argus-work:{INSTALL}"}
p = subprocess.Popen([str(INSTALL / ".argus-work/BCompare")], cwd=str(INSTALL), env=env)
time.sleep(7)
w = subprocess.check_output(["wmctrl", "-l"], text=True)
home = [x for x in w.splitlines() if "Home - Beyond Compare" in x]
OUT.write_text(f"alive={p.poll() is None}\nhome={home}\n")
if p.poll() is None:
    p.terminate()
print(OUT.read_text())
