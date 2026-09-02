"""Launch BC and report process + window state."""

import os
import subprocess
import time
from pathlib import Path

OUT = Path("/home/kiko/petwork/argus/tmp_live_launch.txt")
INSTALL = Path("/usr/lib/beyondcompare")
LAUNCHER = INSTALL / ".argus-work" / "run-bcompare.sh"


def main() -> None:
    os.system("pkill -f '/usr/lib/beyondcompare/.argus-work/BCompare' 2>/dev/null")
    time.sleep(1)
    lines: list[str] = []
    if not LAUNCHER.is_file():
        lines.append(f"MISSING launcher {LAUNCHER}")
        OUT.write_text("\n".join(lines))
        return

    proc = subprocess.Popen(
        [str(LAUNCHER)],
        cwd=str(INSTALL),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(6)
    poll = proc.poll()
    err = proc.stderr.read().decode("utf-8", "replace") if poll is not None else ""
    lines.append(f"pid={proc.pid} poll={poll}")
    if err:
        lines.append(f"stderr={err}")

    try:
        ps = subprocess.check_output(["pgrep", "-a", "BCompare"], text=True, stderr=subprocess.DEVNULL)
        lines.append(f"pgrep:\n{ps.strip()}")
    except subprocess.CalledProcessError:
        lines.append("pgrep: none")

    try:
        wins = subprocess.check_output(["wmctrl", "-l"], text=True, stderr=subprocess.DEVNULL)
        hits = [w for w in wins.splitlines() if "beyond" in w.lower() or "compare" in w.lower() or "home" in w.lower()]
        lines.append("wmctrl hits:\n" + ("\n".join(hits) if hits else "(none)"))
    except Exception as exc:
        lines.append(f"wmctrl error: {exc}")

    pid = None
    for ln in lines:
        if ln.startswith("pgrep:") and "BCompare" in ln:
            pid = ln.split()[0] if False else None
    try:
        pid = int(subprocess.check_output(["pgrep", "-f", ".argus-work/BCompare"], text=True).strip().split()[0])
    except Exception:
        pid = None
    if pid:
        maps = Path(f"/proc/{pid}/maps").read_text(errors="replace")
        so = [m for m in maps.splitlines() if "cloudstorage" in m or "lib7z" in m]
        lines.append("maps:\n" + "\n".join(so[:6]))

    OUT.write_text("\n".join(lines))
    print(OUT.read_text())


if __name__ == "__main__":
    main()
