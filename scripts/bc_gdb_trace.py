#!/usr/bin/env python3
"""Attach GDB to BCompare and break on error dialog (ccaeb0).

Prints backtrace + caller when Error dialog is shown.
Usage:
  python3 bc_gdb_trace.py              # attach to running BCompare
  python3 bc_gdb_trace.py --launch     # start BC, wait, then break on ccaeb0
  python3 bc_gdb_trace.py --launch --trigger  # launch + open Enter Key via xdotool
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

INSTALL = Path("/usr/lib/beyondcompare")
EXE = INSTALL / "BCompare"
LAUNCHER = INSTALL / "run-BCompare.sh"

# VMAs from readelf (PIE link addresses == objdump addresses)
CCAE_B0 = 0xCCAE_B0
CB620C = 0xCB620C
CB6215 = 0xCB6215
ERR_CODE_GLOBAL = 0x2AB0340


def bcompare_pid() -> int | None:
    try:
        return int(subprocess.check_output(["pgrep", "-x", "BCompare"], text=True).strip().split()[0])
    except (subprocess.CalledProcessError, IndexError, ValueError):
        return None


def exe_rx_base(pid: int) -> int:
    maps = Path(f"/proc/{pid}/maps").read_text()
    for line in maps.splitlines():
        if "BCompare" in line and "r-xp" in line:
            return int(line.split("-")[0], 16)
    raise RuntimeError(f"no r-xp BCompare mapping for pid {pid}")


def vma_to_runtime(base: int, vma: int, seg_start: int = 0xCAF000) -> int:
    return base + (vma - seg_start)


def read_error_code(pid: int, base: int) -> int:
    """Best-effort read global error code via gdb."""
    addr = vma_to_runtime(base, ERR_CODE_GLOBAL)
    gdb = f"""
set pagination off
attach {pid}
set $a = *(int*){addr:#x}
printf "error_code_global=%d\\n", $a
detach
quit
"""
    out = subprocess.run(["gdb", "-batch", "-q", "-ex", gdb], capture_output=True, text=True)
    m = re.search(r"error_code_global=(\d+)", out.stdout + out.stderr)
    return int(m.group(1)) if m else -1


def gdb_spawn_trace(*, wait_s: float = 120.0) -> str:
    """Launch BCompare under GDB (works with ptrace_scope=1)."""
    script = f"""
set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
set environment LD_LIBRARY_PATH {INSTALL}
file {EXE}
start
python
import gdb
maps = gdb.execute("info proc mappings", to_string=True)
base = None
for line in maps.splitlines():
    if "BCompare" in line and "r-xp" in line:
        base = int(line.split("-")[0], 16)
        break
if base is None:
    raise RuntimeError("no BCompare r-xp mapping")
seg = 0xCAF000
sites = {{
    "ccaeb0": 0xCCAEb0,
    "cb620c": 0xCB620C,
    "cb6215": 0xCB6215,
    "d31011": 0xD31011,
    "d3119c": 0xD3119C,
}}
for name, vma in sites.items():
    addr = base + (vma - seg)
    gdb.execute(f"break *{{addr:#x}}")
    gdb.execute(f"commands {{addr:#x}} silent printf \\"\\\\n=== HIT {{name}} @ %lx ===\\\\n\\", $rip bt 15 continue end")
end
continue
"""
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        f.write(script)
        script_path = f.name

    lines = [f"spawn-under-gdb LD_LIBRARY_PATH={INSTALL}", f"Waiting {wait_s:.0f}s — open Enter Key -> OK"]
    try:
        proc = subprocess.run(
            ["timeout", str(int(wait_s)), "gdb", "-q", "-x", script_path],
            capture_output=True,
            text=True,
        )
        lines.append(proc.stdout)
        if proc.stderr:
            lines.append("stderr:\n" + proc.stderr)
    finally:
        Path(script_path).unlink(missing_ok=True)
    return "\n".join(lines)


def gdb_break_ccaeb0(pid: int, *, wait_s: float = 120.0) -> str:
    """Attach GDB — needs ptrace_scope=0."""
    base = exe_rx_base(pid)
    bp = vma_to_runtime(base, CCAE_B0)
    cb620c_rt = vma_to_runtime(base, CB620C)

    peek = subprocess.run(
        [
            "gdb", "-batch", "-q",
            "-ex", f"attach {pid}",
            "-ex", f"x/4i {cb620c_rt:#x}",
            "-ex", f"x/6bx {cb620c_rt:#x}",
            "-ex", "detach", "-ex", "quit",
        ],
        capture_output=True,
        text=True,
    )

    lines = [
        f"pid={pid} exe_rx_base={base:#x}",
        f"ccaeb0 runtime={bp:#x}",
        f"cb620c runtime={cb620c_rt:#x}",
        "",
        "=== patch bytes @ cb620c (runtime) ===",
        peek.stdout + peek.stderr,
    ]

    err = read_error_code(pid, base)
    lines.append(f"error_code_global (before) = {err}")

    script = f"""
set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
attach {pid}
break *{bp:#x}
commands
  silent
  printf "\\n=== HIT ccaeb0 (error dialog) ===\\n"
  printf "rip=%#lx\\n", $rip
  set $caller = *(void**)$rsp
  printf "return_addr=%#lx (vma ~ %#lx)\\n", $caller, $caller - {base} + 0xCAF000
  bt 20
  set $ec = *(int*)({vma_to_runtime(base, ERR_CODE_GLOBAL):#x})
  printf "error_code_global=%d\\n", $ec
  continue
end
continue
"""
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        f.write(script)
        script_path = f.name

    lines.append(f"\nWaiting up to {wait_s:.0f}s for ccaeb0...")
    try:
        proc = subprocess.run(
            ["timeout", str(int(wait_s)), "gdb", "-q", "-x", script_path],
            capture_output=True,
            text=True,
        )
        lines.append(proc.stdout)
        if proc.stderr:
            lines.append("stderr:\n" + proc.stderr)
    finally:
        Path(script_path).unlink(missing_ok=True)

    return "\n".join(lines)


def launch_bc() -> int:
    env = {**subprocess.os.environ, "LD_LIBRARY_PATH": str(INSTALL)}
    proc = subprocess.Popen(
        [str(EXE)],
        cwd=str(INSTALL),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(4)
    if proc.poll() is not None:
        raise RuntimeError(f"BCompare exited early code={proc.returncode}")
    return proc.pid


def trigger_enter_key() -> None:
    """Best-effort: open Help menu Enter Key via xdotool."""
    for cmd in (
        ["xdotool", "search", "--name", "Beyond Compare", "windowactivate"],
        ["sleep", "0.5"],
        ["xdotool", "key", "alt+h"],
        ["sleep", "0.3"],
        ["xdotool", "key", "Down", "Down", "Down", "Return"],  # may miss
    ):
        if cmd[0] == "sleep":
            time.sleep(float(cmd[1]))
        else:
            subprocess.run(cmd, capture_output=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--launch", action="store_true", help="start BCompare if not running")
    ap.add_argument("--trigger", action="store_true", help="try xdotool Enter Key menu")
    ap.add_argument("--spawn", action="store_true", help="launch under gdb (works with ptrace_scope=1)")
    ap.add_argument("--wait", type=float, default=120.0)
    ap.add_argument("-o", "--out", type=Path, default=Path(__file__).resolve().parents[1] / "tmp_gdb_trace.txt")
    args = ap.parse_args()

    if args.spawn:
        report = gdb_spawn_trace(wait_s=args.wait)
        args.out.write_text(report)
        print(report)
        print(f"\nwritten: {args.out}", flush=True)
        return 0

    pid = bcompare_pid()
    if pid is None and args.launch:
        print("Launching BCompare...", flush=True)
        pid = launch_bc()
        print(f"pid={pid}", flush=True)
    elif pid is None:
        print("BCompare not running. Use --launch or start it manually.", file=sys.stderr)
        return 1

    if args.trigger:
        print("Triggering menu (best-effort)...", flush=True)
        trigger_enter_key()
        time.sleep(1)

    report = gdb_break_ccaeb0(pid, wait_s=args.wait)
    args.out.write_text(report)
    print(report)
    print(f"\nwritten: {args.out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
