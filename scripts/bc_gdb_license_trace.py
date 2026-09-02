#!/usr/bin/env python3
"""Launch Beyond Compare under GDB and trace license/register paths.

Usage:
  python3 scripts/bc_gdb_license_trace.py

Then: Help -> Enter Key -> any text -> OK
Log: tmp_gdb_license.log
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GDB_SCRIPT = ROOT / "scripts" / "bc_gdb_starti.gdb"
LOG = ROOT / "tmp_gdb_license.log"


def main() -> int:
    GDB_SCRIPT.write_text(
        (Path("/tmp/bc_gdb_starti.gdb").read_text() if Path("/tmp/bc_gdb_starti.gdb").is_file() else "")
        or _default_gdb_script()
    )
    subprocess.run(["pkill", "-x", "BCompare"], capture_output=True)
    subprocess.run(["pkill", "-f", "gdb.*bc_gdb_starti"], capture_output=True)
    LOG.write_text("")
    print(f"Starting GDB trace -> {LOG}", flush=True)
    print("Help -> Enter Key -> any text -> OK", flush=True)
    proc = subprocess.Popen(["gdb", "-q", "-x", str(GDB_SCRIPT)], stdout=LOG.open("a"), stderr=subprocess.STDOUT)
    print(f"gdb pid={proc.pid}", flush=True)
    return 0


def _default_gdb_script() -> str:
    return Path("/tmp/bc_gdb_starti.gdb").read_text()


if __name__ == "__main__":
    sys.exit(main())
