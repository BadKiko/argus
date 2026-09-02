set pagination off
set confirm off
set debuginfod enabled off
set logging file /tmp/bc_gdb_license.log
set logging overwrite on
set logging enabled on
handle SIGPIPE nostop noprint pass
# Do NOT pass SIGSEGV — a continued crash can take down mutter/GNOME.
set environment LD_LIBRARY_PATH /usr/lib/beyondcompare
file /usr/lib/beyondcompare/BCompare
printf "Starting BC under debugger...\n"
starti
python
import gdb, re, time
SEG = 0xCAF000
HITLOG = "/tmp/bc_gdb_hits.log"
open(HITLOG, "w").write("gdb-python-bps\n")

maps = gdb.execute("info proc mappings", to_string=True)
base = None
for line in maps.splitlines():
    if "BCompare" in line and "r-xp" in line:
        base = int(line.split()[0], 16)
        break
if base is None:
    raise gdb.GdbError("no BCompare r-xp mapping")
print(f"exe_rx_base = {base:#x}", flush=True)

class HitBP(gdb.Breakpoint):
    def __init__(self, addr, name):
        super().__init__(f"*{addr:#x}")
        self.hit_name = name
        self.silent = True

    def stop(self):
        rip = int(gdb.parse_and_eval("$rip"))
        rax = int(gdb.parse_and_eval("$rax"))
        rdi = int(gdb.parse_and_eval("$rdi"))
        rsi = int(gdb.parse_and_eval("$rsi"))
        rcx = int(gdb.parse_and_eval("$rcx"))
        line = (
            f"HIT {self.hit_name} rip={rip:#x} "
            f"rax={rax:#x} rdi={rdi:#x} rsi={rsi:#x} rcx={rcx:#x} "
            f"t={time.time():.3f}\n"
        )
        with open(HITLOG, "a") as f:
            f.write(line)
            f.flush()
        gdb.write(f"\n=== {line}")
        return False  # continue

SITES = [
    ("d78fb0_register", 0xD78FB0),
    ("d76b10_decode", 0xD76B10),
    ("d76d35_charset_raise", 0xD76D35),
    ("d79313_err39", 0xD79313),
    ("d79390_err40", 0xD79390),
    ("d794cc_err6", 0xD794CC),
    ("d794d0_err6_store", 0xD794D0),
    ("d81100_checksum", 0xD81100),
    ("d7dcb0_err_dialog", 0xD7DCB0),
    ("d7ab98_thanks", 0xD7AB98),
    ("d7aa80_commit", 0xD7AA80),
]
BPS = []
for name, vma in SITES:
    addr = base + (vma - SEG)
    BPS.append(HitBP(addr, name))
    print(f"bp {name} runtime={addr:#x}", flush=True)
end
printf "\n>>> Ready\n\n"
continue
