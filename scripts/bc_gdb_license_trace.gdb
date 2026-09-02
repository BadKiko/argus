set pagination off
set confirm off
set print thread-events off
handle SIGPIPE nostop noprint pass

set environment LD_LIBRARY_PATH /usr/lib/beyondcompare
set disable-randomization on

file /usr/lib/beyondcompare/BCompare

# Stop at entry, then install runtime breakpoints from load base.
break *0xcb6030
run

python
import gdb

SEG = 0xCAF000
maps = gdb.execute("info proc mappings", to_string=True)
base = None
for line in maps.splitlines():
    if "BCompare" in line and "r-xp" in line:
        base = int(line.split("-")[0], 16)
        break
if base is None:
    raise gdb.GdbError("no BCompare r-xp mapping")

print(f"exe_rx_base = {base:#x}")

SITES = [
    ("ccaeb0_error_dialog", 0xCCAEb0),
    ("d30b8d_enter_key_err", 0xD30B8D),
    ("d30b47_so_apply", 0xD30B47),
    ("d30bb0_version", 0xD30BB0),
    ("d30b64_after_apply", 0xD30B64),
    ("d309f0_err6", 0xD309F0),
    ("d3013e_dialog_err", 0xD3013E),
    ("d30ca3_err", 0xD30CA3),
    ("1150367_err", 0x1150367),
    ("cb6215_async_err", 0xCB6215),
    ("114f680_version", 0x114F680),
    ("d30fd8_version", 0xD30FD8),
]

for name, vma in SITES:
    addr = base + (vma - SEG)
    gdb.execute(f"break *{addr:#x}")
    gdb.execute(
        "commands\n"
        "  silent\n"
        f"  printf \"\\n=== HIT {name} @ %lx ===\\n\", $rip\n"
        "  bt 12\n"
        "  printf \"rax=%lx rbx=%lx rsi=%lx rdi=%lx r12=%lx\\n\", $rax,$rbx,$rsi,$rdi,$r12\n"
        "  continue\n"
        "end"
    )
    print(f"bp {name} runtime={addr:#x} vma={vma:#x}")

gdb.execute("delete 1")  # remove entry breakpoint
gdb.execute("continue")
end
