from pathlib import Path

from argus.binary import load_binary
from argus.binary.file_io import copy_binary_resilient, release_binary_lock
from argus.disasm.cfg import disassemble_at
from argus.disasm.recovery import function_covering
from argus.find import find_in_binary, find_string_xrefs, suggest_patches_near
from argus.llm.workspace import prepare_work_binary
from argus.patch.intents import force_branch

INSTALL = Path("/usr/lib/beyondcompare")
work, _ = prepare_work_binary(str(INSTALL / "BCompare"))
wd = Path(work).parent
so = wd / "libcloudstorage.so.22.0"
for n in ["BCompare", "libcloudstorage.so.22.0"]:
    release_binary_lock(wd / n)
    copy_binary_resilient(INSTALL / n, wd / n)

img = load_binary(str(so))
# trial xref hub
xref = 0x23ACE2
bound = function_covering(img, xref)
print("fn", hex(bound.start) if bound else None, hex(bound.end) if bound else None)
if bound:
    insns = disassemble_at(img, bound.start, max_insns=200)
    jccs = [i for i in insns if i.mnemonic.lower().startswith("j") and i.mnemonic.lower() not in ("jmp",)]
    print("jccs in fn", len(jccs))
    for i in jccs[:20]:
        print(f"  {hex(i.address)}: {i.mnemonic} {i.op_str}")

# suggest near xref
cands = suggest_patches_near(img, xref, window=256)
print("\ncands near xref", len(cands))
for c in cands[:10]:
    print(c)

# BCompare trial mode footer
f = find_in_binary(work, "Running in trial")
print("\nBCompare trial footer hits", f.get("hits")[:3])
for h in (f.get("hits") or [])[:2]:
    img2 = load_binary(work)
    x = find_string_xrefs(img2, int(h["addr"], 16))[:6]
    print(" xrefs", x)
    for xr in x[:3]:
        site = int(xr["addr"], 16)
        for c in suggest_patches_near(img2, site, window=128)[:4]:
            print("  cand", c)
