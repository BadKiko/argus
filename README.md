"""Argus — certified hybrid binary deobfuscation.

## Thesis (what makes this different)

Most tools either:

- trust heuristics/ML and silently drop code, or
- run heavy symbolic execution on the full obfuscated CFG.

Argus is built around a stricter contract:

> **ML proposes. Mathematics proves. Patches ship only with a certificate.**

1. **Propose** junk / dispatcher structure (heuristics or ResGCN)
2. **Prove** each drop (unreachable, nop-only, or no side-effects off sink paths) — otherwise **keep**
3. **Recover** CFF via **state-variable analysis** (not only hub heuristics)
4. **Patch** with an explicit certificate (syntactic + optional behavioral verify)
5. Emit a machine-readable **`argus certify`** report

This is not a universal VMProtect unpacker. It is a framework for *proof-carrying* deobfuscation that can grow with real datasets.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install torch   # optional: GNN train/infer
```

## Quick start

```bash
argus analyze samples/fauxware
argus solve samples/fauxware                 # finds SOSNEAKY
argus prune samples/fauxware -f main         # proof-carrying prune
argus deobf samples/fauxware_fla -f authenticate
argus certify samples/fauxware_fla -f authenticate -o /tmp/cert.json
argus mba
argus patch samples/fauxware --nop 0x4007d5 4 --verify -o /tmp/fw.patched
```

## Sample corpus

Research/CTF binaries under [`samples/`](samples/MANIFEST.md):

- **OLLVM CFF** — Linux/Windows from ollvm-unflattener + fauxware_fla
- **VMProtect 3** — hello_world/adder/switch/… + Salwan samples + UltraSec crackme
- **Themida** — protected hello_world

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q
argus cfg samples/vmp/hello_world.vmp.exe --entry 0x140011267
argus deobf samples/ollvm/CFF_full_linux64.bin -f target_function
```

Upstream clones (optional) go in `third_party/` (gitignored).

## Layout

| Package | Role |
|---------|------|
| `argus.binary` | ELF/PE loaders |
| `argus.disasm` | Capstone CFG |
| `argus.symbolic` | crackme explorer (Z3) |
| `argus.ml` | features + ResGCN propose |
| `argus.prove` | deadness / patch certificates |
| `argus.deobf` | CFF state recovery, toy VM synth |
| `argus.mba` | MBA equivalence proofs |
| `argus.patch` | binary patch + verify |
| `argus.eval` | JSON reports / metrics |
| `legacy/` | archived prototype |

## License

MIT
"""
