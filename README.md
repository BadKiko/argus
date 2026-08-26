"""Argus 0.2.0 — certified hybrid binary deobfuscation for LLM agents.

## Thesis

> **ML/LLM proposes. Mathematics proves. Patches ship only with a certificate.**

The agent speaks natural language; Argus executes a strong pipeline and returns
a password, readable lift, or a patched binary.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,concrete]"
# optional: pip install torch upx
```

## LLM recipe (preferred)

```bash
argus ai "дай пароль для админа" samples/fauxware_fla
# → SOSNEAKY

argus ai "сделай always true для authenticate" samples/fauxware -o /tmp/bypass.bin
argus ai "покажи код функции authenticate" samples/fauxware_fla
argus ai "деобфусцируй" samples/fauxware_fla -o /tmp/x.deobf
argus ai "что за защита" samples/vmp/adder.vmp.exe
```

Python:

```python
from argus import ai
r = ai("samples/fauxware_fla", "дай пароль для админа")
print(r.answer)  # SOSNEAKY
```

Tool schema: `from argus import TOOL_SCHEMA`.

Structured API still available: `argus ask FILE --want password`.

## Classic CLI

```bash
argus analyze samples/fauxware
argus solve samples/fauxware --deobf
argus deobf samples/fauxware_fla -f authenticate --patch /tmp/out --all-cff --verify
argus certify samples/fauxware_fla -f authenticate --solve
argus eval --corpus samples --json /tmp/corpus.json
argus run samples/fauxware_fla -f authenticate -o /tmp/run.bin
```

## Sample corpus

See [`samples/MANIFEST.md`](samples/MANIFEST.md).

- OLLVM CFF ELF/PE — recover + unflatten + (ELF) solve-after-deobf
- VMP tiny — detect + stub + partial handler lift (`ask`/`ai` lift)
- Themida/ultrasec — load/detect smoke only (not full unpack in 0.2.0)

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q
```

## Layout

| Package | Role |
|---------|------|
| `argus.nl` / `argus.ask` | `argus ai` natural language + intent |
| `argus.binary` | ELF/PE loaders |
| `argus.disasm` | Capstone CFG |
| `argus.symbolic` | concolic-friendly Z3 explorer |
| `argus.concrete` | Unicorn runner + concolic seeds |
| `argus.deobf` | CFF unflatten, MBA/bogus, VMP partial |
| `argus.patch` | intents + UPX + verify |
| `argus.ml` | ResGCN proposer (optional torch) |
| `argus.prove` | certificates |

## Non-goals (0.2.0)

Universal VMProtect/Themida commercial unpack. 100% on arbitrary binaries without an agent hint.

## License

MIT
"""
