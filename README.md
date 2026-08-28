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

## Real LLM agent (OpenAI-compatible **or native Gemini AI Studio**)

### Gemini (AI Studio) — recommended for Google keys

Get a key at https://aistudio.google.com/apikey (usually starts with `AIza…`).

```bash
source .venv/bin/activate
export GEMINI_API_KEY="AIza..."          # or ARGUS_GEMINI_API_KEY
export ARGUS_LLM_PROVIDER=gemini
export ARGUS_GEMINI_MODEL=gemini-2.0-flash   # or gemini-3.7-flash if available on your key

argus agent --provider gemini "дай пароль для админа" samples/fauxware_fla -v
```

Native endpoint (not a website — browser GET → 404 is normal):

```text
POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key=API_KEY
```

### OpenAI-compatible (OpenAI / OpenRouter / Gemini openai shim)

```bash
export ARGUS_OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
export ARGUS_OPENAI_API_KEY="AIza..."
export ARGUS_OPENAI_MODEL="gemini-2.0-flash"
argus agent --provider openai "дай пароль" samples/fauxware -v
```

Without a cloud model, use the regex router:

```bash
argus ai "дай пароль для админа" samples/fauxware_fla
```

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
| `argus.memory` | remote case memory client (vector search) |

## Case memory (remote backend, **on by default**)

Shared community experience at `https://argus.cloud.badkiko.ru` — enabled automatically after `pip install -e ".[memory]"`.

**Privacy:** each `argus agent` run may **send** a structured report (binary SHA256 + basename, arch/format, your task text, tool strategies, outcome) and **fetch** similar past cases as hints. Raw binaries are never uploaded.

```bash
pip install -e ".[memory]"   # httpx

# default — shared DB, notice printed once to stderr
argus agent "unlock license" ./app

# opt out for one run
argus agent --no-memory "unlock license" ./app

# opt out globally
export ARGUS_MEMORY=0

# own backend
export ARGUS_MEMORY_URL=https://your-server.example
```

```bash
argus memory search "stripped elf unlock"
argus memory stats
```

Backend deploy: see [`argus-backend/README.md`](argus-backend/README.md).

## Non-goals (0.2.0)

Universal VMProtect/Themida commercial unpack. 100% on arbitrary binaries without an agent hint.

## License

MIT
"""
