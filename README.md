# Argus

**Argus** is an AI-driven reverse-engineering toolkit: you describe what you want in plain language, Argus investigates the binary with real tools, applies changes only to a work copy, and checks that the result actually holds.

> **The model proposes. Deterministic tools execute. Runtime / math verifies.**

It is **not** a license cracker and **not** a Ghidra clone with a chat box. It is a small laboratory where an LLM agent composes atomic operations (find strings, follow xrefs, lift code, build a patch plan, apply, verify) and keeps a certificate of what was proven.

---

## What it is for

| You want… | Argus can… |
|-----------|------------|
| Understand a stripped ELF/PE | Find strings, xrefs, lift pseudo-C, recover CFG |
| Change behavior safely | Build a `patch_plan`, apply it, verify bytes + smoke behavior |
| Solve a crackme / password | Symbolic / concolic solve (`argus ai` / agent) |
| Deobfuscate OLLVM-style CFF | Unflatten + optional patch + verify |
| Reuse past experience | Optional shared case memory (hints, not ground truth) |

**Not in scope (0.2.x):** full commercial VMProtect/Themida unpack; “100% on any binary with no hint.”

---

## How it works (mental model)

```
Your task (NL)
    → LLM agent picks tools
        → gate_scan / find / lift / patch / apply_plan / …
            → work copy of the binary (original stays untouched)
                → verify (bytes, optional behavior)
                    → task marked done only on tool evidence
```

Core ideas:

1. **Formats are adapters** — ELF/PE today; the agent thinks in tasks, not “PE-only recipes.”
2. **Prose never finishes a task** — status comes from tool results (`verify.ok`, slice-sourced plan, etc.).
3. **Gate transform pipeline** — `argus_slice` → `patch_plan` → `argus_apply_plan` → verify. Freestyle gate patches alone do not complete those tasks.
4. **Memory is RAG** — similar past cases are hints; you still must verify locally.

Longer vision: [docs/ARGUS_VISION.md](docs/ARGUS_VISION.md).

---

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,concrete]"
# optional: pip install -e ".[memory]"   # shared case memory client
# optional: pip install torch            # GNN proposer
```

CLI entry point: `argus`.

---

## Quick start

### 1. Natural language (no cloud LLM)

Regex / local router — good for smoke tests:

```bash
argus ai "дай пароль для админа" samples/fauxware_fla
```

### 2. Real agent (recommended)

**Gemini (AI Studio)** — get a key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey):

```bash
export GEMINI_API_KEY="AIza..."
export ARGUS_LLM_PROVIDER=gemini
export ARGUS_GEMINI_MODEL=gemini-2.0-flash

argus agent --provider gemini "дай пароль для админа" samples/fauxware_fla -v
```

**OpenAI-compatible** (OpenAI, OpenRouter, Gemini OpenAI shim):

```bash
export ARGUS_OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
export ARGUS_OPENAI_API_KEY="AIza..."
export ARGUS_OPENAI_MODEL="gemini-2.0-flash"

argus agent --provider openai "дай пароль" samples/fauxware -v
```

The agent discovers related modules if needed, only patches a **work copy**, and finalizes tasks from tool evidence.

### 3. Classic CLI

```bash
argus analyze samples/fauxware
argus solve samples/fauxware --deobf
argus deobf samples/fauxware_fla -f authenticate --patch /tmp/out --all-cff --verify
argus certify samples/fauxware_fla -f authenticate --solve
argus eval --corpus samples --json /tmp/corpus.json
```

Sample corpus: [samples/MANIFEST.md](samples/MANIFEST.md).

---

## Case memory (optional, on by default if installed)

Shared experience at `https://argus.cloud.badkiko.ru` after `pip install -e ".[memory]"`.

**Privacy:** each agent run may send a structured report (SHA256 + basename, arch/format, task text, strategies, outcome) and fetch similar cases as hints. **Raw binaries are never uploaded.**

```bash
argus agent "transform gate check" ./app          # default: memory on
argus agent --no-memory "…" ./app                 # one run off
export ARGUS_MEMORY=0                             # global off
export ARGUS_MEMORY_URL=https://your-server.example

argus memory search "stripped elf gate"
argus memory stats
```

Backend deploy: [argus-backend/README.md](argus-backend/README.md).

---

## Package map

| Package | Role |
|---------|------|
| `argus.llm` | Agent, tools, intent, session |
| `argus.ask` / `argus.nl` | Hint → answer / lift / patch |
| `argus.find_slice` | Gate scan → `patch_plan` |
| `argus.apply_plan` | Apply plan + verify |
| `argus.binary` | ELF/PE loaders |
| `argus.disasm` | Capstone CFG |
| `argus.symbolic` / `argus.concrete` | Z3 / Unicorn |
| `argus.deobf` | CFF, MBA, VMP partial |
| `argus.prove` | Certificates / verification levels |
| `argus.memory` | Remote case memory client |
| `argus.ir` | Format-agnostic IR skeleton |

---

## Tests

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q
```

---

## Languages

- English (this file): [README.md](README.md)
- Русский: [README.ru.md](README.ru.md)

## License

MIT
