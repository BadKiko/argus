# Argus — Vision, Architecture & Development

Argus is a research framework for **autonomous analysis, understanding, and transformation of binary programs**.

## Core goal

Universal **AI-driven reverse engineering / binary analysis agent** — not tied to specific formats or use cases.

> **Argus should understand programs, not specific file formats.**

Formats (PE, ELF, Mach-O, DEX, APK, IPA) are container adapters. The AI composes **atomic operations** into pipelines per task.

## Truth model

> **LLM proposes. Deterministic tooling executes. Mathematics/runtime verifies.**

Verification levels: `UNKNOWN` → `USER_REPORTED` → `EXECUTION_VERIFIED` → `BEHAVIOR_VERIFIED` → `FORMALLY_VERIFIED`.

## Architecture

```
User task → AI/Reasoner → Planner → Tools + Memory/RAG
         → Atomic ops (static / dynamic / formal)
         → Argus IR → Transform → Rebuild → Verify → Memory
```

## Naming (0.2.x+)

Legacy names removed. Use neutral vocabulary:

| Legacy | Current |
|--------|---------|
| `gate_scan` | `gate_scan` |
| `patch_plan` | `patch_plan` |
| `argus_apply_plan` | `argus_apply_plan` |
| `signal_score` | `signal_score` |

See [PLAN_0.2.0.md](../PLAN_0.2.0.md) naming refactor section.

## Memory

Structured case memory: successes **and** failures, strategy scoring, RAG hints (not ground truth).

## Long-term metric

**Unseen binary success rate** — generalize from past cases, not memorize one binary.

## Final principle

> Don't teach the AI every binary. Teach it how to investigate, remember, choose the next experiment, transform, and prove correctness.

## Argus 0.5 — LLM plans, tools observe

From **0.5.0**, the agent path follows:

```
User task → LLM (only planner) → atomic tools → evidence + hints → LLM next step → verify → memory
```

- **Fast-path / autopilot** is **opt-in** (`ARGUS_FAST_PATH=1` or `argus debug fast-path`) — not the default agent.
- Tools return **observations + ranked hints**; hints are never auto-executed.
- `apply_plan` and `diagnose_failure` require explicit parameters from the model (no silent auto-slice, no `"License"` fallback).
- Case memory stores **tool sequences** and `planner=llm` vs `fast_path_legacy`.

See [PLAN_0.5.0.md](../PLAN_0.5.0.md) and `.cursor/rules/no-autopilot.mdc`.
