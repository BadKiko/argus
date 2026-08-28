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
