# Argus 0.5.0 — Universal RE Agent (LLM plans, tools observe)

**Supersedes:** autopilot/fast-path scope in [PLAN_0.4.0.md](PLAN_0.4.0.md) for agent architecture.

**Goal:** Argus toolchain gives the LLM **rich, simple evidence** — but **never decides the investigation path**. The model behaves like a reverse engineer: hypothesize → experiment → interpret → next experiment.

> **LLM proposes (which tool + params). Deterministic tooling executes. Math/runtime verifies.**

---

## 1. Problem statement (0.4.x)

0.4.x added valuable **atoms** (diagnose_failure, decision_flow, apply_plan verify, sandbox) but also added **orchestration that bypasses the LLM**:

| Anti-pattern | Effect |
|--------------|--------|
| `run_gate_fast_path` before first LLM call | Agent exits `steps=0`; model never reasons |
| `bootstrap` injects `NEXT_ACTION` + «trust this over guessing» | Model delegates planning to Python |
| `auto_diagnose_plan` picks best patch + auto-applies | Task-class pipeline, not universal RE |
| `suggest_next_tool` → single next tool | Fixed FSM replaces RE judgment |
| `classify_task_intent` → different pipelines | Product modes by regex |
| Fallback `error_text="License"` | Hardcoded needle when observation missing |
| `_maybe_auto_recover` dispatches slice/diagnose/apply | Side effects without LLM |
| `apply_plan()` without `steps=` auto-slices | Hidden decisions |
| SYSTEM prompt «Fast-Path 1–2 steps for license» | Second planner in prose |

**Result:** High success on gate/corpus binaries, **low universality** — color change, custom behavior, unseen layouts fail because the agent never learned to investigate; Python already «finished».

---

## 2. Target architecture

```
User task
    ↓
LLM (only planner)
    ↓ tool_name + params (from user task / prior evidence)
Atomic tool (dumb executor)
    ↓ structured evidence (facts + optional ranked hints)
LLM interprets → next tool
    ↓
Verify tool → verification level
    ↓
_evaluate_tasks (deterministic truth — KEEP)
    ↓
done | incomplete | failed
```

### Roles

| Layer | Responsibility | Must NOT |
|-------|----------------|----------|
| **LLM** | Choose next experiment; pick needles from user/runtime; compose patch steps from evidence | Invent VAs; claim success without verify |
| **Tools** | Execute one operation; return observations | Auto-call other tools; auto-apply patches; pick «best» plan |
| **Hints** | Ranked suggestions, hypotheses, archetype signals | Imperative `NEXT_ACTION`; «trust this» |
| **Verify / tasks** | Ground truth from bytes/runtime/cert | Complete on model prose |

### Principle: hints ≠ decisions

Every former «router» becomes an **evidence field**:

```json
{
  "ok": true,
  "summary": "find: 3 hits for needle 'invalid'",
  "observations": ["PE64 stripped", "hit @ 0x1406fa317 preview='...'"],
  "evidence": { "hits": [...], "xrefs": [...] },
  "hints": {
    "suggested_tools": [
      {"tool": "argus_xrefs", "reason": "top hit has no plan yet", "confidence": 0.7},
      {"tool": "argus_decision_flow", "reason": "gate-like xref cluster", "confidence": 0.5}
    ],
    "signals": {"reject_ui_candidates": [...], "license_rodata": true}
  },
  "verify": null
}
```

LLM may ignore hints. Hints are **never** executed automatically.

---

## 3. Inventory — REMOVE (agent must not run these)

These **execute or terminate** without LLM approval.

| ID | Location | Action |
|----|----------|--------|
| R1 | `argus/llm/autopilot.py` → `run_gate_fast_path` | **Delete** from agent path; optional CLI `argus fast-path` for regression only |
| R2 | `argus/llm/agent.py` → `_try_gate_fast_path` | **Delete**; default = LLM always runs |
| R3 | `argus/llm/agent.py` → fast-path `finalize_agent(steps=0)` | **Delete** |
| R4 | `argus/llm/agent.py` → `_maybe_auto_recover` tool dispatch | **Delete** side effects; replace with text injection into `open_tasks_hint` |
| R5 | `argus/llm/autopilot.py` → `_dispatch_and_trace` in agent | **Remove** from agent; keep for tests/CLI |
| R6 | Bootstrap `NEXT_ACTION` + «trust this over guessing» | **Remove** imperative block |
| R7 | All `error_text or "License"` fallbacks | **Remove** — see §5 |
| R8 | `intent.routing_hint` hardcoded `'That license key'` | **Remove** |
| R9 | `argus_next_step` as single-action delegate | **Remove tool** or return ranked `hints.suggested_tools` only (no args) |
| R10 | `WEAK_SYSTEM` «call NEXT_ACTION first» | **Remove** |
| R11 | `bootstrap_agent_context` override: force apply_plan when ret_imm present | **Remove** |

### Env migration

| Old | New |
|-----|-----|
| `ARGUS_NO_FAST_PATH=1` to disable fast-path | Fast-path **off by default**; `ARGUS_FAST_PATH=1` for legacy corpus runs |
| — | `ARGUS_AGENT_AUTO_RECOVER=0` default (no auto dispatch) |

---

## 4. Inventory — DEGRADE_TO_HINT (keep analysis, drop decisions)

| ID | Location | Change |
|----|----------|--------|
| H1 | `classify_task_intent` | Return `task_signals: {gate:0.8, password:0.1, ui:0.3}` — no routing branches |
| H2 | `routing_hint()` | Neutral workflow **examples** in SYSTEM only; inject `signals` not «FAST PATH 2 steps» |
| H3 | `suggest_next_tool` | Rename → `rank_tool_suggestions()` → list of `{tool, reason, confidence}` |
| H4 | `suggest_next_action_from_trace` | Same; **no** auto-pivot dispatch; emit «pivot_candidate: modules=[…]» |
| H5 | `trim_patch_plan` | Return `{full_plan, suggested_batches: [[0:1], [0:3], all]}` — LLM picks |
| H6 | `bootstrap_agent_context` | Output `EVIDENCE REPORT` only; optional `hints.suggested_tools` |
| H7 | `run_investigate` | Stop binding `suggested_next_tool` as mandatory; add `reject_ui_candidates` from flow |
| H8 | `auto_diagnose_plan` | Never called by agent bootstrap; expose as tool `argus_diagnose_scan` returning **ranked** diagnoses |
| H9 | `match_archetype` | Prefix output: `Hypothesis (unverified):` |
| H10 | `apply_plan(steps=None)` | **Require** explicit steps OR prior `argus_slice` in same session with LLM copy — no silent auto-slice |
| H11 | `gate_scan` / `gate_scan_modules` `next_hint` | Factual: `plan_steps=3 confidence=low modules_scanned=2` |
| H12 | `open_tasks_hint` | Facts from trace only; no prescribed tool names unless as hints array |
| H13 | `_build_task_explanation` | Explain incomplete from verify level + trace, not «try argus_slice» |
| H14 | `_is_gate_task` fast-path gate | Remove with fast-path |

---

## 5. Inventory — KEEP (deterministic backends / safety)

These are **correct** — they analyze or verify, not plan.

| Component | Role |
|-----------|------|
| `flow.build_decision_flow` | CFG + gates → text + patch **candidates** |
| `flow.diagnose_failure(error_text=…)` | Back-trace when LLM ** supplies** needle |
| `flow.discover_reject_ui_strings` | Evidence list for LLM to choose needle |
| `find_slice.build_patch_plan` | Static ranking → evidence |
| `find.find_in_binary`, xrefs, disasm | Observe |
| `apply_plan` strict plan / `_is_diagnose_plan` | Safety: reject invented steps |
| `apply_plan` verify_patch_disasm | Static verify |
| `patch/*` intents | Byte transform executors |
| `sandbox`, `gui_oracle` (smoke) | Runtime observe |
| `symbolic/concolic solve` | Formal backend |
| `_evaluate_tasks` / `tasks_all_done` | Truth model |
| `discover.py` module scoring | Install-dir evidence |
| `memory/retrieve` | RAG hints (labeled not ground truth) |

### Needle policy (no hardcode rule)

| Allowed | Forbidden |
|---------|-----------|
| User-supplied string in tool arg | Default `error_text="License"` |
| Verbatim sandbox/GUI capture | `_VALIDATE_SUBS` as **only** scan set without query |
| `discover_reject_ui_strings` as **candidates list** | Auto-pick best + auto-apply |
| Structural tokens in **scoring** (`invalid`, `denied`) | Product/vendor branches |

**Change:** `find_slice._VALIDATE_SUBS` used only when `query=` empty → instead return «no query: pass query= or pick from reject_ui_candidates».

---

## 6. Unified tool output contract (0.5)

Every `argus_*` tool returns:

```python
@dataclass
class ToolResult:
    ok: bool
    summary: str                          # one line for LLM
    observations: list[str]               # human-readable facts
    evidence: dict[str, Any]              # machine payload (hits, plan, disasm)
    hints: dict[str, Any] | None = None   # suggested_tools, signals, batches
    verify: dict[str, Any] | None = None  # level, detail, patched_path
    next_errors: list[str] | None = None  # what's missing ("need error_text")
```

### Tool catalog (atomic surface)

| Tool | Params from LLM | Returns (evidence) |
|------|-----------------|-------------------|
| `artifact.inspect` / `analyze` | binary | fmt, arch, sections, protection |
| `find` | binary, query | hits[{addr, preview}] |
| `xrefs` | binary, addr | sites[{addr, fn, disasm}] |
| `disasm` | binary, addr, count | insns[] |
| `cfg` | binary, fn | blocks, edges |
| `decision_flow` | binary, target | gates[], text_flow, patch_candidates[] |
| `diagnose_failure` | binary, error_text **required** | corrective_patch[], caller, explanation |
| `diagnose_scan` | binary, limit? | ranked[{error_text, patch, score}] — **NEW** (wraps auto_diagnose_plan) |
| `slice` | binary, query?, modules? | patch_plan[], confidence, per_module |
| `state_flags` | binary | struct flag sites |
| `apply_plan` | binary, steps[] **required** | patched_path, verify |
| `patch` | binary, kind, addr, … | single-step result |
| `sandbox` | binary | exit, stderr, titles, captured_text |
| `gui_oracle` | binary, reject_texts? | launch smoke only |
| `solve` / `ai` | binary, query | solver result |
| `discover` | root, prompt | ranked modules |
| `lift` | binary, fn/query | pseudo-C |
| `research` | query | external notes (not ground truth) |

**Removed from default agent:** `argus_next_step` (or hints-only variant).

---

## 7. Agent loop changes

### 7.1 Bootstrap (before step 1)

**Was:** investigate + slice + NEXT_ACTION + fast-path apply.

**Becomes:**

```python
def bootstrap_evidence(binary, user_prompt, discover) -> str:
    # Lightweight only — no gate_scan unless LLM asks
    img = load_binary(binary)
    prot = detect_protection(img)
    reject_candidates = discover_reject_ui_strings(img)[:8]
    signals = task_signals(user_prompt, binary)  # was classify_task_intent
    return format_evidence_block(
        binary_summary=...,
        user_task=user_prompt,
        reject_ui_candidates=reject_candidates,
        task_signals=signals,
        work_copy=workspace_path,
        tools_available=tool_catalog_short,
    )
```

LLM first turn: typically `find` or `diagnose_failure` with user-derived needle, or `inspect` if vague task.

### 7.2 SYSTEM prompt rewrite

**Remove:** «Fast-Path Workflow 1–2 steps for license», fixed stage names as mandatory pipeline.

**Keep:** Cognitive model as **education** (verification chain, dominator architecture) — examples not steps.

**Add:**

```
- Tools return observations + hints. Hints are suggestions — you choose the next experiment.
- Never apply patches without steps copied from evidence (slice, diagnose_failure, decision_flow).
- error_text for diagnose_failure MUST come from user, sandbox, or GUI capture — never guess.
- If reject_ui_candidates appear in bootstrap, pick the best match to user intent and verify with xrefs.
- Verification levels: bytes < execution < behavior. Report what was verified, not what you assume.
```

### 7.3 Per-step context

Each LLM turn receives:

1. User task
2. `EVIDENCE REPORT` (bootstrap, refreshed after investigate if LLM called it)
3. `TASK STATUS` from `_evaluate_tasks` (facts)
4. Last N tool results (full evidence, truncated disasm only)
5. `hints.suggested_tools` from last tool (optional)
6. Memory RAG (labeled «past cases, not ground truth»)

**Not injected:** NEXT_ACTION, routing_hint imperatives, auto-recover dispatches.

### 7.4 Termination

Unchanged: `_evaluate_tasks` + verify metadata. LLM `answer` prose never marks done alone.

---

## 8. Phased implementation

### Phase 0 — Guardrails & docs (1–2 days)

- [x] Add `PLAN_0.5.0.md` (this file) to README pointer
- [x] Add `.cursor/rules/no-autopilot.mdc`: forbid new auto-dispatch in agent path
- [x] Tests: `test_agent_no_fast_path_by_default`

### Phase 1 — Remove LLM bypass (3–5 days)

- [x] R1–R5: Remove fast-path from `agent.py`; keep `run_gate_fast_path` as `argus.cli` debug command
- [x] R4: Gut `_maybe_auto_recover` dispatch; hints only
- [x] R6–R11: Bootstrap evidence-only
- [x] R7–R8: Remove all `"License"` fallbacks; tests expect `error_text required`
- [x] Flip env: fast-path opt-in `ARGUS_FAST_PATH=1`
- [x] Update `tests/test_hardening_040.py`, `tests/test_agent_ui.py`

### Phase 2 — Hint refactor (5–7 days)

- [x] H1–H3: `task_signals`, `rank_tool_suggestions`
- [x] H5: `suggest_patch_batches(plan)` utility
- [x] H8: New tool `argus_diagnose_scan` (ranked only)
- [x] H10: `apply_plan` requires steps; clear error if missing
- [x] H11–H13: Factual hints in slice/tasks
- [x] Implement `ToolResult` wrapper in `tools.py`; migrate top 8 tools *(find + envelope; partial migration)*

### Phase 3 — Rich evidence (5–7 days)

- [x] Bootstrap `reject_ui_candidates` + `task_signals`
- [x] `investigate` → evidence report tool (LLM-invoked, not auto)
- [x] `find` always echoes query used; empty query → candidates list not silent scan
- [x] `xrefs` include 3-instruction disasm at each site
- [x] `decision_flow` include `patch_candidates` with confidence per step
- [x] `diagnose_failure` require `error_text`; return `next_errors` if missing
- [x] Session transcript: structured evidence blocks for replay *(evidence_digest on tool_result)*

### Phase 4 — SYSTEM + weak models (2–3 days)

- [x] Unified SYSTEM (no WEAK prescriptive delta)
- [x] Weak models: shorter tool catalog in user msg, same rules
- [x] Remove `default_max_steps` bias; CLI `--max-steps` only

### Phase 5 — Verification & memory (3–4 days)

- [x] Task verify: gate tasks require explicit verify in trace (bytes+disasm OK for diagnose-sourced)
- [x] Certificate records `planner=llm` vs `planner=fast_path_legacy`
- [x] Memory cases store tool sequence, not auto-plan
- [x] RAG retrieves similar **investigation paths**, not patch addresses

### Phase 6 — Live E2E (ongoing)

- [x] `tests/test_agent_e2e_live.py` (skip without API key)
- [ ] Scenarios: gate (Sublime), crackme (password), UI string replace, **general** («find export foo»)
- [x] Metric: `llm_tool_steps > 0` and task done *(basic live test)*

---

## 9. File-by-file edit map

| File | Phase | Changes |
|------|-------|---------|
| `argus/llm/agent.py` | 1,4 | Remove fast-path, auto-recover; rewrite SYSTEM; bootstrap evidence |
| `argus/llm/autopilot.py` | 1,2 | Delete gate fast-path from agent; keep bootstrap helpers; hints only |
| `argus/llm/investigate.py` | 2,3 | rank_tool_suggestions; rich evidence |
| `argus/llm/intent.py` | 2 | task_signals; neutral routing examples |
| `argus/llm/tools.py` | 2,3 | ToolResult; diagnose_scan; apply_plan steps required |
| `argus/llm/tasks.py` | 2,5 | open_tasks_hint factual; remove License fallback |
| `argus/llm/research.py` | 2 | Evidence-only brief |
| `argus/llm/archetypes.py` | 2 | Hypothesis labeling |
| `argus/flow.py` | 3 | diagnose_scan export; document discover_reject as candidates |
| `argus/find_slice.py` | 3 | next_hint factual; query-required scan |
| `argus/apply_plan.py` | 2 | No auto-slice default |
| `argus/cli/main.py` | 1 | `argus debug fast-path` for regression |
| `tests/*` | 1–6 | See §10 |

---

## 10. Test strategy

### Unit (no LLM)

| Test | Asserts |
|------|---------|
| `test_no_fast_path_in_agent` | `run_agent` never calls `run_gate_fast_path` by default |
| `test_apply_plan_requires_steps` | Empty steps → error with hint to call slice |
| `test_diagnose_failure_requires_text` | No error_text → ok=false, next_errors |
| `test_no_license_fallback` | extract_failure_context never returns «License» alone |
| `test_bootstrap_no_next_action` | Bootstrap string lacks `NEXT_ACTION` |
| `test_tool_result_schema` | All tools return observations+evidence |
| `test_diagnose_scan_ranked` | Returns ≥2 candidates or empty, never auto-applies |

### Integration (corpus)

| Test | Asserts |
|------|---------|
| `test_flow_diagnose_sublime` | corrective_patch non-empty when error_text given |
| `test_apply_static_verify` | bytes+disasm ok |
| Existing `test_hardening_040` | Adapt: fast-path via CLI only |

### Live agent (optional CI)

| Test | Asserts |
|------|---------|
| `test_agent_gate_live` | steps≥3, apply in trace, task done |
| `test_agent_general_live` | «list exports» completes without apply_plan |

---

## 11. Example sessions (target behavior)

### A. Gate / reject dialog (any binary)

```
User: accept any key for Enter License
LLM: find(query="license") → hits
LLM: xrefs(addr=top) → caller sites
LLM: diagnose_failure(error_text=<verbatim from hit or user>) → corrective_patch
LLM: apply_plan(steps=patch[0:3]) → verify bytes ok
LLM: apply_plan(steps=patch[3:]) → verify ok
Tasks: done (EXECUTION_VERIFIED)
```

### B. User gives exact error text

```
User: bypass — dialog says "Evaluation period expired"
LLM: diagnose_failure(error_text="Evaluation period expired") → patch
LLM: apply_plan(steps=...) → sandbox → done
```

### C. Color / UI (universal path)

```
User: make the toolbar background darker
LLM: find(query="background") or find(query="#") → hits
LLM: xrefs → disasm → identifies RGB immediate
LLM: patch(kind=nop_bytes|patch_bytes, ...) OR research if no anchor
LLM: sandbox → user confirms OR static only with caveat
```

### D. Failure — no guess

```
LLM: diagnose_failure() without error_text
Tool: ok=false, next_errors=["pass error_text from sandbox or user"]
LLM: sandbox(binary) → captures stderr/title
LLM: diagnose_failure(error_text=<captured>) → ...
```

---

## 12. Success metrics (0.5 release gate)

- [ ] **No agent code path** auto-dispatches tools (grep CI check)
- [ ] **No default needles** in diagnose/autopilot (grep CI check)
- [ ] `pytest -q` green without live LLM
- [ ] Corpus gate tests pass via **explicit** tool sequence (scripted agent mock or live)
- [ ] At least one **non-gate** scenario documented (string replace or find export)
- [ ] `steps=0` agent runs flagged warning in CLI output
- [ ] Docs: [docs/ARGUS_VISION.md](docs/ARGUS_VISION.md) updated — «autopilot deprecated»

---

## 13. Non-goals (0.5)

- Full Argus IR lift/transform (0.6+)
- APK/DEX adapters
- GUI auto-input (remains forbidden)
- Teaching LLM vendor-specific recipes
- Fine-tuned models

---

## 14. Migration notes for users

```powershell
# Old (0.4): agent often finished at steps=0
python -m argus.cli.main agent "..." app.exe --provider gemini

# New (0.5): LLM always runs; expect steps>=1
# Legacy fast-path for scripts:
$env:ARGUS_FAST_PATH = "1"
python -m argus.cli.main debug fast-path "..." app.exe
```

---

## 15. Summary

| | 0.4.x | 0.5.x |
|---|-------|-------|
| Planner | Python fast-path + LLM | **LLM only** |
| Tool role | Pipeline stages | **Atomic experiments** |
| diagnose | Auto needle + auto apply | LLM picks needle |
| Bootstrap | NEXT_ACTION | **EVIDENCE REPORT** |
| Success on unseen | Low (wrong pipeline) | Higher (same RE loop) |
| Success on gate corpus | High (short-circuit) | Good (LLM + same atoms) |

**One sentence:** Stop finishing investigations before the model sees them; give it more evidence, not more decisions.
