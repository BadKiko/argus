# Argus 0.4.0 — release plan

Supersedes incomplete [PLAN_0.2.0.md](PLAN_0.2.0.md) for agent hardening scope.

## Done in 0.4.0

- **Truth model**: strict GUI/behavior verify (no timeout=false-success), positive oracle for slice plans
- **argus_exec**: python-only default, workspace jail, no password grounding
- **VerificationLevel**: unified BYTES / EXECUTION / BEHAVIOR / FORMAL
- **Autopilot**: bootstrap before LLM, auto-pivot on empty slice, `argus_next_step`, weak SYSTEM for Flash Lite
- **Sandbox**: auto preflight before `argus_apply_plan`
- **Concolic**: seed from `concrete_until_branch`, libc hooks (fgets/memcmp/strlen), hint parsing in solve
- **PE CFF**: rsp slot + indirect-jmp dispatcher heuristics

## Backlog 0.5+

- Full Argus IR lift/transform
- Mach-O / DEX / APK adapters
- VMP partial Unicorn (Wave D)
- UPX orchestration (Wave E)
- Live LLM e2e tests

## Release gate

- `__version__ == "0.4.0"`
- `pytest -q` green (no live LLM)
- Gate tasks require behavior oracle, not silence
