from __future__ import annotations

"""Commercial protection workflow (VMProtect / Themida / Denuvo) — 1.0.0 foundation.

Detect → trace/unpack → lift → diagnose → apply → verify on the same agent loop.
No product-specific patch recipes — only structural signals and workflow routing.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from argus.binary.image import BinaryImage
from argus.deobf.detect import ProtectionReport, detect_protection

COMMERCIAL_KINDS = frozenset({"vmp", "themida", "mixed", "denuvo"})

WORKFLOW_STAGES = (
    "detect",
    "observe",
    "trace",
    "unpack",
    "lift",
    "diagnose",
    "apply",
    "verify",
)

_WORKFLOW_BY_KIND = {
    "vmp": "vmp_vm",
    "themida": "themida_vm",
    "mixed": "vm_mixed",
    "denuvo": "denuvo_at",
}

_RECOMMENDED = {
    "vmp_vm": (
        "argus_run(reject_texts=…) — capture runtime/UI fragment",
        "argus_exec — optional trace/unpack probe when static find is empty",
        "argus_peek — stub/handler windows after trace",
        "argus_diagnose — on lifted code or runtime error_text",
        "argus_apply — only on grounded plan from diagnose",
        "argus_run — behavior verify",
    ),
    "themida_vm": (
        "argus_run(reject_texts=…) — runtime observe",
        "argus_exec — trace/OEP probe",
        "argus_peek — entry stub blocks",
        "argus_diagnose — lifted VM or error_text",
        "argus_apply → argus_run verify",
    ),
    "vm_mixed": (
        "argus_run — runtime observe first",
        "argus_exec — trace/unpack",
        "argus_peek / argus_diagnose on lifted regions",
        "argus_apply → argus_run verify",
    ),
    "denuvo_at": (
        "argus_run — launch and capture stderr/UI (protected module may load late)",
        "argus_exec — maps/dlopen/OEP trace when strings are absent",
        "argus_look — sibling payloads (not encrypted host .text)",
        "argus_diagnose on runtime error_text or post-OEP lift",
        "argus_apply → argus_run behavior verify",
    ),
}

_BLOCKED_UNTIL_LIFT = (
    "Repeated argus_find on encrypted host .text expecting license strings",
    "argus_apply native jcc/ret_imm on entry stub without diagnose evidence",
    "Treating idle GUI title as success without reject_texts verify",
)


@dataclass
class CommercialBrief:
    tier: str  # commercial | standard
    workflow: str  # vmp_vm | themida_vm | vm_mixed | denuvo_at | none
    protection: ProtectionReport
    stage: str = "detect"
    stages: List[str] = field(default_factory=lambda: list(WORKFLOW_STAGES))
    recommended_tools: List[str] = field(default_factory=list)
    blocked_until_lift: List[str] = field(default_factory=list)
    next_hint: str = ""
    agent_block: str = ""
    stub_blocks: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "workflow": self.workflow,
            "stage": self.stage,
            "stages": list(self.stages),
            "protection": self.protection.to_dict(),
            "recommended_tools": list(self.recommended_tools),
            "blocked_until_lift": list(self.blocked_until_lift),
            "next_hint": self.next_hint,
            "agent_block": self.agent_block,
            "stub_blocks": list(self.stub_blocks),
        }


def is_commercial_kind(kind: str) -> bool:
    return (kind or "").lower() in COMMERCIAL_KINDS


def workflow_for_kind(kind: str) -> str:
    k = (kind or "").lower()
    if k == "mixed":
        return "vm_mixed"
    return _WORKFLOW_BY_KIND.get(k, "none")


def _stub_preview(image: BinaryImage, *, max_blocks: int = 8) -> List[str]:
    try:
        from argus.deobf.vmp_layer import map_entry_stub

        stubs = map_entry_stub(image, max_blocks=max_blocks)
        return [hex(a) for a in stubs[:max_blocks]]
    except Exception:
        return []


def analyze_commercial(image: BinaryImage) -> CommercialBrief:
    prot = detect_protection(image)
    if not is_commercial_kind(prot.kind):
        return CommercialBrief(
            tier="standard",
            workflow="none",
            protection=prot,
            next_hint="",
            agent_block="",
        )

    wf = workflow_for_kind(prot.kind)
    rec = list(_RECOMMENDED.get(wf, _RECOMMENDED["vm_mixed"]))
    stubs = _stub_preview(image)
    blocked = list(_BLOCKED_UNTIL_LIFT)

    agent_lines = [
        "COMMERCIAL PROTECTION (1.0.0 workflow — do not treat as plain native):",
        f"  kind={prot.kind} conf={prot.confidence:.2f} workflow={wf}",
        f"  stage=observe — runtime/trace before string find on encrypted .text",
    ]
    if stubs:
        agent_lines.append(f"  entry_stub_blocks: {', '.join(stubs[:6])}")
    agent_lines.append("  recommended:")
    for line in rec[:5]:
        agent_lines.append(f"    - {line}")
    agent_lines.append("  blocked until lift/OEP:")
    for line in blocked[:3]:
        agent_lines.append(f"    - {line}")

    next_hint = (
        f"commercial {prot.kind}: argus_run(reject_texts=…) or argus_exec trace/OEP first — "
        "do not loop argus_find on encrypted host .text; diagnose/apply only on lifted or runtime evidence"
    )

    return CommercialBrief(
        tier="commercial",
        workflow=wf,
        protection=prot,
        stage="observe",
        recommended_tools=rec,
        blocked_until_lift=blocked,
        next_hint=next_hint,
        agent_block="\n".join(agent_lines),
        stub_blocks=stubs,
    )


def format_commercial_text(data: Dict[str, Any]) -> str:
    if not data or data.get("tier") != "commercial":
        return ""
    block = str(data.get("agent_block") or "").strip()
    if block:
        return block
    prot = data.get("protection") or {}
    wf = data.get("workflow") or "none"
    lines = [
        "COMMERCIAL PROTECTION:",
        f"  kind={prot.get('kind')} workflow={wf}",
        f"  next: {data.get('next_hint') or ''}",
    ]
    return "\n".join(lines)


def commercial_find_guard(image: BinaryImage) -> Optional[Dict[str, Any]]:
    """Overlay for argus_find on native ELF/PE behind commercial protection."""
    brief = analyze_commercial(image)
    if brief.tier != "commercial":
        return None
    return {
        "commercial": brief.to_dict(),
        "commercial_tier": brief.tier,
        "protection": brief.protection.to_dict(),
        "next_hint": brief.next_hint,
        "observations": [brief.agent_block.split("\n")[0] if brief.agent_block else brief.next_hint],
        "blocked_patterns": list(brief.blocked_until_lift),
        "recommended_tools": [{"tool": t.split("—")[0].strip(), "reason": "commercial workflow"} for t in brief.recommended_tools[:4]],
    }


def merge_find_commercial(result: Dict[str, Any], overlay: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not overlay:
        return result
    out = dict(result)
    ev = dict(out.get("evidence") or {})
    ev["commercial"] = overlay.get("commercial")
    ev["protection"] = overlay.get("protection")
    out["evidence"] = ev
    out["commercial"] = overlay.get("commercial")
    out["next_hint"] = overlay.get("next_hint") or out.get("next_hint")
    obs = list(out.get("observations") or [])
    for o in overlay.get("observations") or []:
        if o and o not in obs:
            obs.insert(0, o)
    out["observations"] = obs
    hints = dict(out.get("hints") or {})
    hints["commercial"] = overlay.get("commercial")
    hints["suggested_tools"] = overlay.get("recommended_tools") or hints.get("suggested_tools")
    out["hints"] = hints
    summary = str(out.get("summary") or "")
    if "commercial" not in summary:
        kind = (overlay.get("protection") or {}).get("kind") or "commercial"
        out["summary"] = f"{summary} commercial={kind}"
    return out


def commercial_observe_plan(brief: Dict[str, Any], user_prompt: str) -> Optional[Dict[str, Any]]:
    """CHECK FIRST for commercial native binaries — runtime before string find."""
    comm = brief.get("commercial") or {}
    if comm.get("tier") != "commercial":
        return None
    primary = str(brief.get("path") or "")
    name = primary.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] if primary else "primary"
    prot = comm.get("protection") or {}
    wf = comm.get("workflow") or "vm_mixed"
    queries: List[str] = []
    # Only grounded runtime needles — no invented license UI
    from argus.llm.observe import needles_from_task

    for q in needles_from_task(user_prompt, cap=3):
        queries.append(q)
    check_first = [
        {
            "name": name,
            "path": primary,
            "why": f"commercial {prot.get('kind')} — argus_run/observe before find on .text",
        }
    ]
    pool = []
    for key in ("payloads", "siblings"):
        for r in brief.get(key) or []:
            if str(r.get("kind") or "") in ("archive", "text"):
                pool.append(r)
    for r in pool[:3]:
        check_first.append(
            {
                "name": str(r.get("name") or ""),
                "path": str(r.get("path") or ""),
                "why": "sidecar payload — may hold plaintext logic outside VM",
            }
        )
    return {
        "check_first": check_first[:5],
        "find_queries": queries,
        "skip": [],
        "notes": (
            f"commercial workflow={wf}: CHECK FIRST is runtime observe + sidecar payloads, "
            "not repeated argus_find on encrypted host .text"
        ),
        "commercial": True,
        "workflow": wf,
    }
