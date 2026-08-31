from __future__ import annotations

"""Unified tool output contract (0.5)."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolResult:
    ok: bool = True
    summary: str = ""
    observations: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    hints: Optional[Dict[str, Any]] = None
    verify: Optional[Dict[str, Any]] = None
    next_errors: Optional[List[str]] = None
    next_hint: str = ""
    limits: Optional[Dict[str, Any]] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ok": self.ok,
            "summary": self.summary,
            "observations": list(self.observations),
            "evidence": dict(self.evidence or {}),
        }
        if self.hints is not None:
            out["hints"] = self.hints
        if self.verify is not None:
            out["verify"] = self.verify
        if self.next_errors:
            out["next_errors"] = list(self.next_errors)
        if self.next_hint:
            out["next_hint"] = self.next_hint
        if self.limits:
            out["limits"] = self.limits
        out.update(self.extra)
        return out


def envelope_from_result(result: ToolResult) -> Dict[str, Any]:
    return result.to_dict()


def digest_tool_result(result: str, *, max_obs: int = 8) -> Optional[Dict[str, Any]]:
    """Compact evidence block for transcripts / logs — no full patch bytes."""
    import json

    try:
        payload = json.loads(result)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    digest: Dict[str, Any] = {
        "ok": payload.get("ok"),
        "summary": str(payload.get("summary") or "")[:400],
    }
    obs = payload.get("observations")
    if obs:
        digest["observations"] = list(obs)[:max_obs]
    hints = payload.get("hints")
    if isinstance(hints, dict):
        slim: Dict[str, Any] = {}
        if hints.get("suggested_tools"):
            slim["suggested_tools"] = hints["suggested_tools"][:5]
        if hints.get("suggested_batches"):
            slim["suggested_batches"] = [
                {
                    "label": b.get("label"),
                    "step_count": len(b.get("steps") or []),
                    "rationale": b.get("rationale"),
                }
                for b in hints["suggested_batches"][:4]
            ]
        if hints.get("reject_ui_candidates"):
            slim["reject_ui_candidates"] = list(hints["reject_ui_candidates"])[:8]
        if slim:
            digest["hints"] = slim
    verify = payload.get("verify")
    if isinstance(verify, dict):
        digest["verify"] = {
            "kind": verify.get("kind"),
            "ok": verify.get("ok"),
            "detail": str(verify.get("detail") or "")[:160],
        }
    ev = payload.get("evidence") or {}
    if isinstance(ev, dict):
        if ev.get("patch_plan"):
            digest["patch_plan_len"] = len(ev["patch_plan"])
        if ev.get("ranked_diagnoses"):
            digest["ranked_diagnoses"] = len(ev["ranked_diagnoses"])
    elif payload.get("patch_plan"):
        digest["patch_plan_len"] = len(payload["patch_plan"])
    if payload.get("next_errors"):
        digest["next_errors"] = list(payload["next_errors"])[:4]
    return digest
