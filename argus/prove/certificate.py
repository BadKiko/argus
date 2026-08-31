from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class VerificationLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    USER_REPORTED = "USER_REPORTED"
    BYTES_VERIFIED = "BYTES_VERIFIED"
    EXECUTION_VERIFIED = "EXECUTION_VERIFIED"
    BEHAVIOR_VERIFIED = "BEHAVIOR_VERIFIED"
    FORMALLY_VERIFIED = "FORMALLY_VERIFIED"


@dataclass
class PatchCertificate:
    """Evidence that a patch is safe to ship (or explicitly unproven)."""

    patches: List[Dict[str, Any]] = field(default_factory=list)
    behavioral: Optional[Dict[str, Any]] = None
    proven: bool = False
    level: VerificationLevel = VerificationLevel.UNKNOWN
    notes: List[str] = field(default_factory=list)
    planner: str = "llm"

    def to_dict(self) -> dict:
        return {
            "proven": self.proven,
            "level": self.level.value,
            "patches": self.patches,
            "behavioral": self.behavioral,
            "notes": self.notes,
            "planner": self.planner,
        }


def level_from_verify(verify: Optional[Dict[str, Any]]) -> VerificationLevel:
    if not verify or verify.get("ok") is not True:
        return VerificationLevel.UNKNOWN
    kind = verify.get("kind") or ""
    if kind == "patch_composite":
        behavior = verify.get("patch_behavior") or {}
        if behavior.get("ran") and behavior.get("ok") is True:
            return VerificationLevel.BEHAVIOR_VERIFIED
        bytes_v = verify.get("patch_bytes") or {}
        if bytes_v.get("ok") is True:
            return VerificationLevel.BYTES_VERIFIED
    if kind == "patch_bytes":
        return VerificationLevel.BYTES_VERIFIED
    if kind in ("behavioral", "concrete", "patch_behavior"):
        return VerificationLevel.BEHAVIOR_VERIFIED
    return VerificationLevel.UNKNOWN


def certify_apply_plan(
    applied: List[Dict[str, Any]],
    verify: Optional[Dict[str, Any]],
    *,
    planner: str = "llm",
) -> PatchCertificate:
    level = level_from_verify(verify)
    proven = level == VerificationLevel.FORMALLY_VERIFIED
    notes: List[str] = []
    if verify:
        notes.append(str(verify.get("detail") or verify.get("kind") or "verify"))
    behavioral = None
    if verify and verify.get("kind") == "patch_composite":
        behavioral = verify.get("patch_behavior")
    return PatchCertificate(
        patches=[dict(a) for a in applied],
        behavioral=behavioral,
        proven=proven,
        level=level,
        notes=notes,
        planner=planner,
    )


def certify_nop_patches(patch_records: list, verify_result: Optional[dict] = None) -> PatchCertificate:
    """NOP-only patches are syntactically local; behavioral verify upgrades to proven."""
    notes = ["NOP patches do not change non-nop instruction semantics locally"]
    proven = False
    behavioral = verify_result
    level = VerificationLevel.UNKNOWN
    if verify_result and verify_result.get("ok"):
        proven = True
        level = VerificationLevel.BEHAVIOR_VERIFIED
        notes.append("behavioral verify ok")
    elif verify_result:
        notes.append(f"behavioral verify incomplete: {verify_result}")
    return PatchCertificate(
        patches=[
            {
                "addr": hex(p.addr),
                "old": p.old.hex(),
                "new": p.new.hex(),
                "note": p.note,
            }
            for p in patch_records
        ],
        behavioral=behavioral,
        proven=proven,
        level=level,
        notes=notes,
    )
