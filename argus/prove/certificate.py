from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PatchCertificate:
    """Evidence that a patch is safe to ship (or explicitly unproven)."""

    patches: List[Dict[str, Any]] = field(default_factory=list)
    behavioral: Optional[Dict[str, Any]] = None
    proven: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "proven": self.proven,
            "patches": self.patches,
            "behavioral": self.behavioral,
            "notes": self.notes,
        }


def certify_nop_patches(patch_records: list, verify_result: Optional[dict] = None) -> PatchCertificate:
    """NOP-only patches are syntactically local; behavioral verify upgrades to proven."""
    notes = ["NOP patches do not change non-nop instruction semantics locally"]
    proven = False
    behavioral = verify_result
    if verify_result and verify_result.get("ok"):
        # Same return code & stdout as expected smoke → weak behavioral certificate
        proven = True
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
        notes=notes,
    )
