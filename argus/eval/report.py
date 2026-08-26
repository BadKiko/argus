from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ArgusReport:
    binary: str
    fmt: str
    entry: str
    functions: List[str] = field(default_factory=list)
    prune: Optional[Dict[str, Any]] = None
    certificate: Optional[Dict[str, Any]] = None
    cff: Optional[Dict[str, Any]] = None
    solve: Optional[Dict[str, Any]] = None
    patches: List[Dict[str, Any]] = field(default_factory=list)
    patch_certificate: Optional[Dict[str, Any]] = None
    notes: List[str] = field(default_factory=list)
    thesis: str = "ML proposes, mathematics proves, patch only with a certificate"

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)
