from __future__ import annotations

"""Lift linear MBA snippets from Intel asm text and prove simplification."""

import re
from dataclasses import dataclass
from typing import List, Optional

import z3

from argus.mba.simplifier import MBASimplifier, MBA_CATALOG


@dataclass
class AsmMBAHit:
    text: str
    simplified: str
    proved: bool


_EXPR_HINTS = [
    re.compile(r"xor.*,.*\n.*and.*,.*\n.*add", re.I | re.M),
]


def prove_catalog() -> List[dict]:
    s = MBASimplifier(32)
    out = []
    for name, fn in MBA_CATALOG:
        r = s.simplify_binary_expr(fn)
        out.append({"name": name, "simplified": r.simplified, "proved": r.proved})
    return out


def scan_asm_for_mba(asm_text: str) -> List[AsmMBAHit]:
    """Conservative: if block text matches known MBA shape, attach catalog proof."""
    hits: List[AsmMBAHit] = []
    catalog = prove_catalog()
    proved = [c for c in catalog if c["proved"]]
    if "xor" in asm_text.lower() and "and" in asm_text.lower() and "add" in asm_text.lower():
        for c in proved:
            if c["name"] in ("x+y", "x^y"):
                hits.append(AsmMBAHit(asm_text[:120], c["simplified"], True))
                break
    return hits
