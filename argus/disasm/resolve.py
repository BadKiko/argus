from __future__ import annotations

"""Resolve a lift/read target on named or stripped binaries (no vendor recipes)."""

from dataclasses import dataclass
from typing import Optional, Tuple

from argus.binary.image import BinaryImage
from argus.disasm.recovery import function_covering, recover_functions


@dataclass
class LiftTarget:
    va: int
    label: str
    reason: str


def resolve_lift_target(
    img: BinaryImage,
    *,
    function: Optional[str] = None,
    entry: Optional[int] = None,
    query: Optional[str] = None,
) -> LiftTarget:
    """
    Order:
      1) explicit entry VA
      2) query string → first string hit → xref → covering function
      3) function name / 0x… / sub_…
      4) recovered function covering img.entry
    Never picks 'largest symbol'. Query beats a bare picked symbol name so
    stripped `--query` is not overridden by default `main`.
    """
    if entry is not None:
        return _from_va(img, int(entry), reason="explicit_entry")

    if query and query.strip():
        hit = _resolve_via_string(img, query.strip())
        if hit is not None:
            return hit

    if function:
        fn = function.strip()
        if fn in img.symbols and img.symbols[fn].addr:
            addr = img.symbols[fn].addr
            return LiftTarget(va=addr, label=fn, reason="symbol")
        if fn.startswith("0x") or fn.startswith("0X") or (fn[:1].isdigit() and "x" in fn.lower()):
            try:
                return _from_va(img, int(fn, 0), reason="function_hex")
            except ValueError:
                pass
        if fn.startswith("sub_"):
            try:
                return _from_va(img, int(fn[4:], 16), reason="sub_label")
            except ValueError:
                pass
        try:
            if all(c in "0123456789abcdefABCDEF" for c in fn) and len(fn) >= 4:
                return _from_va(img, int(fn, 16), reason="function_hex")
        except ValueError:
            pass

    return _from_va(img, img.entry, reason="program_entry")


def _from_va(img: BinaryImage, va: int, *, reason: str) -> LiftTarget:
    b = function_covering(img, va)
    if b and b.start != va:
        return LiftTarget(va=b.start, label=b.name, reason=f"{reason}+covering")
    if b:
        return LiftTarget(va=b.start, label=b.name, reason=f"{reason}+{b.source}")
    # named symbol at exact addr?
    for name, sym in img.symbols.items():
        if sym.addr == va and sym.is_function:
            return LiftTarget(va=va, label=name, reason=f"{reason}+symbol")
    return LiftTarget(va=va, label=f"sub_{va:x}", reason=reason)


def _resolve_via_string(img: BinaryImage, query: str) -> Optional[LiftTarget]:
    needle = query.encode("utf-8", errors="replace")
    addrs = img.find_string(needle)
    if not addrs and len(query) >= 4:
        # try latin1 / shorter token
        addrs = img.find_string(query.encode("latin1", errors="replace"))
    if not addrs:
        return None

    str_va = addrs[0]
    # Prefer code xref → covering function
    try:
        from argus.find import find_string_xrefs

        xrefs = find_string_xrefs(img, str_va, max_hits=8)
    except Exception:
        xrefs = []

    if xrefs:
        xref_va = int(xrefs[0]["addr"], 0)
        b = function_covering(img, xref_va)
        if b:
            return LiftTarget(
                va=b.start,
                label=b.name,
                reason=f"string_xref@{hex(str_va)}→{hex(xref_va)}",
            )
        return LiftTarget(
            va=xref_va,
            label=f"sub_{xref_va:x}",
            reason=f"string_xref@{hex(str_va)}",
        )

    # No xref: still return covering of nothing useful — fall through
    # Use string VA only as last resort for data (not code) — skip
    return None
