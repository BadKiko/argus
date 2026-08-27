from __future__ import annotations

"""Batch unlock apply + static byte verify (no GUI / no vendor recipes)."""

import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from argus.ask import Hint, PatchKind, Want, ask
from argus.binary import load_binary
from argus.find_slice import license_slice


def _parse_addr(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    try:
        return int(str(raw), 0)
    except (TypeError, ValueError):
        return None


def _read_hex(path: str, addr: int, n: int = 8) -> str:
    try:
        img = load_binary(path)
        raw = img.read_bytes(addr, n) or b""
        return raw.hex()
    except Exception:
        return ""


def verify_unlock_bytes(
    original: str,
    patched: str,
    steps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Static check: each plan step changed bytes in the expected way.
    Does NOT claim GUI 'licensed' — only that unlock patches landed.
    """
    details: List[Dict[str, Any]] = []
    all_ok = True
    if not steps:
        return {
            "kind": "unlock_bytes",
            "ok": False,
            "detail": "empty unlock_plan",
            "steps": [],
        }
    try:
        img0 = load_binary(original)
        img1 = load_binary(patched)
    except Exception as e:
        return {
            "kind": "unlock_bytes",
            "ok": False,
            "detail": f"load failed: {e}",
            "steps": [],
        }

    for step in steps:
        kind = step.get("kind")
        addr = _parse_addr(step.get("addr"))
        row: Dict[str, Any] = {
            "kind": kind,
            "addr": step.get("addr"),
            "ok": False,
        }
        if addr is None:
            row["detail"] = "bad addr"
            all_ok = False
            details.append(row)
            continue
        before = img0.read_bytes(addr, 8) or b""
        after = img1.read_bytes(addr, 8) or b""
        row["before"] = before.hex()
        row["after"] = after.hex()
        if before == after:
            row["detail"] = "bytes unchanged"
            all_ok = False
            details.append(row)
            continue
        if kind == "ret_imm":
            # mov eax, imm32; ret  → b8 xx xx xx xx c3
            ok = len(after) >= 6 and after[0] == 0xB8 and after[5] == 0xC3
            row["ok"] = bool(ok)
            row["detail"] = "ret_imm pattern" if ok else "expected mov eax,imm; ret"
        elif kind == "force_branch":
            taken = bool(step.get("taken", False))
            if not taken:
                # NOP sled (at least 2 bytes of 0x90)
                ok = after[:2] == b"\x90\x90" or after[0:1] == b"\x90"
                row["ok"] = bool(ok)
                row["detail"] = "force not-taken NOPs" if ok else "expected NOP"
            else:
                # short jmp eb or near e9
                ok = after[0] in (0xEB, 0xE9)
                row["ok"] = bool(ok)
                row["detail"] = "force taken jmp" if ok else "expected jmp"
        else:
            row["ok"] = before != after
            row["detail"] = "bytes changed"
        if not row["ok"]:
            all_ok = False
        details.append(row)

    return {
        "kind": "unlock_bytes",
        "ok": all_ok,
        "detail": "all plan steps patched" if all_ok else "one or more steps failed verify",
        "steps": details,
    }


def unlock_apply(
    path: str,
    *,
    output: Optional[str] = None,
    steps: Optional[List[Dict[str, Any]]] = None,
    query: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Apply unlock_plan steps into one output binary.
    If steps omitted, build plan via license_slice.
    """
    out = output or (str(path) + ".patched")
    plan = list(steps or [])
    slice_info: Dict[str, Any] = {}
    if not plan:
        slice_info = license_slice(path, query)
        plan = list(slice_info.get("unlock_plan") or [])
    if not plan:
        return {
            "ok": False,
            "summary": "no unlock_plan",
            "unlock_plan": [],
            "patched_path": None,
            "applied": [],
            "verify": {
                "kind": "unlock_bytes",
                "ok": False,
                "detail": "empty plan",
                "steps": [],
            },
            "next_hint": slice_info.get("next_hint")
            or "argus_slice returned no unlock_plan — incomplete",
            "evidence": {"unlock_plan": [], "slice": slice_info},
        }

    # Fresh copy from source
    src = Path(path)
    dst = Path(out)
    if src.resolve() != dst.resolve():
        shutil.copy(src, dst)
    else:
        # in-place: copy to temp then replace — keep it simple: write alongside
        dst = Path(str(path) + ".patched")
        shutil.copy(src, dst)
        out = str(dst)

    applied: List[Dict[str, Any]] = []
    cur = out
    for step in plan:
        kind = step.get("kind")
        addr = _parse_addr(step.get("addr"))
        row: Dict[str, Any] = {
            "kind": kind,
            "addr": step.get("addr"),
            "ok": False,
        }
        if addr is None or kind not in ("force_branch", "ret_imm"):
            row["detail"] = "unsupported step"
            applied.append(row)
            break
        before = _read_hex(cur, addr, 8)
        row["before"] = before
        if kind == "force_branch":
            r = ask(
                cur,
                Hint(
                    want=Want.PATCH,
                    patch_kind=PatchKind.FORCE_BRANCH,
                    branch_addr=addr,
                    patch_addr=addr,
                    force_taken=bool(step.get("taken", False)),
                    output=out,
                ),
            )
        else:
            r = ask(
                cur,
                Hint(
                    want=Want.PATCH,
                    patch_kind=PatchKind.RET_IMM,
                    patch_addr=addr,
                    ret_value=int(step.get("value") if step.get("value") is not None else 1),
                    output=out,
                ),
            )
        after = _read_hex(out, addr, 8)
        row["after"] = after
        row["ok"] = bool(r.ok) and before != after
        row["detail"] = r.answer or (r.notes[0] if r.notes else "")
        applied.append(row)
        if not r.ok:
            break
        cur = out

    verify = verify_unlock_bytes(str(path), out, plan)
    # If we stopped early, verify will fail — ok
    ok = bool(verify.get("ok")) and all(a.get("ok") for a in applied)
    return {
        "ok": ok,
        "summary": (
            f"unlock_apply steps={len(applied)}/{len(plan)} "
            f"verify={'ok' if verify.get('ok') else 'fail'}"
        ),
        "unlock_plan": plan,
        "patched_path": out if applied else None,
        "applied": applied,
        "verify": verify,
        "next_hint": (
            "unlock_bytes verify ok — do not claim GUI licensed; Unregistered may remain in rodata"
            if ok
            else "unlock incomplete — inspect applied[].detail / try argus_slice with another query"
        ),
        "evidence": {
            "unlock_plan": plan,
            "applied": applied,
            "verify": verify,
        },
    }
