from __future__ import annotations

"""Batch unlock apply + static byte verify (no GUI / no vendor recipes)."""

import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from argus.ask import Hint, PatchKind, Want, ask
from argus.binary import load_binary
from argus.find_slice import license_slice, license_slice_modules


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


def _module_output(src: str, primary_out: str, primary_src: str) -> str:
    """Map source module → output path when primary has a single output name."""
    src_p = Path(src).resolve()
    prim_p = Path(primary_src).resolve()
    out_p = Path(primary_out)
    if src_p == prim_p:
        return str(out_p)
    # sibling: same directory as primary output, name + -patch / .patched
    parent = out_p.parent
    stem = Path(src).name
    return str(parent / f"{stem}-patch")


def verify_unlock_bytes(
    original: str,
    patched: str,
    steps: List[Dict[str, Any]],
    *,
    module_pairs: Optional[List[Tuple[str, str]]] = None,
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

    # Map module src → patched path
    pair_map: Dict[str, Tuple[str, str]] = {}
    if module_pairs:
        for src, dst in module_pairs:
            pair_map[str(Path(src).resolve())] = (src, dst)
    else:
        pair_map[str(Path(original).resolve())] = (original, patched)

    for step in steps:
        kind = step.get("kind")
        addr = _parse_addr(step.get("addr"))
        mod = step.get("module") or original
        row: Dict[str, Any] = {
            "kind": kind,
            "addr": step.get("addr"),
            "module": mod,
            "ok": False,
        }
        if addr is None:
            row["detail"] = "bad addr"
            all_ok = False
            details.append(row)
            continue
        key = str(Path(mod).resolve()) if Path(mod).exists() else str(mod)
        pair = pair_map.get(key)
        if not pair:
            # try basename match
            for k, v in pair_map.items():
                if Path(k).name == Path(mod).name:
                    pair = v
                    break
        if not pair:
            pair = (original, patched)
        src_path, dst_path = pair
        try:
            img0 = load_binary(src_path)
            img1 = load_binary(dst_path)
        except Exception as e:
            row["detail"] = f"load failed: {e}"
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
            ok = len(after) >= 6 and after[0] == 0xB8 and after[5] == 0xC3
            row["ok"] = bool(ok)
            row["detail"] = "ret_imm pattern" if ok else "expected mov eax,imm; ret"
        elif kind == "force_branch":
            taken = bool(step.get("taken", False))
            if not taken:
                ok = after[:2] == b"\x90\x90" or after[0:1] == b"\x90"
                row["ok"] = bool(ok)
                row["detail"] = "force not-taken NOPs" if ok else "expected NOP"
            else:
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
    modules: Optional[List[str]] = None,
    multi: bool = True,
) -> Dict[str, Any]:
    """
    Apply unlock_plan steps. Steps may target different modules via step['module'].
    If steps omitted, build plan via multi-module license_slice when multi=True.
    """
    out = output or (str(path) + ".patched")
    plan = list(steps or [])
    slice_info: Dict[str, Any] = {}
    if not plan:
        if multi or modules:
            slice_info = license_slice_modules(path, modules=modules, query=query)
        else:
            slice_info = license_slice(path, query)
        plan = list(slice_info.get("unlock_plan") or [])
    if not plan:
        return {
            "ok": False,
            "summary": "no unlock_plan",
            "unlock_plan": [],
            "patched_path": None,
            "patched_paths": [],
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

    # Group steps by module
    for s in plan:
        s.setdefault("module", path)

    module_outs: Dict[str, str] = {}
    pairs: List[Tuple[str, str]] = []
    for s in plan:
        mod = str(s.get("module") or path)
        if mod not in module_outs:
            dst = _module_output(mod, out, path)
            src_p = Path(mod)
            dst_p = Path(dst)
            if src_p.resolve() != dst_p.resolve():
                shutil.copy(src_p, dst_p)
            else:
                dst = str(src_p) + ".patched"
                shutil.copy(src_p, dst)
            try:
                Path(dst).chmod(src_p.stat().st_mode)
            except OSError:
                pass
            module_outs[mod] = dst
            pairs.append((mod, dst))

    applied: List[Dict[str, Any]] = []
    for step in plan:
        kind = step.get("kind")
        addr = _parse_addr(step.get("addr"))
        mod = str(step.get("module") or path)
        dst = module_outs[mod]
        row: Dict[str, Any] = {
            "kind": kind,
            "addr": step.get("addr"),
            "module": mod,
            "ok": False,
        }
        if addr is None or kind not in ("force_branch", "ret_imm"):
            row["detail"] = "unsupported step"
            applied.append(row)
            break
        before = _read_hex(dst, addr, 8)
        row["before"] = before
        if kind == "force_branch":
            r = ask(
                dst,
                Hint(
                    want=Want.PATCH,
                    patch_kind=PatchKind.FORCE_BRANCH,
                    branch_addr=addr,
                    patch_addr=addr,
                    force_taken=bool(step.get("taken", False)),
                    output=dst,
                ),
            )
        else:
            r = ask(
                dst,
                Hint(
                    want=Want.PATCH,
                    patch_kind=PatchKind.RET_IMM,
                    patch_addr=addr,
                    ret_value=int(step.get("value") if step.get("value") is not None else 1),
                    output=dst,
                ),
            )
        after = _read_hex(dst, addr, 8)
        row["after"] = after
        row["ok"] = bool(r.ok) and before != after
        row["detail"] = r.answer or (r.notes[0] if r.notes else "")
        applied.append(row)
        if not r.ok:
            break

    verify = verify_unlock_bytes(path, module_outs.get(path, out), plan, module_pairs=pairs)
    ok = bool(verify.get("ok")) and all(a.get("ok") for a in applied)
    primary_out = module_outs.get(path, out)
    return {
        "ok": ok,
        "summary": (
            f"unlock_apply steps={len(applied)}/{len(plan)} modules={len(module_outs)} "
            f"verify={'ok' if verify.get('ok') else 'fail'}"
        ),
        "unlock_plan": plan,
        "patched_path": primary_out if applied else None,
        "patched_paths": list(module_outs.values()),
        "applied": applied,
        "verify": verify,
        "next_hint": (
            "unlock_bytes verify ok — do not claim GUI licensed; Unregistered may remain in rodata"
            if ok
            else "unlock incomplete — inspect applied[].detail / try argus_discover + slice"
        ),
        "evidence": {
            "unlock_plan": plan,
            "applied": applied,
            "verify": verify,
            "modules": list(module_outs.keys()),
        },
    }
