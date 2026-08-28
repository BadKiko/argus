from __future__ import annotations

"""Batch patch-plan apply + static byte verify (no GUI / no vendor recipes)."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.ask import Hint, PatchKind, Want, ask
from argus.binary import load_binary
from argus.find_slice import gate_scan, gate_scan_modules
from argus.llm.session import strict_plan_enabled

from argus.prove.certificate import certify_apply_plan, level_from_verify

_BEHAVIOR_DENY = (
    b"go away",
    b"wrong password",
    b"wrong",
    b"access denied",
    b"invalid license",
    b"unregistered",
    b"trial expired",
)


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


def verify_patch_bytes(
    original: str,
    patched: str,
    steps: List[Dict[str, Any]],
    *,
    module_pairs: Optional[List[Tuple[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Static check: each plan step changed bytes in the expected way.
    Does NOT claim GUI 'licensed' — only that patch bytes landed.
    """
    details: List[Dict[str, Any]] = []
    all_ok = True
    if not steps:
        return {
            "kind": "patch_bytes",
            "ok": False,
            "detail": "empty patch_plan",
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
        "kind": "patch_bytes",
        "ok": all_ok,
        "detail": "all plan steps patched" if all_ok else "one or more steps failed verify",
        "steps": details,
    }


def _step_fingerprint(step: Dict[str, Any], default_module: str) -> Optional[Tuple[str, int, str, str]]:
    kind = step.get("kind")
    addr = _parse_addr(step.get("addr"))
    if kind not in ("force_branch", "ret_imm") or addr is None:
        return None
    mod = str(step.get("module") or default_module)
    try:
        mod = str(Path(mod).resolve()) if Path(mod).exists() else mod
    except OSError:
        pass
    if kind == "force_branch":
        polarity = "1" if bool(step.get("taken", False)) else "0"
    else:
        val = step.get("value")
        if val is None:
            val = step.get("ret_guess", 1)
        polarity = str(int(val))
    return (str(kind), int(addr), mod, polarity)


def _plan_fingerprints(plan: List[Dict[str, Any]], default_module: str) -> Set[Tuple[str, int, str, str]]:
    out: Set[Tuple[str, int, str, str]] = set()
    for step in plan:
        fp = _step_fingerprint(step, default_module)
        if fp:
            out.add(fp)
    return out


def _steps_subset_of_plan(
    requested: List[Dict[str, Any]],
    slice_plan: List[Dict[str, Any]],
    default_module: str,
) -> bool:
    if not requested:
        return False
    allow = _plan_fingerprints(slice_plan, default_module)
    if not allow:
        return False
    for step in requested:
        fp = _step_fingerprint(step, default_module)
        if fp is None or fp not in allow:
            return False
    return True


def _behavior_verify_enabled() -> bool:
    return os.environ.get("ARGUS_PATCH_BEHAVIOR", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def verify_patch_behavior(
    patched: str,
    *,
    allow_strings: Optional[List[str]] = None,
    stdin: bytes = b"nope\nnope\n",
    max_bytes: int = 512 * 1024,
) -> Dict[str, Any]:
    """Smoke-run patched binary; fail on denylist strings in stdout."""
    p = Path(patched)
    if not p.is_file():
        return {
            "kind": "patch_behavior",
            "ok": False,
            "detail": "patched file missing",
            "ran": False,
        }
    try:
        if p.stat().st_size > max_bytes:
            return {
                "kind": "patch_behavior",
                "ok": False,
                "detail": "binary too large for behavior smoke",
                "ran": False,
                "skipped": True,
            }
    except OSError as e:
        return {"kind": "patch_behavior", "ok": False, "detail": str(e), "ran": False}

    stdout = b""
    ran = False
    method = ""

    if _behavior_verify_enabled():
        try:
            from argus.concrete.runner import concrete_run, unicorn_available

            if unicorn_available():
                res = concrete_run(str(p), stdin=stdin)
                if res.ok or res.stdout:
                    stdout = res.stdout or b""
                    ran = True
                    method = "unicorn"
        except Exception:
            pass

    if not ran:
        try:
            proc = subprocess.run(
                [str(p)],
                input=stdin,
                capture_output=True,
                timeout=8,
                cwd=str(p.parent),
            )
            stdout = proc.stdout or b""
            ran = True
            method = "subprocess"
        except Exception as e:
            return {
                "kind": "patch_behavior",
                "ok": False,
                "detail": f"behavior run failed: {e}",
                "ran": False,
            }

    low = stdout.lower()
    for deny in _BEHAVIOR_DENY:
        if deny in low:
            preview = stdout[:240].decode("utf-8", errors="replace")
            return {
                "kind": "patch_behavior",
                "ok": False,
                "detail": f"stdout contains deny phrase {deny!r}",
                "stdout_preview": preview,
                "ran": True,
                "method": method,
            }

    allow_ok = True
    if allow_strings:
        allow_ok = any(s.encode() in stdout for s in allow_strings if s)
    preview = stdout[:240].decode("utf-8", errors="replace")
    return {
        "kind": "patch_behavior",
        "ok": bool(allow_ok),
        "detail": "behavior smoke ok" if allow_ok else "stdout missing expected allow strings",
        "stdout_preview": preview,
        "ran": True,
        "method": method,
    }


def _composite_verify(
    bytes_verify: Dict[str, Any],
    behavior_verify: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    behavior = behavior_verify or {}
    behavior_ran = bool(behavior.get("ran"))
    behavior_ok = behavior.get("ok") is True
    bytes_ok = bool(bytes_verify.get("ok"))
    if behavior_ran:
        ok = bytes_ok and behavior_ok
        detail = "bytes+behavior ok" if ok else "behavior or bytes verify failed"
        kind = "patch_composite"
    else:
        ok = bytes_ok
        detail = bytes_verify.get("detail") or ("bytes ok" if ok else "bytes verify failed")
        kind = "patch_bytes"
    out: Dict[str, Any] = {
        "kind": kind,
        "ok": ok,
        "detail": detail,
        "patch_bytes": bytes_verify,
    }
    if behavior_verify is not None:
        out["patch_behavior"] = behavior_verify
    return out


def apply_plan(
    path: str,
    *,
    output: Optional[str] = None,
    steps: Optional[List[Dict[str, Any]]] = None,
    query: Optional[str] = None,
    modules: Optional[List[str]] = None,
    multi: bool = True,
) -> Dict[str, Any]:
    """
    Apply patch_plan steps. Steps may target different modules via step['module'].
    If steps omitted, build plan via multi-module gate_scan when multi=True.
    """
    out = output or (str(path) + ".patched")
    explicit_steps = steps is not None and len(steps or []) > 0
    plan = list(steps or [])
    slice_info: Dict[str, Any] = {}
    plan_source = "empty"

    if multi or modules:
        slice_info = gate_scan_modules(path, modules=modules, query=query)
    else:
        slice_info = gate_scan(path, query)
    slice_plan = list(slice_info.get("patch_plan") or [])

    if explicit_steps:
        if strict_plan_enabled() and not _steps_subset_of_plan(plan, slice_plan, path):
            plan_source = "rejected_model"
            verify = {
                "kind": "patch_bytes",
                "ok": False,
                "detail": "steps not from patch_plan",
                "steps": [],
            }
            return {
                "ok": False,
                "summary": "apply_plan rejected model-invented steps",
                "plan_source": plan_source,
                "slice_plan_len": len(slice_plan),
                "patch_plan": plan,
                "patched_path": None,
                "patched_paths": [],
                "applied": [],
                "verify": verify,
                "next_hint": (
                    "custom steps must match argus_slice patch_plan exactly — "
                    "re-slice or omit steps= for auto-apply"
                ),
                "evidence": {
                    "patch_plan": plan,
                    "slice_plan": slice_plan,
                    "slice": slice_info,
                    "plan_source": plan_source,
                },
            }
        plan_source = "slice" if _steps_subset_of_plan(plan, slice_plan, path) else "model"
    elif not plan:
        plan = slice_plan
        plan_source = "slice" if plan else "empty"

    if not plan:
        return {
            "ok": False,
            "summary": "no patch_plan",
            "plan_source": plan_source,
            "slice_plan_len": len(slice_plan),
            "patch_plan": [],
            "patched_path": None,
            "patched_paths": [],
            "applied": [],
            "verify": {
                "kind": "patch_bytes",
                "ok": False,
                "detail": "empty plan",
                "steps": [],
            },
            "next_hint": slice_info.get("next_hint")
            or "argus_slice returned no patch_plan — incomplete",
            "evidence": {"patch_plan": [], "slice": slice_info, "plan_source": plan_source},
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

    bytes_verify = verify_patch_bytes(path, module_outs.get(path, out), plan, module_pairs=pairs)
    behavior_verify: Optional[Dict[str, Any]] = None
    primary_out = module_outs.get(path, out)
    if bytes_verify.get("ok") and primary_out and Path(primary_out).is_file():
        allow: List[str] = []
        for hit in slice_info.get("string_hits") or []:
            if isinstance(hit, dict):
                s = hit.get("string") or hit.get("text")
                if s:
                    allow.append(str(s))
            elif isinstance(hit, str):
                allow.append(hit)
        behavior_verify = verify_patch_behavior(primary_out, allow_strings=allow or None)
    verify = _composite_verify(bytes_verify, behavior_verify)
    ok = bool(verify.get("ok")) and all(a.get("ok") for a in applied)
    primary_out = module_outs.get(path, out)
    certificate = certify_apply_plan(applied, verify)
    verification_level = level_from_verify(verify).value
    return {
        "ok": ok,
        "summary": (
            f"apply_plan steps={len(applied)}/{len(plan)} modules={len(module_outs)} "
            f"verify={'ok' if verify.get('ok') else 'fail'} plan_source={plan_source}"
        ),
        "plan_source": plan_source,
        "slice_plan_len": len(slice_plan),
        "patch_plan": plan,
        "patched_path": primary_out if applied else None,
        "patched_paths": list(module_outs.values()),
        "applied": applied,
        "verify": verify,
        "certificate": certificate.to_dict(),
        "verification_level": verification_level,
        "next_hint": (
            "patch verify ok — do not claim GUI licensed; rodata strings may remain"
            if ok
            else "patch incomplete — inspect applied[].detail / try argus_discover + slice"
        ),
        "evidence": {
            "patch_plan": plan,
            "applied": applied,
            "verify": verify,
            "certificate": certificate.to_dict(),
            "verification_level": verification_level,
            "modules": list(module_outs.keys()),
            "plan_source": plan_source,
            "slice_plan_len": len(slice_plan),
        },
    }
