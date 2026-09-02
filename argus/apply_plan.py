from __future__ import annotations

"""Batch patch-plan apply + static byte verify (no GUI / no vendor recipes)."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.ask import Hint, PatchKind, Want, ask
from argus.binary import load_binary
from argus.binary.launch_env import launch_env_for
from argus.find_slice import gate_scan, gate_scan_modules
from argus.llm.session import strict_plan_enabled, cached_gate_scan

from argus.prove.certificate import certify_apply_plan, level_from_verify

_BEHAVIOR_DENY = (
    b"go away",
    b"wrong password",
    b"wrong",
    b"access denied",
    b"invalid license",
    b"unregistered",
    b"trial expired",
    b"trial mode",
    b"trial information",
    b"missing or corrupt",
    b"not a valid",
    b"evaluation error",
    b"license error",
    b"error =",
)
_UNICORN_MAX_BYTES = 512 * 1024


def _behavior_max_bytes() -> int:
    raw = os.environ.get("ARGUS_BEHAVIOR_MAX_BYTES", "").strip()
    if raw.isdigit():
        return int(raw)
    return 128 * 1024 * 1024


_APPLY_KINDS = frozenset({"force_branch", "ret_imm", "nop_call", "nop_bytes", "force_flag", "replace_string"})


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


def _hex_to_bytes(raw: str) -> bytes:
    try:
        return bytes.fromhex(raw or "")
    except ValueError:
        return b""


def bytes_match_patch_intent(kind: str, after: bytes, *, taken: bool = False, value: int = 1, size: int = 5) -> bool:
    """True when `after` already looks like the intended patch encoding."""
    if not after:
        return False
    k = (kind or "").strip()
    if k == "force_branch":
        if not taken:
            return after[:2] == b"\x90\x90" or after[:1] == b"\x90"
        return after[0] in (0xEB, 0xE9)
    if k == "ret_imm":
        return len(after) >= 6 and after[0] == 0xB8 and after[5] == 0xC3
    if k in ("nop_call", "nop_bytes"):
        n = max(1, int(size or 5))
        return after[:n] == b"\x90" * n
    if k == "force_flag":
        return len(after) >= 4 and after[0] == 0xC6 and after[3] == 0x01
    return False


def _module_output(src: str, primary_out: str, primary_src: str) -> str:
    """Map source module → output path when primary has a single output name."""
    from argus.patch.deploy import in_place_enabled

    src_p = Path(src).resolve()
    prim_p = Path(primary_src).resolve()
    out_p = Path(primary_out)
    if in_place_enabled():
        return str(src_p)
    if src_p == prim_p:
        return str(out_p)
    parent = out_p.parent
    return str(parent / Path(src).name)


def _is_diagnose_plan(plan: List[Dict[str, Any]], path: str = "") -> bool:
    """Plans from argus_diagnose_failure (verified session steps or diagnose kinds)."""
    from argus.llm.session import get_verified_plan_steps

    verified = get_verified_plan_steps()
    if verified and _steps_subset_of_plan(plan, verified, path):
        return True
    kinds = {str(s.get("kind")) for s in plan}
    if any(s.get("ir") in ("text", "archive") for s in plan):
        return True
    return bool(kinds & {"force_flag", "nop_call", "replace_string"})


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

    # Map module path → (before_image, after_image). Index both ends so in-place
    # pairs (original/backup, work copy) resolve when the step names the work path.
    pair_map: Dict[str, Tuple[str, str]] = {}

    def _index_pair(src: str, dst: str) -> None:
        pair = (src, dst)
        for p in (src, dst):
            try:
                pair_map[str(Path(p).resolve())] = pair
            except OSError:
                pair_map[str(p)] = pair
            pair_map[Path(p).name] = pair

    if module_pairs:
        for src, dst in module_pairs:
            _index_pair(src, dst)
    else:
        _index_pair(original, patched)

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
        if str(step.get("ir") or "") in ("text", "archive") or kind == "replace_string":
            try:
                blob1 = Path(dst_path).read_bytes()
            except OSError as e:
                row["detail"] = f"load failed: {e}"
                all_ok = False
                details.append(row)
                continue
            old = (step.get("old") or "").encode("utf-8", errors="replace")
            new = (step.get("new") or "").encode("utf-8", errors="replace")
            if new and old and len(new) < len(old):
                new = new + b" " * (len(old) - len(new))
            if new and new in blob1:
                row["ok"] = True
                row["before"] = (old[:8].hex() if old else "")
                row["after"] = new[:8].hex()
                row["detail"] = "text bytes applied"
                details.append(row)
                continue
            row["detail"] = "text bytes not found"
            all_ok = False
            details.append(row)
            continue
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
        taken = bool(step.get("taken", False))
        size = int(step.get("size") or 5)
        already = bytes_match_patch_intent(str(kind or ""), after, taken=taken, size=size)
        if before == after and not already:
            row["detail"] = "bytes unchanged"
            all_ok = False
            details.append(row)
            continue
        if before == after and already:
            row["ok"] = True
            row["detail"] = "already matches intended encoding"
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
        elif kind in ("nop_call", "nop_bytes"):
            size = int(step.get("size") or 5)
            ok = after[:size] == b"\x90" * size
            row["ok"] = bool(ok)
            row["detail"] = f"NOP x{size}" if ok else "expected NOP fill"
        elif kind == "force_flag":
            ok = len(after) >= 4 and after[0] == 0xC6 and after[3] == 0x01
            row["ok"] = bool(ok)
            row["detail"] = "mov byte imm 1" if ok else "expected force_flag"
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


def verify_patch_disasm(patched: str, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Capstone preview at each patched site — static check only, no GUI launch."""
    import capstone as cs

    p = Path(patched)
    if not p.is_file() or not steps:
        return {"kind": "patch_disasm", "ok": False, "detail": "missing patched file or empty plan"}
    try:
        img = load_binary(str(p))
    except Exception as e:
        return {"kind": "patch_disasm", "ok": False, "detail": str(e)}
    mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    previews: List[Dict[str, Any]] = []
    for step in steps:
        addr = _parse_addr(step.get("addr"))
        if addr is None:
            continue
        data = img.read_bytes(addr, 16) or b""
        insns = list(md.disasm(data, addr))[:4]
        previews.append({
            "addr": hex(addr),
            "kind": step.get("kind"),
            "disasm": "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns),
        })
    kinds = {str(s.get("kind")) for s in steps}
    coverage_ok = bool(kinds & {"force_branch", "force_flag"}) or "ret_imm" in kinds
    return {
        "kind": "patch_disasm",
        "ok": coverage_ok and bool(previews),
        "detail": f"static disasm {len(previews)} sites",
        "previews": previews,
    }


def _step_fingerprint(step: Dict[str, Any], default_module: str) -> Optional[Tuple[str, int, str, str]]:
    kind = step.get("kind")
    addr = _parse_addr(step.get("addr"))
    if kind not in _APPLY_KINDS or addr is None:
        return None
    mod = str(step.get("module") or default_module)
    try:
        mod = str(Path(mod).resolve()) if Path(mod).exists() else mod
    except OSError:
        pass
    if kind == "force_branch":
        polarity = "1" if bool(step.get("taken", False)) else "0"
    elif kind == "ret_imm":
        val = step.get("value")
        if val is None:
            val = step.get("ret_guess", 1)
        polarity = str(int(val))
    elif kind in ("nop_call", "nop_bytes"):
        polarity = str(int(step.get("size") or 5))
    else:
        polarity = "1"
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
    original: Optional[str] = None,
    require_positive_oracle: bool = False,
    stdin: bytes = b"nope\nnope\n",
    max_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """Smoke-run patched binary; fail on denylist strings in stdout/stderr."""
    p = Path(patched)
    if not p.is_file():
        return {
            "kind": "patch_behavior",
            "ok": False,
            "detail": "patched file missing",
            "ran": False,
        }
    size_limit = max_bytes if max_bytes is not None else _behavior_max_bytes()
    try:
        fsize = p.stat().st_size
    except OSError as e:
        return {"kind": "patch_behavior", "ok": False, "detail": str(e), "ran": False}
    if fsize > size_limit:
        return {
            "kind": "patch_behavior",
            "ok": False,
            "detail": f"binary too large for behavior smoke ({fsize} > {size_limit})",
            "ran": False,
            "skipped": True,
        }

    stdout = b""
    stderr = b""
    ran = False
    method = ""
    timed_out = False

    if _behavior_verify_enabled() and fsize <= _UNICORN_MAX_BYTES:
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

    is_gui = False
    try:
        from argus.patch.safety import _looks_gui_or_heavy
        img_check = load_binary(str(p))
        is_gui = _looks_gui_or_heavy(img_check)
    except Exception:
        pass

    try:
        from argus.behavior import verify_binary_semantic
        s_res = verify_binary_semantic(
            str(p),
            stdin=stdin,
            original_path=original,
            allow_strings=allow_strings,
            require_positive_oracle=require_positive_oracle,
        )
        if s_res.get("ok") is False or s_res.get("windows") or s_res.get("needs_oracle"):
            return {
                "kind": "patch_behavior",
                "ok": bool(s_res.get("ok")),
                "detail": s_res.get("detail") or "semantic verify",
                "ran": True,
                "method": "semantic_inspector",
                "windows": s_res.get("windows"),
                "suggested_action": s_res.get("suggested_action"),
                "needs_oracle": s_res.get("needs_oracle"),
                "oracle_kind": s_res.get("oracle_kind"),
            }
    except Exception:
        pass

    if not ran:
        from argus.binary.launch_env import stage_native_executable

        staged = stage_native_executable(str(p), original=original)
        timeout = 2.0 if is_gui else 8.0
        cwd, env = launch_env_for(staged.path)
        cwd = staged.cwd or cwd
        try:
            proc = subprocess.run(
                [str(staged.path.resolve())],
                input=stdin,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )
            stdout = proc.stdout or b""
            stderr = proc.stderr or b""
            ran = True
            method = "subprocess"
            if is_gui and proc.returncode != 0:
                return {
                    "kind": "patch_behavior",
                    "ok": False,
                    "detail": f"GUI process crashed on startup (returncode {proc.returncode})",
                    "ran": True,
                    "method": method,
                }
        except subprocess.TimeoutExpired as e:
            timed_out = True
            ran = True
            method = "subprocess"
            stdout = getattr(e, "stdout", b"") or b""
            stderr = getattr(e, "stderr", b"") or b""
        except Exception as e:
            return {
                "kind": "patch_behavior",
                "ok": False,
                "detail": f"behavior run failed: {e}",
                "ran": False,
            }
        finally:
            if staged.ephemeral:
                try:
                    staged.path.unlink()
                except OSError:
                    pass

    if timed_out:
        if is_gui:
            return {
                "kind": "patch_behavior",
                "ok": False,
                "detail": "GUI process alive after timeout but goal unproven",
                "ran": True,
                "method": method,
                "gui": True,
                "needs_oracle": True,
            }
        return {
            "kind": "patch_behavior",
            "ok": False,
            "detail": "process still running after 8s (unresponsive CLI?)",
            "ran": True,
            "method": method,
            "timed_out": True,
        }

    combined = stdout + b"\n" + stderr
    low = combined.lower()
    for deny in _BEHAVIOR_DENY:
        if deny in low:
            preview = combined[:240].decode("utf-8", errors="replace")
            return {
                "kind": "patch_behavior",
                "ok": False,
                "detail": f"output contains deny phrase {deny!r}",
                "stdout_preview": preview,
                "ran": True,
                "method": method,
            }

    allow_ok = True
    if allow_strings:
        allow_ok = any(s.encode() in combined for s in allow_strings if s)
    elif require_positive_oracle:
        allow_ok = False
    preview = combined[:240].decode("utf-8", errors="replace")
    return {
        "kind": "patch_behavior",
        "ok": bool(allow_ok),
        "detail": "behavior smoke ok" if allow_ok else "output missing expected allow strings",
        "stdout_preview": preview,
        "ran": True,
        "method": method,
        "needs_oracle": require_positive_oracle and not allow_ok,
    }


def _composite_verify(
    bytes_verify: Dict[str, Any],
    behavior_verify: Optional[Dict[str, Any]],
    *,
    require_behavior: bool = False,
    require_positive_oracle: bool = False,
) -> Dict[str, Any]:
    behavior = behavior_verify or {}
    behavior_ran = bool(behavior.get("ran"))
    behavior_ok = behavior.get("ok") is True
    behavior_skipped = bool(behavior.get("skipped"))
    needs_oracle = bool(behavior.get("needs_oracle"))
    bytes_ok = bool(bytes_verify.get("ok"))
    if behavior_ran:
        if needs_oracle and bytes_ok and not require_positive_oracle:
            ok = True
            detail = "bytes ok — GUI needs argus_gui_oracle (reject_texts from diagnose)"
            kind = "patch_composite"
        else:
            ok = bytes_ok and behavior_ok
            if require_positive_oracle and (needs_oracle or not behavior_ok):
                ok = False
            detail = "bytes+behavior ok" if ok else "behavior or bytes verify failed"
            kind = "patch_composite"
    elif behavior_skipped and require_behavior:
        ok = False
        detail = behavior.get("detail") or "behavior verify skipped — insufficient for gate transform"
        kind = "patch_composite"
    elif require_behavior and bytes_ok:
        ok = False
        detail = "bytes ok but behavior verify did not run"
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
    auto_slice: bool = False,
) -> Dict[str, Any]:
    """
    Apply patch_plan steps. Steps may target different modules via step['module'].
    steps= is required unless auto_slice=True (legacy/scripts only).
    """
    from argus.llm.workspace import default_patch_output

    out = output or default_patch_output(path)
    explicit_steps = steps is not None and len(steps or []) > 0
    plan = list(steps or [])
    slice_info: Dict[str, Any] = {}
    plan_source = "empty"

    if not explicit_steps and not auto_slice:
        return {
            "ok": False,
            "summary": "apply_plan requires explicit steps= from slice/diagnose evidence",
            "plan_source": "missing_steps",
            "slice_plan_len": 0,
            "patch_plan": [],
            "patched_path": None,
            "patched_paths": [],
            "applied": [],
            "verify": {
                "kind": "patch_bytes",
                "ok": False,
                "detail": "missing steps",
                "steps": [],
            },
            "next_hint": "call argus_slice or argus_diagnose_failure first, then apply_plan(steps=[...])",
            "evidence": {"plan_source": "missing_steps"},
        }

    use_multi = bool(multi or modules)
    cached = cached_gate_scan(path, query=query, modules=modules, multi=use_multi) if use_multi else None
    slice_from_cache = cached is not None
    if cached is not None:
        slice_info = cached
    elif use_multi and auto_slice:
        slice_info = gate_scan_modules(path, modules=modules, query=query)
    elif auto_slice:
        slice_info = gate_scan(path, query)
    from argus.llm.session import get_verified_plan_steps, get_session
    slice_plan = list(slice_info.get("patch_plan") or [])
    sess = get_session()
    if sess.last_slice_patch_plan:
        slice_plan = list(sess.last_slice_patch_plan) + slice_plan
    slice_plan = slice_plan + get_verified_plan_steps()

    from argus.payload import host_apply_refused

    if plan:
        refuse = host_apply_refused(path, plan)
        if refuse:
            return {
                "ok": False,
                "summary": refuse,
                "plan_source": "host_runtime_refuse",
                "slice_plan_len": len(slice_plan),
                "patch_plan": plan,
                "patched_path": None,
                "patched_paths": [],
                "applied": [],
                "verify": {
                    "kind": "patch_bytes",
                    "ok": False,
                    "detail": "host_runtime refuse",
                    "steps": [],
                },
                "next_hint": refuse,
                "evidence": {"plan_source": "host_runtime_refuse", "error": "host_runtime_refuse"},
            }

    if explicit_steps:
        from argus.llm.session import text_replace_grounded

        if text_replace_grounded(plan):
            from argus.llm.session import enrich_text_replace_steps

            plan = enrich_text_replace_steps(plan)
            plan_source = "text_window"
        elif strict_plan_enabled() and not _steps_subset_of_plan(plan, slice_plan, path):
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
                    "re-slice or pass steps= from diagnose_failure corrective_patch"
                ),
                "evidence": {
                    "patch_plan": plan,
                    "slice_plan": slice_plan,
                    "slice": slice_info,
                    "plan_source": plan_source,
                },
            }
        elif _is_diagnose_plan(plan, path):
            plan_source = "diagnose"
        elif _steps_subset_of_plan(plan, slice_plan, path):
            plan_source = "slice"
        else:
            plan_source = "model"
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

    from argus.payload import host_apply_refused

    refuse = host_apply_refused(path, plan)
    if refuse:
        return {
            "ok": False,
            "summary": refuse,
            "plan_source": plan_source,
            "slice_plan_len": len(slice_plan),
            "patch_plan": plan,
            "patched_path": None,
            "patched_paths": [],
            "applied": [],
            "verify": {
                "kind": "patch_bytes",
                "ok": False,
                "detail": "host_runtime refuse",
                "steps": [],
            },
            "next_hint": refuse,
            "evidence": {"plan_source": plan_source, "error": "host_runtime_refuse"},
        }

    # Group steps by module
    for s in plan:
        s.setdefault("module", path)

    module_outs: Dict[str, str] = {}
    pairs: List[Tuple[str, str]] = []
    from argus.patch.deploy import ensure_original_backup, in_place_enabled

    for s in plan:
        mod = str(s.get("module") or path)
        if mod not in module_outs:
            dst = _module_output(mod, out, path)
            src_p = Path(mod)
            dst_p = Path(dst)
            if in_place_enabled():
                backup = ensure_original_backup(src_p)
                work = str(src_p.resolve())
                module_outs[mod] = work
                # Verify against pristine backup, not the already-patched work copy.
                pairs.append((str(backup), work))
                continue
            if src_p.resolve() != dst_p.resolve():
                from argus.binary.file_io import copy_binary_resilient

                copy_binary_resilient(src_p, dst_p, fallback_src=path)
            else:
                dst = default_patch_output(str(src_p))
                from argus.binary.file_io import copy_binary_resilient

                copy_binary_resilient(src_p, dst, fallback_src=path)
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
        is_text = str(step.get("ir") or "") in ("text", "archive") or kind == "replace_string"
        if is_text:
            from argus.payload import apply_text_step

            try:
                blob = Path(dst).read_bytes()
                off = addr if addr is not None else 0
                row["before"] = blob[off : off + 8].hex() if off < len(blob) else ""
            except OSError:
                row["before"] = ""
            ok_step, step_detail = apply_text_step(dst, step)
            try:
                blob = Path(dst).read_bytes()
                off = addr if addr is not None else 0
                row["after"] = blob[off : off + 8].hex() if off < len(blob) else ""
            except OSError:
                row["after"] = ""
            row["ok"] = bool(ok_step)
            row["detail"] = step_detail
            applied.append(row)
            if not ok_step:
                break
            continue
        if addr is None or kind not in _APPLY_KINDS:
            row["detail"] = "unsupported step"
            applied.append(row)
            break
        before = _read_hex(dst, addr, 8)
        row["before"] = before
        ok_step = False
        step_detail = ""
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
            ok_step = bool(r.ok)
            step_detail = r.answer or (r.notes[0] if r.notes else "")
        elif kind == "ret_imm":
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
            ok_step = bool(r.ok)
            step_detail = r.answer or (r.notes[0] if r.notes else "")
        elif kind in ("nop_call", "nop_bytes"):
            from argus.patch.intents import nop_bytes

            size = int(step.get("size") or 5)
            ok_step, cert = nop_bytes(dst, addr, size, dst)
            step_detail = (cert.get("notes") or [""])[0]
        elif kind == "force_flag":
            from argus.patch.intents import force_flag

            ok_step, cert = force_flag(dst, addr, dst)
            step_detail = (cert.get("notes") or [""])[0]
        else:
            row["detail"] = "unsupported step"
            applied.append(row)
            break
        after = _read_hex(dst, addr, 8)
        row["after"] = after
        already = bytes_match_patch_intent(
            str(kind or ""),
            _hex_to_bytes(after),
            taken=bool(step.get("taken", False)),
            value=int(step.get("value") if step.get("value") is not None else 1),
            size=int(step.get("size") or 5),
        )
        row["ok"] = bool(ok_step) and (before != after or already)
        if row["ok"] and before == after and already:
            step_detail = (step_detail + " — already applied").strip(" —")
        row["detail"] = step_detail
        applied.append(row)
        if not ok_step:
            break

    bytes_verify = verify_patch_bytes(path, module_outs.get(path, out), plan, module_pairs=pairs)
    behavior_verify: Optional[Dict[str, Any]] = None
    disasm_verify: Optional[Dict[str, Any]] = None
    primary_out = module_outs.get(path, out)
    text_only = bool(plan) and all(
        str(s.get("ir") or "") in ("text", "archive") or s.get("kind") == "replace_string"
        for s in plan
    )
    if bytes_verify.get("ok") and primary_out and Path(primary_out).is_file() and not text_only:
        if plan_source == "diagnose":
            disasm_verify = verify_patch_disasm(primary_out, plan)
        else:
            allow: List[str] = []
            for hit in slice_info.get("string_hits") or []:
                if isinstance(hit, dict):
                    s = hit.get("string") or hit.get("text")
                    if s:
                        allow.append(str(s))
                elif isinstance(hit, str):
                    allow.append(hit)
            behavior_verify = verify_patch_behavior(
                primary_out,
                allow_strings=allow or None,
                original=path,
                require_positive_oracle=plan_source == "slice",
            )
    require_behavior = bool(plan) and plan_source == "slice" and not text_only
    verify = _composite_verify(
        bytes_verify,
        behavior_verify,
        require_behavior=require_behavior,
        require_positive_oracle=require_behavior,
    )
    if plan_source == "diagnose" and bytes_verify.get("ok") and disasm_verify:
        verify["patch_disasm"] = disasm_verify
        if disasm_verify.get("ok"):
            verify["ok"] = True
            verify["kind"] = "patch_composite"
            verify["detail"] = "bytes+static disasm ok (no GUI input)"
    ok = bool(verify.get("ok")) and all(a.get("ok") for a in applied)
    primary_out = module_outs.get(path, out)
    deploy_info: Optional[Dict[str, Any]] = None
    if ok and primary_out and Path(primary_out).is_file():
        from argus.patch.deploy import deploy_patched_modules, in_place_enabled

        if in_place_enabled():
            deploy_info = deploy_patched_modules(module_outs, primary=path)
        else:
            p_out = Path(primary_out)
            if p_out.parent.name == ".argus-work":
                deploy_info = deploy_patched_modules(module_outs, primary=path)
                if deploy_info.get("ok"):
                    native_out = p_out.parent.parent / p_out.name
                    if native_out.is_file():
                        primary_out = str(native_out)
                        module_outs[path] = primary_out
            else:
                try:
                    shutil.copy2(primary_out, Path(path).resolve())
                    primary_out = str(Path(path).resolve())
                    module_outs[path] = primary_out
                except Exception:
                    pass

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
            "patch verify ok (static disasm) — launch app manually to confirm"
            if ok and plan_source == "diagnose"
            else (
                "patch verify ok (bytes+behavior) — user may confirm GUI manually"
                if ok
                else "patch incomplete — inspect verify / try argus_diagnose_failure"
            )
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
            "deploy": deploy_info,
        },
    }
