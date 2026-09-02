"""Argus Pre-Flight Patch Sandbox.

Tests proposed binary patches in an isolated scratch environment before modifying
the main workspace binary. Catches crashes (0xC0000005, SIGSEGV, illegal instructions)
in milliseconds without corrupting the user's working binary.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from argus.behavior import verify_binary_semantic
from argus.binary.file_io import copy_binary_resilient, release_binary_lock


def _apply_step_direct(path: str, step: Dict[str, Any]) -> bool:
    try:
        import argus.patch.intents as pi
        from argus.apply_plan import bytes_match_patch_intent
        from argus.binary import load_binary

        kind = step.get("kind")
        raw_addr = step.get("addr")
        if not raw_addr:
            return False
        addr = (
            int(raw_addr, 16)
            if isinstance(raw_addr, str) and raw_addr.startswith("0x")
            else int(raw_addr)
        )
        taken = bool(step.get("taken", False))
        size = int(step.get("size") or (5 if kind in ("nop_call", "nop_bytes", "nop") else 2))
        try:
            cur = load_binary(path).read_bytes(addr, 16) or b""
        except Exception:
            cur = b""
        if bytes_match_patch_intent(str(kind or ""), cur, taken=taken, size=size):
            return True

        if kind == "ret_imm":
            val = int(step.get("value", 1))
            ok, _ = pi.ret_imm(path, fn_addr=addr, value=val, output=path)
            return bool(ok)
        elif kind == "force_branch":
            ok, _ = pi.force_branch(path, addr=addr, taken=taken, output=path)
            return bool(ok)
        elif kind in ("nop", "nop_bytes", "nop_call"):
            size = int(step.get("size", 5 if kind == "nop_call" else 2))
            from argus.patch import Patcher

            patcher = Patcher.from_path(path)
            ok = patcher.nop(addr, size)
            if ok:
                patcher.save(path)
            return bool(ok)
        elif kind == "force_flag":
            ok, _ = pi.force_flag(path, addr=addr, output=path)
            return bool(ok)
        return False
    except Exception:
        return False


def _sandbox_failure_detail(
    step: Dict[str, Any],
    *,
    primary: str,
    module: str,
) -> str:
    kind = step.get("kind")
    addr = step.get("addr")
    mod_name = Path(module).name
    prim_name = Path(primary).name
    if module != primary:
        return (
            f"Failed to apply {kind} @ {addr} on linked module {mod_name} "
            f"(primary={prim_name}). Multi-module plan: steps patch linked SO/DLL — "
            f"not invalid plan; sandbox applies each module copy separately."
        )
    return (
        f"Failed to apply {kind} @ {addr} on {mod_name}. "
        f"Check disasm boundaries / taken polarity before freestyle patch."
    )


def test_patch_in_sandbox(
    binary: str,
    patch_steps: List[Dict[str, Any]],
    *,
    stdin: bytes = b"test_sandbox_input\n",
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """Apply patch steps to isolated copies and verify process safety.

    Supports cross-module patch_plan steps (step['module'] != primary binary).
    """
    src = Path(binary)
    if not src.is_file():
        return {"safe": False, "detail": f"Source binary missing: {binary}"}

    try:
        from argus.patch.gui_oracle import close_process

        close_process(src.name)
        release_binary_lock(src)
    except Exception:
        pass

    primary = str(src.resolve())
    orig_fallback = primary
    try:
        from argus.llm.session import get_session

        sess = get_session()
        if sess.original_binary and Path(sess.original_binary).is_file():
            orig_fallback = sess.original_binary
    except Exception:
        pass

    modules: List[str] = []
    seen_mods: Set[str] = set()
    for step in patch_steps:
        mod = str(step.get("module") or primary)
        if mod not in seen_mods:
            seen_mods.add(mod)
            modules.append(mod)
    if primary not in seen_mods:
        modules.insert(0, primary)

    scratch_dir = Path(tempfile.mkdtemp(prefix="argus-sandbox-"))
    module_scratch: Dict[str, str] = {}
    try:
        for mod in modules:
            mod_p = Path(mod)
            if not mod_p.is_file():
                return {
                    "safe": False,
                    "detail": f"Module missing for sandbox preflight: {mod_p.name}",
                    "module": mod,
                }
            scratch_path = str(scratch_dir / mod_p.name)
            copy_binary_resilient(mod_p, scratch_path, fallback_src=orig_fallback)
            module_scratch[mod] = scratch_path

        primary_scratch = module_scratch.get(primary)
        if not primary_scratch:
            primary_scratch = str(scratch_dir / src.name)
            copy_binary_resilient(src, primary_scratch, fallback_src=orig_fallback)
            module_scratch[primary] = primary_scratch

        for step in patch_steps:
            mod = str(step.get("module") or primary)
            scratch_path = module_scratch.get(mod)
            if not scratch_path:
                return {
                    "safe": False,
                    "detail": f"No scratch copy for module {Path(mod).name}",
                    "module": mod,
                }
            if str(step.get("ir") or "") in ("text", "archive") or step.get("kind") == "replace_string":
                from argus.payload import apply_text_step

                ok_t, detail_t = apply_text_step(scratch_path, step)
                if not ok_t:
                    return {
                        "safe": False,
                        "detail": f"text sandbox apply failed: {detail_t}",
                        "step": step,
                        "module": mod,
                    }
                continue
            if not _apply_step_direct(scratch_path, step):
                return {
                    "safe": False,
                    "detail": _sandbox_failure_detail(step, primary=primary, module=mod),
                    "scratch_applied": False,
                    "module": mod,
                    "step": {"kind": step.get("kind"), "addr": step.get("addr")},
                }

        text_only = bool(patch_steps) and all(
            str(s.get("ir") or "") in ("text", "archive") or s.get("kind") == "replace_string"
            for s in patch_steps
        )
        if text_only:
            return {
                "safe": True,
                "detail": "text/archive payload splice ok (no native smoke)",
                "scratch_applied": True,
            }

        from argus.binary.launch_env import stage_native_executable

        staged = stage_native_executable(primary_scratch, original=orig_fallback)
        verify_path = str(staged.path)
        launch_env = os.environ.copy()
        ld_parts = [str(scratch_dir), str(staged.path.parent)]
        prev_ld = launch_env.get("LD_LIBRARY_PATH", "")
        if prev_ld:
            ld_parts.append(prev_ld)
        launch_env["LD_LIBRARY_PATH"] = ":".join(dict.fromkeys(x for x in ld_parts if x))

        v_res = verify_binary_semantic(
            verify_path,
            original_path=orig_fallback,
            stdin=stdin,
            timeout=timeout,
        )

        release_binary_lock(staged.path)
        for sp in module_scratch.values():
            release_binary_lock(sp)

        if staged.ephemeral and staged.path.is_file():
            try:
                staged.path.unlink()
            except OSError:
                pass
        elif staged.path.is_file() and staged.path.parent.name == ".argus-work":
            try:
                staged.path.unlink()
            except OSError:
                pass

        if not v_res.get("ok"):
            crash_code = v_res.get("crash_code")
            return {
                "safe": False,
                "crash_code": crash_code,
                "detail": f"Sandbox pre-flight rejected patch: {v_res.get('detail')}",
                "suggested_action": v_res.get("suggested_action"),
            }

        return {
            "safe": True,
            "detail": "Patch pre-flight passed cleanly in sandbox (no crash, clean launch)",
            "windows_count": len(v_res.get("windows") or []),
            "modules": list(module_scratch.keys()),
        }

    except Exception as e:
        return {
            "safe": False,
            "detail": f"Sandbox test failed with exception: {e}",
        }
    finally:
        try:
            for fp in scratch_dir.iterdir():
                try:
                    fp.unlink()
                except OSError:
                    pass
            if scratch_dir.is_dir():
                scratch_dir.rmdir()
        except OSError:
            pass
