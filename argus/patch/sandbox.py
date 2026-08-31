"""Argus Pre-Flight Patch Sandbox.

Tests proposed binary patches in an isolated scratch environment before modifying
the main workspace binary. Catches crashes (0xC0000005, SIGSEGV, illegal instructions)
in milliseconds without corrupting the user's working binary.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from argus.behavior import verify_binary_semantic
from argus.binary.file_io import copy_binary_resilient, release_binary_lock


def _apply_step_direct(path: str, step: Dict[str, Any]) -> bool:
    try:
        import argus.patch.intents as pi
        kind = step.get("kind")
        raw_addr = step.get("addr")
        if not raw_addr:
            return False
        addr = int(raw_addr, 16) if isinstance(raw_addr, str) and raw_addr.startswith("0x") else int(raw_addr)

        if kind == "ret_imm":
            val = int(step.get("value", 1))
            ok, _ = pi.ret_imm(path, fn_addr=addr, value=val, output=path)
            return bool(ok)
        elif kind == "force_branch":
            taken = bool(step.get("taken", True))
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


def test_patch_in_sandbox(
    binary: str,
    patch_steps: List[Dict[str, Any]],
    *,
    stdin: bytes = b"test_sandbox_input\n",
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """Apply patch steps to an isolated temporary copy and verify process safety.

    Returns:
        Dict with 'safe': bool, 'crash_code': Optional[str], 'detail': str.
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

    scratch_dir = Path(tempfile.mkdtemp(prefix="argus-sandbox-"))
    scratch_path = str(scratch_dir / f"scratch_{src.name}")
    try:
        orig_fallback = str(src)
        try:
            from argus.llm.session import get_session

            sess = get_session()
            if sess.original_binary and Path(sess.original_binary).is_file():
                orig_fallback = sess.original_binary
        except Exception:
            pass
        copy_binary_resilient(src, scratch_path, fallback_src=orig_fallback)

        # Apply patch steps directly to scratch copy
        for step in patch_steps:
            ok = _apply_step_direct(scratch_path, step)
            if not ok:
                return {
                    "safe": False,
                    "detail": f"Failed to apply patch step: {step}",
                    "scratch_applied": False,
                }

        # Run semantic pre-flight check on scratch copy
        orig = str(src)
        try:
            from argus.llm.session import get_session

            sess = get_session()
            if sess.original_binary:
                orig = sess.original_binary
        except Exception:
            pass
        # Run semantic pre-flight on install-staged copy (Packages/DLLs beside exe).
        from argus.binary.launch_env import stage_native_executable

        staged = stage_native_executable(scratch_path, original=orig)
        verify_path = str(staged.path)
        v_res = verify_binary_semantic(
            verify_path,
            original_path=orig,
            stdin=stdin,
            timeout=timeout,
        )

        release_binary_lock(staged.path)
        release_binary_lock(scratch_path)

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
        }

    except Exception as e:
        return {
            "safe": False,
            "detail": f"Sandbox test failed with exception: {e}",
        }
    finally:
        try:
            if os.path.exists(scratch_path):
                os.remove(scratch_path)
            if scratch_dir.is_dir():
                scratch_dir.rmdir()
        except OSError:
            pass
