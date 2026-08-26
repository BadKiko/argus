from __future__ import annotations

"""Heuristics: will this patch break app startup? Feed result back to the LLM."""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from argus.binary import load_binary


def _is_early_ret_stub(prologue: bytes) -> bool:
    """mov eax/rax,imm; ret  or lone ret / xor+ret at function start."""
    if not prologue:
        return False
    if prologue[0] == 0xC3:
        return True
    # mov eax, imm32 ; ret
    if len(prologue) >= 6 and prologue[0] == 0xB8 and prologue[5] == 0xC3:
        return True
    # xor eax,eax ; ret
    if len(prologue) >= 3 and prologue[0:2] == b"\x31\xc0" and prologue[2] == 0xC3:
        return True
    # xor eax,eax ; nop* ; ret
    if len(prologue) >= 3 and prologue[0:2] == b"\x31\xc0" and 0xC3 in prologue[:8]:
        return True
    return False


def _entry_addr(img) -> int:
    main = img.symbols.get("main")
    if main and main.addr:
        return main.addr
    return img.entry


def _read_prologue(img, addr: int, n: int = 16) -> bytes:
    return img.read_bytes(addr, n)


def preflight_patch(
    path: str,
    *,
    target_addr: Optional[int],
    label: str = "",
    kind: str = "",
) -> Dict[str, Any]:
    """
    Before writing: structural refuse if patch would kill startup.
    Returns {safe, reason, next_hint}.
    """
    img = load_binary(path)
    entry = _entry_addr(img)
    reasons: List[str] = []

    if target_addr is not None and target_addr == entry and kind in (
        "always_true",
        "always_false",
        "ret_imm",
    ):
        reasons.append(
            f"target {label or hex(target_addr)} is program entry — early ret exits the app"
        )

    if target_addr is not None and target_addr == img.entry and kind in (
        "always_true",
        "always_false",
        "ret_imm",
    ):
        if not reasons:
            reasons.append("target is ELF/PE entry — stubbing it prevents startup")

    if reasons:
        return {
            "safe": False,
            "reason": "; ".join(reasons),
            "next_hint": (
                "re-patch: use argus_find for license/check strings, then "
                "force_branch or nop_bytes on the check VA — never stub main/entry"
            ),
            "entry": hex(entry),
        }
    return {"safe": True, "reason": "", "next_hint": "", "entry": hex(entry)}


def assess_patched_binary(
    original_path: str,
    patched_path: str,
    *,
    smoke_timeout: float = 0.4,
) -> Dict[str, Any]:
    """
    After write: check entry prologue + short smoke run vs original.
    If unsafe, caller should treat patch as failed and ask LLM to re-patch.
    """
    if not Path(patched_path).is_file():
        return {
            "safe": False,
            "reason": "patched file missing",
            "next_hint": "re-patch with a different intent",
        }

    orig = load_binary(original_path)
    patched = load_binary(patched_path)
    entry = _entry_addr(orig)
    o_pro = _read_prologue(orig, entry)
    p_pro = _read_prologue(patched, entry)

    if _is_early_ret_stub(p_pro) and not _is_early_ret_stub(o_pro):
        return {
            "safe": False,
            "reason": f"entry@{hex(entry)} became early-ret stub ({p_pro[:6].hex()}) — app will exit immediately",
            "next_hint": (
                "delete this approach; re-patch with force_branch/nop_bytes on a "
                "license/check call, not main"
            ),
            "entry": hex(entry),
            "orig_prologue": o_pro[:8].hex(),
            "patched_prologue": p_pro[:8].hex(),
        }

    # GUI / long-running heuristic: original still running at timeout → patched must not exit instantly empty
    if orig.fmt == "elf":
        o_run = _smoke_run(original_path, smoke_timeout)
        p_run = _smoke_run(patched_path, smoke_timeout)
        # Original timed out (still alive) but patched exited fast with no output → broken GUI
        if o_run.get("timeout") and not p_run.get("timeout"):
            out = p_run.get("stdout") or b""
            err = p_run.get("stderr") or b""
            if len(out) + len(err) < 8 and p_run.get("returncode") is not None:
                return {
                    "safe": False,
                    "reason": (
                        "original still runs after timeout (likely GUI) but patched "
                        f"exited immediately rc={p_run.get('returncode')} with empty I/O"
                    ),
                    "next_hint": (
                        "re-patch surgically (force_branch/nop_bytes on check); "
                        "do not stub startup path"
                    ),
                    "entry": hex(entry),
                    "orig_smoke": {k: o_run.get(k) for k in ("timeout", "returncode")},
                    "patched_smoke": {
                        "timeout": p_run.get("timeout"),
                        "returncode": p_run.get("returncode"),
                    },
                }
        # Patched crash / segfault vs original ok
        if o_run.get("ok") and p_run.get("ok"):
            orc = o_run.get("returncode")
            prc = p_run.get("returncode")
            if orc == 0 and prc is not None and prc < 0:
                return {
                    "safe": False,
                    "reason": f"patched crashed (signal {-prc}) while original exited cleanly",
                    "next_hint": "re-patch with a smaller/safer change",
                    "entry": hex(entry),
                }

    return {
        "safe": True,
        "reason": "",
        "next_hint": "",
        "entry": hex(entry),
        "orig_prologue": o_pro[:8].hex(),
        "patched_prologue": p_pro[:8].hex(),
    }


def _smoke_run(path: str, timeout: float) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            [path],
            input=b"\n\n",
            capture_output=True,
            timeout=timeout,
            env={**os.environ, "QT_QPA_PLATFORM": "offscreen", "DISPLAY": os.environ.get("DISPLAY", "")},
        )
        return {
            "ok": True,
            "timeout": False,
            "returncode": p.returncode,
            "stdout": p.stdout[:200],
            "stderr": p.stderr[:200],
        }
    except subprocess.TimeoutExpired:
        return {"ok": True, "timeout": True, "returncode": None, "stdout": b"", "stderr": b""}
    except Exception as e:
        return {"ok": False, "timeout": False, "reason": str(e), "returncode": None}


def finalize_patch_safety(
    original_path: str,
    patched_path: str,
    cert: Dict[str, Any],
    *,
    remove_if_unsafe: bool = True,
) -> Tuple[bool, Dict[str, Any], List[str]]:
    """
    Run post-patch assess. If unsafe: optionally remove file, mark cert, return ok=False.
    """
    assess = assess_patched_binary(original_path, patched_path)
    notes: List[str] = []
    cert = dict(cert or {})
    cert["safety"] = assess
    if assess.get("safe"):
        cert.setdefault("notes", [])
        if isinstance(cert["notes"], list):
            cert["notes"] = list(cert["notes"]) + ["safety_ok"]
        return True, cert, ["safety_ok"]

    notes.append(f"unsafe: {assess.get('reason')}")
    if assess.get("next_hint"):
        notes.append(f"next: {assess['next_hint']}")
    cert["proven"] = False
    cert.setdefault("notes", [])
    if isinstance(cert["notes"], list):
        cert["notes"] = list(cert["notes"]) + notes
    if remove_if_unsafe:
        try:
            Path(patched_path).unlink(missing_ok=True)
            notes.append(f"removed unsafe {patched_path}")
        except OSError:
            pass
    return False, cert, notes
