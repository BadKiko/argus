from __future__ import annotations

"""Lightweight task intent routing: gate transform vs password crackme vs UI patch."""

import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from argus.binary import load_binary

_GATE_SIGNAL_RX = re.compile(
    r"(unlock|license|лиценз|активац|активир|register|unregistered|trial|serial|"
    r"restriction|entitlement|activation|verify|check|gate|transform|"
    r"\bключ\b|license\s*key|any\s*key|"
    r"убери\s+про|remove\s+licen|bypass\s+licen|crack\s+licen)",
    re.IGNORECASE,
)
_PASSWORD_RX = re.compile(
    r"(password|парол|crackme|flag|keygen|backdoor|authenticate|login|"
    r"wrong\s+password|enter\s+password)",
    re.IGNORECASE,
)
_UI_RX = re.compile(
    r"(заголов|title|тем[аыу]|theme|строк|надпис|текст|label|напиш|переимен|"
    r"rename|ui\b|окно|replace\s+string)",
    re.IGNORECASE,
)


class TaskKind(Enum):
    GATE_TRANSFORM = "gate_transform"
    PASSWORD = "password"
    PATCH_UI = "patch_ui"
    GENERAL = "general"


def classify_task_intent(
    task_text: str,
    *,
    binary: Optional[str] = None,
    discover: Optional[Dict[str, Any]] = None,
) -> TaskKind:
    text = (task_text or "").strip()
    if not text:
        return TaskKind.GENERAL

    has_license_words = bool(_GATE_SIGNAL_RX.search(text))
    has_password_words = bool(_PASSWORD_RX.search(text))
    has_ui_words = bool(_UI_RX.search(text))

    binary_signals = _binary_signals(binary) if binary else {}

    # Crackme: authenticate + Welcome/Password strings, no license rodata
    if binary_signals.get("authenticate_symbol") and not binary_signals.get("license_strings"):
        if has_license_words or has_password_words or binary_signals.get("password_crackme"):
            return TaskKind.PASSWORD

    if binary_signals.get("password_crackme") and not binary_signals.get("license_strings"):
        if has_license_words and not has_password_words:
            return TaskKind.PASSWORD
        if has_password_words or binary_signals.get("authenticate_symbol"):
            return TaskKind.PASSWORD

    if has_ui_words and not has_license_words:
        return TaskKind.PATCH_UI

    if has_license_words or binary_signals.get("license_strings"):
        return TaskKind.GATE_TRANSFORM

    if has_password_words or binary_signals.get("password_crackme"):
        return TaskKind.PASSWORD

    return TaskKind.GENERAL


def _binary_signals(path: Optional[str]) -> Dict[str, bool]:
    out: Dict[str, bool] = {
        "license_strings": False,
        "password_crackme": False,
        "authenticate_symbol": False,
    }
    if not path:
        return out
    try:
        img = load_binary(path)
    except Exception:
        return out

    syms = set(img.symbols.keys()) if img.symbols else set()
    out["authenticate_symbol"] = "authenticate" in syms

    blob = b""
    for sec in getattr(img, "sections", []) or []:
        if getattr(sec, "data", None):
            blob += sec.data[: min(len(sec.data), 128 * 1024)]
        else:
            try:
                addr = getattr(sec, "addr", None) or getattr(sec, "vaddr", 0)
                blob += img.read_bytes(addr, min(sec.size, 128 * 1024)) or b""
            except Exception:
                continue
    if len(blob) < 4096:
        try:
            blob += Path(path).read_bytes()[:512 * 1024]
        except OSError:
            pass

    low = blob.lower()
    license_hits = (
        b"unregistered",
        b"trial expired",
        b"trial version",
        b"license key",
        b"invalid license",
        b"activation",
        b"serial number",
        b"enter license",
    )
    password_hits = (
        b"password",
        b"wrong",
        b"welcome",
        b"username",
        b"go away",
    )
    out["license_strings"] = any(h in low for h in license_hits)
    out["password_crackme"] = any(h in low for h in password_hits) and (
        out["authenticate_symbol"] or b"password" in low
    )
    return out


_PASSWORD_Q_RX = re.compile(
    r"(какой|what|дай|give|find|узнать|tell|show).{0,24}(парол|password)",
    re.IGNORECASE,
)

_BYPASS_PASSWORD_RX = re.compile(
    r"(любой\s*парол|any\s*password|accept\s*any|принимал|принимал[аи]|"
    r"без\s*парол|skip\s*auth|always\s*accept|обойд\w*\s*парол|bypass\s*password)",
    re.IGNORECASE,
)


def is_bypass_password_task(text: str) -> bool:
    return bool(_BYPASS_PASSWORD_RX.search(text or ""))


_BYPASS_GATE_SIGNAL_RX = re.compile(
    r"(люб\w*\s+ключ|any\s+key|accept\s+any\s+(?:key|license)|"
    r"люб\w*\s+лиценз|люб\w*\s+serial|any\s+license\s+key)",
    re.IGNORECASE,
)


def is_bypass_license_task(text: str) -> bool:
    return bool(_BYPASS_GATE_SIGNAL_RX.search(text or ""))


def task_signals(
    task_text: str,
    *,
    binary: Optional[str] = None,
    discover: Optional[Dict[str, Any]] = None,
) -> Dict[str, float]:
    """Soft signal scores for the LLM — not routing decisions."""
    text = (task_text or "").strip()
    binary_signals = _binary_signals(binary) if binary else {}
    gate = 0.0
    password = 0.0
    ui = 0.0
    if _GATE_SIGNAL_RX.search(text):
        gate += 0.75
    if _PASSWORD_RX.search(text):
        password += 0.75
    if _UI_RX.search(text):
        ui += 0.7
    if binary_signals.get("license_strings"):
        gate += 0.35
    if binary_signals.get("password_crackme"):
        password += 0.4
    if binary_signals.get("authenticate_symbol"):
        password += 0.25
    if is_bypass_license_task(text):
        gate += 0.2
    if is_bypass_password_task(text):
        password += 0.2
    return {
        "gate_transform": min(1.0, gate),
        "password": min(1.0, password),
        "patch_ui": min(1.0, ui),
        "general": max(0.0, 1.0 - min(1.0, gate + password + ui)),
    }


def format_task_signals(
    task_text: str,
    *,
    binary: Optional[str] = None,
    discover: Optional[Dict[str, Any]] = None,
) -> str:
    sig = task_signals(task_text, binary=binary, discover=discover)
    kind = classify_task_intent(task_text, binary=binary, discover=discover)
    return (
        f"task_signals (hints only, not ground truth): {sig} "
        f"legacy_kind={kind.value}"
    )


def routing_hint(
    task_text: str,
    *,
    binary: Optional[str] = None,
    discover: Optional[Dict[str, Any]] = None,
) -> str:
    """Neutral workflow examples — LLM chooses tools."""
    sig = task_signals(task_text, binary=binary, discover=discover)
    parts = [format_task_signals(task_text, binary=binary, discover=discover)]
    parts.append(
        "RE workflow (examples): observe (find/xrefs/disasm) → hypothesize → "
        "diagnose_failure(error_text=<verbatim from user or sandbox>) → "
        "apply_plan(steps=<from evidence>) → verify."
    )
    if sig.get("password", 0) > sig.get("gate_transform", 0):
        parts.append(
            "Password-like signals: consider argus_ai, argus_solve, or authenticate xref — verify with behavior."
        )
    elif sig.get("patch_ui", 0) > 0.5:
        parts.append("UI-like signals: argus_find + argus_patch replace_string (new len ≤ old).")
    elif sig.get("gate_transform", 0) > 0.4:
        parts.append(
            "Gate-like signals: find error text → diagnose_failure → small apply_plan batches from corrective_patch."
        )
    parts.append("Never invent addresses; error_text must be verbatim from user, sandbox, or find hits.")
    return "\n".join(parts)
