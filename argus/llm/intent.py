from __future__ import annotations

"""Lightweight task intent routing: license unlock vs password crackme vs UI patch."""

import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from argus.binary import load_binary

_LICENSE_RX = re.compile(
    r"(unlock|license|лиценз|активац|register|unregistered|trial|serial|"
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
    UNLOCK_LICENSE = "unlock_license"
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

    has_license_words = bool(_LICENSE_RX.search(text))
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
        return TaskKind.UNLOCK_LICENSE

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


_BYPASS_LICENSE_RX = re.compile(
    r"(люб\w*\s+ключ|any\s+key|accept\s+any\s+(?:key|license)|"
    r"люб\w*\s+лиценз|люб\w*\s+serial|any\s+license\s+key)",
    re.IGNORECASE,
)


def is_bypass_license_task(text: str) -> bool:
    return bool(_BYPASS_LICENSE_RX.search(text or ""))


def routing_hint(
    task_text: str,
    *,
    binary: Optional[str] = None,
    discover: Optional[Dict[str, Any]] = None,
) -> str:
    kind = classify_task_intent(task_text, binary=binary, discover=discover)
    if kind == TaskKind.PASSWORD:
        if _PASSWORD_Q_RX.search(task_text or ""):
            return (
                "Task routing: PASSWORD question — ONE argus_ai(prompt=<exact user task>); "
                "symbolic solve returns stdin/password. Do NOT lift/deobf/solve-spam."
            )
        if is_bypass_password_task(task_text or ""):
            return (
                "Task routing: BYPASS password (accept any) — argus_slice → argus_unlock_apply "
                "by unlock_plan; ret_imm on authenticate alone may fail behavior verify."
            )
        return (
            "Task routing: PASSWORD crackme (not license unlock) — use argus_ai/ask password "
            "path or patch authenticate; do NOT use argus_unlock_apply for license."
        )
    if kind == TaskKind.UNLOCK_LICENSE:
        if is_bypass_license_task(task_text or ""):
            return (
                "Task routing: BYPASS license key (accept any key) — argus_slice on work binary "
                "(install-dir modules via modules=[] if plan=0), then ONE argus_unlock_apply "
                "from unlock_plan only; discover root = install dir, NOT workspace cache."
            )
        return (
            "Task routing: LICENSE — require argus_slice with non-empty unlock_plan, "
            "then ONE argus_unlock_apply (no custom steps unless copied from slice JSON)."
        )
    if kind == TaskKind.PATCH_UI:
        return "Task routing: UI/patch — use argus_patch replace_string or weak UI xref; not unlock_apply."
    return ""
