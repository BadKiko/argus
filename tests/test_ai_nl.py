"""Natural-language `argus ai` entry."""

from __future__ import annotations

from pathlib import Path

from argus.nl import ai, parse_prompt
from argus.ask import Want, PatchKind

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_parse_password_ru():
    h = parse_prompt("дай пароль для админа")
    assert h.want == Want.PASSWORD
    assert "админ" in h.note.lower() or "админа" in h.note


def test_parse_bypass():
    h = parse_prompt("сделай always true для authenticate")
    assert h.want == Want.PATCH
    assert h.patch_kind == PatchKind.ALWAYS_TRUE
    assert h.function == "authenticate"


def test_parse_lift():
    h = parse_prompt("покажи код функции authenticate")
    assert h.want == Want.LIFT
    assert h.function == "authenticate"


def test_parse_remove_license_check():
    h = parse_prompt("убери проверку лицензии в authenticate")
    assert h.want == Want.PATCH
    assert h.patch_kind == PatchKind.SKIP_CHECK


def test_ai_password_fla():
    r = ai(str(SAMPLES / "fauxware_fla"), "дай пароль для админа")
    assert r.ok
    assert r.answer == "SOSNEAKY"
