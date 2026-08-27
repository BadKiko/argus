"""Natural-language `argus ai` entry."""

from __future__ import annotations

from pathlib import Path

from argus.nl import parse_prompt
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
    assert h.patch_kind in (PatchKind.SKIP_CHECK, PatchKind.RET_IMM)
    assert h.function == "authenticate"


def test_parse_unlock_to_ret_imm():
    h = parse_prompt("любой ключ / unlock")
    assert h.want == Want.PATCH
    assert h.patch_kind == PatchKind.RET_IMM
    assert h.ret_value == 0


def test_ai_password_fla():
    from argus.ask import Hint, Want, ask

    # oracle sample: explicit find + function (no production defaults)
    r = ask(
        str(SAMPLES / "fauxware_fla"),
        Hint(
            want=Want.PASSWORD,
            find=b"Welcome",
            function="authenticate",
            note="дай пароль cff",
        ),
    )
    assert r.ok
    assert r.answer == "SOSNEAKY"
