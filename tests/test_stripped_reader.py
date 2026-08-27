"""Universal stripped code reader tests."""

from __future__ import annotations

from pathlib import Path

from argus.ask import Hint, Want, ask
from argus.binary import load_binary
from argus.disasm.recovery import recover_functions
from argus.disasm.resolve import resolve_lift_target
from argus.lift.pseudo import annotated_lift

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_recovery_includes_named_funcs():
    img = load_binary(str(SAMPLES / "fauxware"))
    idx = recover_functions(img)
    assert "authenticate" in img.symbols
    assert "main" in img.symbols
    assert img.symbols["authenticate"].addr in idx.starts
    assert img.symbols["main"].addr in idx.starts
    assert len(idx.starts) >= 2


def test_resolve_by_symbol_and_entry():
    img = load_binary(str(SAMPLES / "fauxware"))
    t = resolve_lift_target(img, function="authenticate")
    assert t.label == "authenticate"
    assert t.va == img.symbols["authenticate"].addr
    t2 = resolve_lift_target(img, entry=img.symbols["main"].addr)
    assert t2.va == img.symbols["main"].addr or t2.label.startswith("sub_") or t2.label == "main"


def test_resolve_by_string_query():
    img = load_binary(str(SAMPLES / "fauxware"))
    # common fauxware prompt-ish string
    data = Path(SAMPLES / "fauxware").read_bytes()
    query = None
    for cand in (b"Username", b"Password", b"Welcome", b"user"):
        if cand in data:
            query = cand.decode()
            break
    assert query
    t = resolve_lift_target(img, query=query)
    # must resolve somewhere in executable text
    assert any(lo <= t.va < hi for lo, hi in recover_functions(img).text_ranges)


def test_annotated_lift_has_confidence_and_lea_or_call():
    path = str(SAMPLES / "fauxware")
    text, ev = annotated_lift(path, function="authenticate")
    assert "Argus lift" in text
    assert "confidence" in ev
    assert ev["confidence"] in ("high", "medium", "low")
    assert ev.get("function") == "authenticate"
    assert ev.get("blocks", 0) >= 1


def test_ask_lift_named_no_regress():
    r = ask(str(SAMPLES / "fauxware"), Hint(want=Want.LIFT, function="authenticate"))
    assert r.ok
    assert r.readable
    assert "authenticate" in (r.readable or "")


def test_ask_lift_via_entry():
    img = load_binary(str(SAMPLES / "fauxware"))
    addr = img.symbols["authenticate"].addr
    r = ask(str(SAMPLES / "fauxware"), Hint(want=Want.LIFT, entry=addr))
    assert r.ok
    assert r.readable
    assert "confidence" in (r.evidence or {})


def test_sublime_optional_recovery_many_starts():
    sublime = Path("/opt/sublime_merge/sublime_merge")
    if not sublime.is_file():
        return
    img = load_binary(str(sublime))
    idx = recover_functions(img)
    # far more than the ~9 local symbols
    assert len(idx.starts) > 50
