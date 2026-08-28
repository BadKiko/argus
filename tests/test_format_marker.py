"""Structural format-marker heuristics (no phrase hardcode)."""

from argus.find_slice import _is_format_marker_string, _structural_gate_reason


def test_format_marker_all_caps():
    assert _is_format_marker_string("BEGIN FOO")
    assert _is_format_marker_string("END BAR")
    assert not _is_format_marker_string("This doesn't appear to be valid")


def test_structural_gate_reason():
    assert _structural_gate_reason("call→cmp==1 near xref")
    assert _structural_gate_reason("jcc after test eax")
    assert not _structural_gate_reason("ui label string hit")
