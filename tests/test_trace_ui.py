"""Agent investigation trace UI."""

from __future__ import annotations

from argus.cli.trace_graph import InvestigationGraph
from argus.cli.trace_ui import describe_tool_call, describe_tool_result


def test_describe_slice_empty_plan():
    action = describe_tool_call("argus_slice", {"binary": "fauxware", "query": "license"})
    assert "gate" in action
    out = describe_tool_result(
        "argus_slice",
        {"binary": "fauxware"},
        {"ok": True, "patch_plan": [], "string_hits": [{"addr": "0x1"}]},
    )
    assert "plan=0" in out


def test_describe_patch():
    action = describe_tool_call(
        "argus_patch",
        {"kind": "force_branch", "addr": "0x4007bb", "binary": "fauxware", "taken": True},
    )
    assert "0x4007bb" in action
    out = describe_tool_result(
        "argus_patch",
        {"addr": "0x4007bb"},
        {"ok": True, "patched_path": "fauxware.patched"},
    )
    assert "fauxware.patched" in out


def test_graph_fan_out_three_files():
    g = InvestigationGraph()
    g.add("discover", subtitle="app", detail="3 linked", fan_out=["main", "liba.so", "libb.so"])
    text = g.render(max_lines=40)
    assert "START" in text
    assert "discover" in text
    assert "liba.so" in text


def test_graph_compresses_old_steps():
    g = InvestigationGraph()
    for i in range(20):
        g.add(f"t{i}", subtitle="fauxware", detail=f"d{i}")
    short = g.render(max_lines=22)
    assert "…" in short
    assert "steps" in short
    assert "▸ t19" in short or "t19" in short
    assert short.count("╭") < 20


def test_graph_lines_centered():
    from argus.cli.trace_graph import _center_graph_lines

    lines = [
        "╭────────────────╮",
        "│      wide      │",
        "╰────────────────╯",
        "        │",
        "╭──────╮",
        "│ tiny │",
        "╰──────╯",
    ]
    out = _center_graph_lines(lines)
    w = len(out[0])
    assert all(len(ln) == w for ln in out)
    assert out[4].center(w) == out[4]
