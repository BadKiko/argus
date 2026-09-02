"""Observe ranking: check-first plan from brief + user task."""

from __future__ import annotations

import json
from pathlib import Path

from argus.discover import discover_targets
from argus.llm.agent import _build_user_content
from argus.llm.observe import (
    build_observe_plan,
    deterministic_observe_plan,
    format_observe_plan,
    merge_llm_plan,
    needles_from_task,
)
from argus.payload import build_target_brief, prefer_observe_linked
from tests.test_payload_ir import _host_tree


def test_needles_from_task_not_invented():
    qs = needles_from_task('сделай чтобы любой ключ принимал "trial expired"')
    assert any("ключ" in q for q in qs)
    assert "trial expired" in qs
    assert not any("enter license" == q.lower() for q in qs)


def test_asar_outranks_gles_and_license(tmp_path):
    host = _host_tree(tmp_path, asar=True)
    gles = host.parent / "libGLESv2.so"
    gles.write_bytes(b"license " * 4000)
    (host.parent / "LICENSES.chromium.html").write_text("license " * 2000)
    brief = build_target_brief(host, install_dir=str(host.parent))
    names = [p["name"] for p in brief["payloads"]]
    assert names[0] == "app.asar"
    assert "LICENSES.chromium.html" not in names[:3]
    linked = prefer_observe_linked(
        [
            {"path": str(gles), "name": "libGLESv2.so", "kind": "native", "score": 80, "size": gles.stat().st_size},
            {
                "path": str(host.parent / "resources" / "app.asar"),
                "name": "app.asar",
                "kind": "archive",
                "score": 0,
                "size": (host.parent / "resources" / "app.asar").stat().st_size,
            },
            {
                "path": str(host.parent / "LICENSES.chromium.html"),
                "name": "LICENSES.chromium.html",
                "kind": "text",
                "score": 40,
                "size": 100,
            },
        ],
        cap=8,
    )
    assert linked[0]["name"] == "app.asar"
    assert all(x["name"] != "LICENSES.chromium.html" for x in linked)


def test_discover_linked_keeps_zero_score_asar(tmp_path):
    host = _host_tree(tmp_path, asar=True)
    gles = host.parent / "libGLESv2.so"
    gles.write_bytes(b"invalid license\x00Unregistered\x00" * 200)
    d = discover_targets("trial", root=str(host.parent), binary=str(host))
    names = [Path(m["path"]).name for m in d.get("linked") or []]
    assert "app.asar" in names
    assert names[0] in ("app.asar", "app.js")


def test_deterministic_check_first_payload(tmp_path):
    host = _host_tree(tmp_path, asar=True)
    brief = build_target_brief(host, install_dir=str(host.parent))
    plan = deterministic_observe_plan(brief, "чтобы любой ключ принимал")
    names = [x["name"] for x in plan["check_first"]]
    assert names[0] == "app.asar"
    assert "ключ" in " ".join(plan["find_queries"])
    text = format_observe_plan(plan)
    assert "CHECK FIRST" in text
    assert "argus_find(binary=" in text
    assert str(host.parent / "resources" / "app.asar") in text


def test_llm_merge_drops_invented_paths_and_needles(tmp_path):
    host = _host_tree(tmp_path, asar=True)
    brief = build_target_brief(host, install_dir=str(host.parent))
    base = deterministic_observe_plan(brief, "unlock trial")
    merged = merge_llm_plan(
        base,
        {
            "check_first": [
                {"name": "not-a-real-module.js", "why": "guess"},
                {"name": "app.asar", "why": "payload archive"},
            ],
            "find_queries": ["Enter License", "trial"],
            "skip": ["LICENSE.electron"],
        },
        brief,
        "unlock trial",
    )
    names = [x["name"] for x in merged["check_first"]]
    assert "not-a-real-module.js" not in names
    assert "app.asar" in names
    assert "Enter License" not in merged["find_queries"]
    assert "trial" in merged["find_queries"]


def test_build_observe_plan_uses_generate_text(tmp_path):
    host = _host_tree(tmp_path, asar=True)
    brief = build_target_brief(host, install_dir=str(host.parent))

    def fake(_system: str, _user: str) -> str:
        return json.dumps(
            {
                "check_first": [{"name": "app.js", "why": "text sidecar"}],
                "find_queries": ["trial"],
                "skip": ["LICENSE.electron"],
            }
        )

    plan = build_observe_plan(brief, "unlock trial", generate_text=fake)
    assert plan["source"] == "llm"
    assert plan["check_first"][0]["name"] == "app.js"


def test_user_content_includes_check_first(tmp_path):
    host = _host_tree(tmp_path, asar=True)
    brief = build_target_brief(host, install_dir=str(host.parent))
    plan = deterministic_observe_plan(brief, "unlock trial")
    content = _build_user_content(
        "unlock trial",
        str(host),
        "TASKS:\n1. unlock",
        discover={"brief": brief, "observe_plan": plan},
    )
    assert content.startswith("TARGET BRIEF")
    assert "CHECK FIRST" in content
    assert content.index("TARGET BRIEF") < content.index("CHECK FIRST")
    assert content.index("CHECK FIRST") < content.index("unlock trial")
