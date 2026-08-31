"""Intent routing: password crackme vs license unlock."""

from __future__ import annotations

from pathlib import Path

from argus.llm.intent import TaskKind, classify_task_intent, routing_hint

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FAUXWARE = SAMPLES / "fauxware"


def test_fauxware_remove_license_routes_password():
    if not FAUXWARE.is_file():
        return
    kind = classify_task_intent("remove license check", binary=str(FAUXWARE))
    assert kind == TaskKind.PASSWORD
    hint = routing_hint("remove license check", binary=str(FAUXWARE))
    assert "password" in hint.lower() or "Password" in hint


def test_license_prompt_routes_unlock():
    kind = classify_task_intent("bypass trial activation serial")
    assert kind == TaskKind.GATE_TRANSFORM


def test_ui_replace_routes_patch():
    kind = classify_task_intent("replace title string in window")
    assert kind == TaskKind.PATCH_UI
