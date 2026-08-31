from argus.llm.intent import is_bypass_license_task, routing_hint


def test_bypass_license_russian():
    assert is_bypass_license_task("сделай чтобы любой ключ подходил лицензии")
    hint = routing_hint("сделай чтобы любой ключ подходил лицензии")
    assert "gate" in hint.lower() or "Gate" in hint
    assert "task_signals" in hint
