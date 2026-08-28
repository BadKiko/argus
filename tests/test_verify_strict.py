"""Stricter gate verify + plan confidence."""

from __future__ import annotations

from argus.apply_plan import _composite_verify
from argus.find_slice import build_patch_plan, plan_is_confident
from argus.llm.tasks import _patch_verify_ok


def test_format_marker_covering_not_confident():
    gates = [
        {
            "kind": "ret_imm",
            "addr": "0x1000",
            "score": 455,
            "ui_label_only": False,
            "ret_guess": 1,
            "reason": "validate-covering fn size=0x1000 substr='BEGIN FOO'",
            "string_preview": "BEGIN FOO",
            "nearby_fn": "sub_1000",
            "structural_nearby": False,
        },
    ]
    plan = build_patch_plan(gates)
    assert not plan or not plan_is_confident(plan)
    if plan:
        assert plan[0].get("confidence") == "low"


def test_structural_covering_can_be_medium():
    gates = [
        {
            "kind": "ret_imm",
            "addr": "0x1000",
            "score": 520,
            "ui_label_only": False,
            "ret_guess": 1,
            "reason": "validate-covering fn size=0x1000 substr='error 5'",
            "string_preview": "error 5",
            "nearby_fn": "sub_1000",
            "structural_nearby": True,
        },
    ]
    plan = build_patch_plan(gates)
    assert plan
    assert plan[0].get("confidence") in ("medium", "high")


def test_call_cmp_plan_is_confident():
    gates = [
        {
            "kind": "ret_imm",
            "addr": "0x2000",
            "score": 500,
            "ui_label_only": False,
            "ret_guess": 1,
            "reason": "call→cmp==1 large callee size=0x900",
            "nearby_fn": "sub_2000",
        },
    ]
    plan = build_patch_plan(gates)
    assert plan_is_confident(plan)
    assert plan[0].get("confidence") == "high"


def test_gate_task_rejects_bytes_only_verify():
    payload = {
        "ok": True,
        "verify": {
            "kind": "patch_bytes",
            "ok": True,
            "detail": "bytes ok",
        },
    }
    assert _patch_verify_ok(payload, gate_task=False) is True
    assert _patch_verify_ok(payload, gate_task=True) is False


def test_gate_task_rejects_skipped_behavior():
    payload = {
        "ok": True,
        "verify": {
            "kind": "patch_composite",
            "ok": True,
            "patch_bytes": {"ok": True},
            "patch_behavior": {"ok": False, "ran": False, "skipped": True},
        },
    }
    assert _patch_verify_ok(payload, gate_task=True) is False


def test_composite_requires_behavior_when_flagged():
    bytes_v = {"ok": True, "detail": "bytes changed"}
    skipped = {"ok": False, "ran": False, "skipped": True, "detail": "too large"}
    out = _composite_verify(bytes_v, skipped, require_behavior=True)
    assert out["ok"] is False
    assert out["kind"] == "patch_composite"
