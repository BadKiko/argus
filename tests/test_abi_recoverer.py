# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.abi_recoverer import ABIRecoverer

def test_abi_recoverer_signature_inference():
    recoverer = ABIRecoverer(is_64bit=True)

    # Simulated function that uses RCX and RDX, computes RAX, and returns
    instrs = [
        {"op": "MOV", "writes": ["rax"], "reads": ["rcx"]},
        {"op": "ADD", "writes": ["rax"], "reads": ["rax", "rdx"]},
        {"op": "RET", "writes": [], "reads": ["rax"]}
    ]

    res = recoverer.infer_function_signature("calculate_checksum", instrs)

    assert res["arg_count"] == 2
    assert "rcx" in res["inferred_args"]
    assert "rdx" in res["inferred_args"]
    assert res["returns_value"] is True
    assert "calculate_checksum(uint64_t arg_1_rcx, uint64_t arg_2_rdx);" in res["c_prototype"]
