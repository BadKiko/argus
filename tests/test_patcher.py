# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import os
from argus.engine.patcher import BinaryPatcher

def test_binary_patcher_pe_modification():
    src_pe = r"E:\Work\argus\angr_test_sample.exe"
    assert os.path.exists(src_pe)

    patcher = BinaryPatcher(src_pe)
    # Patch 4 NOP bytes at Entry Point RVA (0xBB00)
    success = patcher.nop_range(rva=0xBB00, length=4, description="Test entry NOP patch")
    assert success is True

    out_pe = r"E:\Work\argus\test_patched.exe"
    patcher.save_patched_binary(out_pe)
    assert os.path.exists(out_pe)
    assert os.path.getsize(out_pe) > 0

    # Verify patched bytes
    with open(out_pe, "rb") as f:
        data = f.read()
    offset = patcher.rva_to_offset(0xBB00)
    assert data[offset:offset + 4] == b"\x90\x90\x90\x90"

    # Cleanup test output
    if os.path.exists(out_pe):
        os.remove(out_pe)
