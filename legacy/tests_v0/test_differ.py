# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.differ import BinaryDiffer

def test_binary_differ_output():
    differ = BinaryDiffer(bit_size=64)
    
    # Original: xor eax, eax (31 c0) + ret (c3)
    orig = b"\x31\xC0\xC3\x90"
    # Patched: mov eax, 1 (b8 01 00 00 00)
    patched = b"\xB8\x01\x00\x00\x00"
    
    diffs = differ.diff_buffers(orig, patched, base_address=0x140001000)
    assert len(diffs) >= 1
    assert diffs[0]["address"] == "0x140001000"
    assert diffs[0]["orig_hex"] != diffs[0]["patched_hex"]
