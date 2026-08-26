# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import os
from argus.scanner.xref_engine import XRefEngine

def test_xref_engine_string_discovery():
    src_pe = r"E:\Work\argus\angr_test_sample.exe"
    assert os.path.exists(src_pe)

    xref_engine = XRefEngine(src_pe, bit_size=64)
    strings = xref_engine.find_strings(min_length=5)
    
    assert len(strings) > 0
    # Check that strings are mapped with section and RVA
    assert "string" in strings[0]
    assert "rva" in strings[0]
    assert "section" in strings[0]
    xref_engine.close()
