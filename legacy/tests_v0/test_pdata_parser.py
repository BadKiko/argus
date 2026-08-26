# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.frontend.pdata_parser import PDataParser
from argus.targets.pdata_mock_target import PDataMockTarget

def test_pdata_parser_runtime_function_catalog():
    target = PDataMockTarget()
    parser = PDataParser()

    entries = parser.parse_pdata_raw(bytes(target.pdata_bytes))

    assert len(entries) == 5
    assert entries[0].begin_rva == 0x1000
    assert entries[0].end_rva == 0x1050
    assert entries[0].size == 0x50

    # Lookup function containing RVA 0x1150 (falls in function 3: 0x1120 - 0x1200)
    match = parser.get_function_at_rva(entries, 0x1150)
    assert match is not None
    assert match["begin_rva"] == hex(0x1120)
    assert match["end_rva"] == hex(0x1200)
