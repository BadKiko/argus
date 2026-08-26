# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import os
import sys
from argus.frontend.pe_parser import PEParser

def test_pe_parser_on_system_binary():
    # Use real binary from System32 (e.g. cmd.exe or notepad.exe)
    test_exe = r"C:\Windows\System32\cmd.exe"
    assert os.path.exists(test_exe)

    parser = PEParser(test_exe)
    info = parser.get_basic_info()
    sections = parser.get_sections()
    code_bytes = parser.extract_text_section_bytes()

    assert info["is_exe"] is True
    assert info["number_of_sections"] > 0
    assert len(sections) > 0
    assert code_bytes is not None
    assert len(code_bytes) > 0
    parser.close()
