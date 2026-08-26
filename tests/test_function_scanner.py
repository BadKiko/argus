# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.scanner.function_scanner import FunctionScanner

def test_function_scanner_detection():
    scanner = FunctionScanner(bit_size=64)
    
    # Machine code for:
    # func1 (validator):
    #   xor eax, 0x5A
    #   cmp eax, 0x1B
    #   jz 0x06
    #   xor eax, eax
    #   ret
    #   mov eax, 1
    #   ret
    code = b"\x83\xf0\x5a\x83\xf8\x1b\x74\x03\x31\xc0\xc3\xb8\x01\x00\x00\x00\xc3"
    
    functions = scanner.scan_functions_in_bytes(code, base_address=0x1000)
    assert len(functions) >= 1
    assert any(f["has_conditional_branch"] for f in functions)
