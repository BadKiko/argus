# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.iat_reconstructor import IATReconstructor

def test_iat_reconstructor_api_hash_resolution():
    recon = IATReconstructor()

    # Known hashes
    h1 = 0xEC0E4E8E # LoadLibraryA
    h2 = 0x7C0DFCAA # GetProcAddress

    assert recon.resolve_api_hash(h1) == "kernel32.dll!LoadLibraryA"
    assert recon.resolve_api_hash(h2) == "kernel32.dll!GetProcAddress"

    # Scan constants list
    matches = recon.scan_for_api_hashes([0x12345678, h1, 0x99999999, h2])
    assert len(matches) == 2
    assert matches[0]["api"] == "kernel32.dll!LoadLibraryA"
    assert matches[1]["api"] == "kernel32.dll!GetProcAddress"
