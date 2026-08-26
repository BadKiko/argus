# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import os
import tempfile
from argus.frontend.mmap_loader import MmapBinaryLoader

def test_mmap_binary_loader_rva_streaming():
    # Create temporary file with test payload
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # 4096 bytes file
        tmp.write(b"HEADER" + b"\x00" * 506 + b"TARGET_PAYLOAD_AT_OFFSET_512" + b"\x00" * 3500)
        tmp_path = tmp.name

    try:
        with MmapBinaryLoader(tmp_path) as loader:
            # Register section: .text at RVA 0x1000, raw offset 512
            loader.add_section_mapping(".text", virtual_address=0x1000, virtual_size=0x1000, raw_offset=512, raw_size=512)

            # Read via RVA
            read_bytes = loader.read_rva_bytes(0x1000, len(b"TARGET_PAYLOAD_AT_OFFSET_512"))
            assert read_bytes == b"TARGET_PAYLOAD_AT_OFFSET_512"

            # Read raw
            raw_header = loader.read_raw_bytes(0, 6)
            assert raw_header == b"HEADER"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
