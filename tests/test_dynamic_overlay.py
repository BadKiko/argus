# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.frontend.dynamic_overlay import DynamicOverlayEngine, MemoryPage
from argus.targets.self_modifying_target import SelfModifyingTarget

def test_dynamic_overlay_wx_page_capture():
    target = SelfModifyingTarget(key=0x7F)
    engine = DynamicOverlayEngine()
    
    # 1. Allocate writable page and write encrypted payload
    page = engine.allocate_page(0x140001000, size=4096, perms=MemoryPage.PAGE_READ | MemoryPage.PAGE_WRITE)
    engine.write_memory(0x140001000, target.encrypted_payload)

    # 2. Simulate runtime decryptor
    decrypted = target.decrypt_in_memory()
    engine.write_memory(0x140001000, decrypted)

    # 3. Transition to PAGE_EXECUTE (W^X trigger)
    snapshot = engine.protect_memory(0x140001000, MemoryPage.PAGE_READ | MemoryPage.PAGE_EXECUTE)

    assert snapshot is not None
    assert snapshot["base_addr"] == 0x140001000
    assert snapshot["data"][:len(decrypted)] == target.plaintext_code
    assert engine.read_memory(0x140001000, len(decrypted)) == target.plaintext_code
