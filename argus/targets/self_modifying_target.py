# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Self-Modifying / JIT Unpacking Target.
Encrypts code payload on disk and dynamically decrypts to an executable page at runtime.
"""
from typing import Tuple

class SelfModifyingTarget:
    def __init__(self, key: int = 0xAA):
        self.xor_key = key
        # Plaintext payload: MOV EAX, 0x1337; RET (b"\xb8\x37\x13\x00\x00\xc3")
        self.plaintext_code = b"\xb8\x37\x13\x00\x00\xc3"
        self.encrypted_payload = bytes([b ^ self.xor_key for b in self.plaintext_code])

    def decrypt_in_memory(self) -> bytes:
        """Simulates runtime decryptor routine."""
        return bytes([b ^ self.xor_key for b in self.encrypted_payload])
