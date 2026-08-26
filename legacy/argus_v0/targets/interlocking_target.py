# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Interlocking Distributed Checksum Target.
Feeds code hash directly into the application's arithmetic computation loop.
"""
class InterlockingTarget:
    def __init__(self, code_bytes: bytes = b"\x90\x90\x90\x90\xb8\x01\x00\x00\x00\xc3"):
        self.code_bytes = code_bytes
        self.expected_hash = self.compute_hash(self.code_bytes)

    def compute_hash(self, data: bytes) -> int:
        h = 0
        for b in data:
            h = ((h << 5) + h + b) & 0xFFFFFFFF
        return h

    def execute_state_step(self, user_input: int, code_current: bytes) -> int:
        h = self.compute_hash(code_current)
        # Downstream calculation is entangled with hash h
        state = (user_input * h) ^ 0x5A5A5A5A
        return state & 0xFFFFFFFF
