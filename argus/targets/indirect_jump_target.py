# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Indirect Jump Table Target.
"""
class IndirectJumpTarget:
    def __init__(self):
        self.table_base = 0x140008000
        self.targets = [
            0x140001010,
            0x140001020,
            0x140001030,
            0x140001040
        ]
        self.table_bytes = bytearray()
        for t in self.targets:
            self.table_bytes.extend(t.to_bytes(8, "little"))
