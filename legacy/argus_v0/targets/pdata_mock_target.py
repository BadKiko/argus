# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Synthetic x64 .pdata Exception Table Target.
Generates structured RUNTIME_FUNCTION entries for 5 simulated functions.
"""
import struct

class PDataMockTarget:
    def __init__(self):
        # 5 synthetic functions
        self.functions = [
            {"begin": 0x1000, "end": 0x1050, "unwind": 0x3000},
            {"begin": 0x1050, "end": 0x1120, "unwind": 0x3020},
            {"begin": 0x1120, "end": 0x1200, "unwind": 0x3040},
            {"begin": 0x1200, "end": 0x1380, "unwind": 0x3060},
            {"begin": 0x1380, "end": 0x1500, "unwind": 0x3080}
        ]
        
        self.pdata_bytes = bytearray()
        for fn in self.functions:
            self.pdata_bytes.extend(struct.pack("<III", fn["begin"], fn["end"], fn["unwind"]))
