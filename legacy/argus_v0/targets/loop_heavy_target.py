# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Loop-Heavy Cryptographic Counter Target.
Iterates a linear counter 1,000,000 times.
"""
class LoopHeavyTarget:
    def __init__(self, iterations: int = 1_000_000, init: int = 0x1337, step: int = 7):
        self.iterations = iterations
        self.init = init
        self.step = step

    def concrete_execute(self) -> int:
        val = self.init
        for _ in range(self.iterations):
            val = (val + self.step) & 0xFFFFFFFF
        return val
