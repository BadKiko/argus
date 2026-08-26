# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Polymorphic Metamorphic Virtual Machine Target.
Dynamic opcode mapping where bytecodes change per instance.
"""
from typing import Dict, Tuple, List, Callable
import random

class PolymorphicVMTarget:
    def __init__(self, seed: int = 1337):
        self.rng = random.Random(seed)
        # Randomize opcode IDs per instance
        opcodes = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]
        self.rng.shuffle(opcodes)
        self.OP_ADD = opcodes[0]
        self.OP_SUB = opcodes[1]
        self.OP_XOR = opcodes[2]
        self.OP_AND = opcodes[3]
        self.OP_OR  = opcodes[4]
        self.OP_IMM = opcodes[5]
        self.OP_RET = opcodes[6]

    def get_opcode_map(self) -> Dict[int, str]:
        return {
            self.OP_ADD: "V_ADD",
            self.OP_SUB: "V_SUB",
            self.OP_XOR: "V_XOR",
            self.OP_AND: "V_AND",
            self.OP_OR:  "V_OR",
            self.OP_IMM: "V_IMM",
            self.OP_RET: "V_RET",
        }

    def generate_sample_bytecode(self, secret_key: int = 0x1337BEEF) -> bytes:
        """Generates bytecode: PUSH secret; PUSH 0x42; XOR; RET"""
        bc = bytearray()
        bc.append(self.OP_IMM)
        bc.extend(secret_key.to_bytes(4, "little"))
        bc.append(self.OP_IMM)
        bc.extend((0x42).to_bytes(4, "little"))
        bc.append(self.OP_XOR)
        bc.append(self.OP_RET)
        return bytes(bc)
