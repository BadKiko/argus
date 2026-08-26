# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.devirtualizer_v2 import AutomatedDevirtualizer, VMHandlerSynthesizer, VMOpcodeType
from argus.targets.polymorphic_vm_target import PolymorphicVMTarget

def test_automated_devirtualizer_v2_synthesis():
    target = PolymorphicVMTarget(seed=42)
    opcode_map = target.get_opcode_map()
    bytecode = target.generate_sample_bytecode(secret_key=0xDEADBEEF)

    # 1. Synthesize binary handler semantics
    synth = VMHandlerSynthesizer()
    op_type, _ = synth.synthesize_binary_handler(lambda a, b: (a ^ b) & 0xFFFFFFFF)
    assert op_type == VMOpcodeType.V_XOR

    # 2. De-virtualize bytecode into clean IR stream
    devirt = AutomatedDevirtualizer()
    ir_stream = devirt.devirtualize_bytecode_stream(bytecode, opcode_map)

    assert len(ir_stream) == 4
    assert ir_stream[0]["type"] == "PUSH_IMM"
    assert ir_stream[0]["value"] == "0xdeadbeef"
    assert ir_stream[1]["type"] == "PUSH_IMM"
    assert ir_stream[1]["value"] == "0x42"
    assert ir_stream[2]["type"] == "V_XOR"
    assert ir_stream[3]["type"] == "RETURN"
