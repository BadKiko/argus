# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Exception-Driven Control Flow Graph (SEH/VEH) Engine.
Recovers implicit control flow edges caused by intentional hardware and software exceptions
(e.g., division by zero, null dereference, UD2 invalid opcode) routed through Vectored Exception Handlers.
"""
from typing import Dict, List, Tuple, Optional, Any

class ExceptionType:
    DIVIDE_BY_ZERO = "STATUS_INTEGER_DIVIDE_BY_ZERO"
    ACCESS_VIOLATION = "STATUS_ACCESS_VIOLATION"
    ILLEGAL_INSTRUCTION = "STATUS_ILLEGAL_INSTRUCTION"

class ExceptionHandlerEntry:
    def __init__(self, handler_rva: int, exception_code: str, target_rva: int):
        self.handler_rva = handler_rva
        self.exception_code = exception_code
        self.target_rva = target_rva

class ExceptionCFGBuilder:
    def __init__(self):
        self.registered_veh: List[ExceptionHandlerEntry] = []

    def register_veh_handler(self, handler_rva: int, exception_code: str, target_rva: int):
        """Registers an active VEH handler routing table."""
        entry = ExceptionHandlerEntry(handler_rva, exception_code, target_rva)
        self.registered_veh.append(entry)

    def resolve_faulting_instruction(self, fault_rva: int, opcode_bytes: bytes) -> Optional[Dict[str, Any]]:
        """
        Determines if an instruction triggers an intentional exception and stitches the implicit CFG edge.
        """
        # Detection of division by zero (e.g. IDIV with divisor 0)
        if b"\xf7\xf9" in opcode_bytes or b"\xf7\xf8" in opcode_bytes: # idiv ecx / eax
            exc_code = ExceptionType.DIVIDE_BY_ZERO
        # Detection of UD2 invalid opcode (0x0F 0x0B)
        elif opcode_bytes.startswith(b"\x0f\x0b"):
            exc_code = ExceptionType.ILLEGAL_INSTRUCTION
        # Null pointer dereference
        elif b"\x8b\x00" in opcode_bytes or b"\x89\x00" in opcode_bytes: # mov eax, [rax] where rax == 0
            exc_code = ExceptionType.ACCESS_VIOLATION
        else:
            return None

        # Find matching registered handler
        for veh in self.registered_veh:
            if veh.exception_code == exc_code:
                return {
                    "fault_rva": hex(fault_rva),
                    "exception_type": exc_code,
                    "handler_rva": hex(veh.handler_rva),
                    "implicit_target_rva": hex(veh.target_rva),
                    "is_stitched": True
                }
        return None
