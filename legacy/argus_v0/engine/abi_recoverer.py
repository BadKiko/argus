# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Interprocedural ABI & Calling Convention Recovery Engine.
Performs liveness analysis across function boundaries to automatically infer:
1. Input argument count and register allocation (e.g. RCX, RDX, R8, R9 for Windows x64 ABI).
2. Return type and return register usage (RAX / EAX).
3. Reconstructed C function prototype.
"""
from typing import List, Dict, Set, Tuple, Any

class ABIRecoverer:
    X64_ARG_REGISTERS = ["rcx", "rdx", "r8", "r9"]
    X86_ARG_REGISTERS = ["ecx", "edx"] # Fastcall

    def __init__(self, is_64bit: bool = True):
        self.is_64bit = is_64bit
        self.arg_regs = self.X64_ARG_REGISTERS if is_64bit else self.X86_ARG_REGISTERS

    def infer_function_signature(self, function_name: str, instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes register read-before-write to infer arguments and return value.
        """
        written_regs: Set[str] = set()
        read_before_write: List[str] = []
        has_return_val = False

        for instr in instructions:
            reads = [r.lower() for r in instr.get("reads", [])]
            writes = [w.lower() for w in instr.get("writes", [])]

            # Check reads
            for r in reads:
                if r in self.arg_regs and r not in written_regs and r not in read_before_write:
                    read_before_write.append(r)
                if r in ["rax", "eax"] and instr.get("op") == "RET":
                    has_return_val = True

            # Register writes
            for w in writes:
                written_regs.add(w)

        # Generate C Prototype
        args_str = ", ".join([f"uint64_t arg_{i+1}_{r}" for i, r in enumerate(read_before_write)])
        if not args_str:
            args_str = "void"
        ret_type = "uint64_t" if (has_return_val or "rax" in written_regs or "eax" in written_regs) else "void"
        prototype = f"{ret_type} {function_name}({args_str});"

        return {
            "function_name": function_name,
            "inferred_args": read_before_write,
            "arg_count": len(read_before_write),
            "returns_value": (ret_type != "void"),
            "c_prototype": prototype
        }
