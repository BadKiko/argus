# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Static Single Assignment (SSA) Optimization Pipeline.
Performs compiler-level canonicalization on de-virtualized IR:
1. Global Value Numbering (GVN) for redundant expression elimination.
2. Sparse Constant Folding.
3. Dead Code Elimination (DCE).
"""
from typing import List, Dict, Tuple, Any, Optional

class SSAInstruction:
    def __init__(self, dest: str, op: str, args: List[str]):
        self.dest = dest
        self.op = op
        self.args = args

    def to_dict(self) -> Dict[str, Any]:
        return {"dest": self.dest, "op": self.op, "args": self.args}

    def __repr__(self):
        return f"{self.dest} = {self.op}({', '.join(self.args)})"

class SSAOptimizer:
    def __init__(self):
        pass

    def optimize_ir_block(self, instructions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs full GVN, Constant Folding, and DCE optimization passes on an IR block.
        """
        value_table: Dict[Tuple[str, Tuple[str, ...]], str] = {}
        const_table: Dict[str, int] = {}
        optimized: List[Dict[str, Any]] = []

        # Pass 1: Constant Folding & GVN
        for instr in instructions:
            dest = instr.get("dest", "")
            op = instr.get("op", "")
            args = instr.get("args", [])

            # Check if operands are known constants
            if op == "CONST":
                val = int(args[0], 0) if isinstance(args[0], str) else int(args[0])
                const_table[dest] = val
                optimized.append(instr)
                continue

            # Evaluate arithmetic if all args are constant
            if op in ["ADD", "SUB", "XOR"] and len(args) == 2:
                arg0, arg1 = args[0], args[1]
                if arg0 in const_table and arg1 in const_table:
                    v0, v1 = const_table[arg0], const_table[arg1]
                    if op == "ADD": res = (v0 + v1) & 0xFFFFFFFF
                    elif op == "SUB": res = (v0 - v1) & 0xFFFFFFFF
                    elif op == "XOR": res = (v0 ^ v1) & 0xFFFFFFFF
                    const_table[dest] = res
                    optimized.append({"dest": dest, "op": "CONST", "args": [hex(res)]})
                    continue

            # GVN Expression key
            expr_key = (op, tuple(args))
            if expr_key in value_table:
                # Value numbering match! Replace with existing value
                existing_var = value_table[expr_key]
                optimized.append({"dest": dest, "op": "COPY", "args": [existing_var]})
            else:
                value_table[expr_key] = dest
                optimized.append(instr)

        # Pass 2: Dead Code Elimination (DCE)
        used_vars = set()
        # Find last instruction (assumed live sink / return)
        if optimized:
            used_vars.update(optimized[-1].get("args", []))

        # Backward collection of live dependencies
        for instr in reversed(optimized[:-1]):
            dest = instr.get("dest", "")
            if dest in used_vars:
                used_vars.update(instr.get("args", []))

        # Filter out unused assignments (except side-effecting or root vars)
        final_ir = [
            instr for instr in optimized
            if instr.get("dest", "") in used_vars or instr == optimized[-1] or instr.get("op") == "RETURN"
        ]

        return final_ir
