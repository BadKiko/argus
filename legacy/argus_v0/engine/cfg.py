# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Control Flow Graph (CFG) Construction & DOT/Mermaid Graph Exporter.
Allows visual inspection of flattened and de-flattened basic blocks.
"""
from typing import List, Dict, Set, Tuple
import networkx as nx
from ..targets.complex_license_vm import VMBytecodeInstr, AdvancedVMOpcode

class CFGBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_from_bytecode(self, bytecode: List[VMBytecodeInstr]) -> nx.DiGraph:
        """
        Builds a Directed Graph (CFG) from flattened VM instruction streams.
        """
        self.graph.clear()
        
        # Group by State ID
        state_blocks: Dict[int, List[VMBytecodeInstr]] = {}
        for instr in bytecode:
            state_blocks.setdefault(instr.state_id, []).append(instr)

        # Create Nodes
        for state_id, instrs in state_blocks.items():
            opcodes_summary = [i.opcode for i in instrs if not i.is_junk]
            label = f"State_{state_id}\n(Inst: {len(instrs)}, Clean: {len(opcodes_summary)})"
            self.graph.add_node(state_id, label=label, size=len(instrs))

        # Create Dispatcher & State Edges
        for state_id, instrs in state_blocks.items():
            for instr in instrs:
                if instr.opcode == AdvancedVMOpcode.VM_UPDATE_STATE:
                    target_state = instr.arg
                    if target_state in state_blocks:
                        self.graph.add_edge(state_id, target_state, type="transition")

        return self.graph

    def export_mermaid(self) -> str:
        """
        Exports the reconstructed CFG to Mermaid diagram syntax for markdown rendering.
        """
        lines = ["flowchart TD"]
        for node in self.graph.nodes():
            label = self.graph.nodes[node].get("label", f"State_{node}").replace("\n", " ")
            lines.append(f'    State_{node}["{label}"]')
            
        for u, v in self.graph.edges():
            lines.append(f"    State_{u} --> State_{v}")
            
        return "\n".join(lines)
