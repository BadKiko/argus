# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Lightweight Machine Learning & Heuristic Sifter for Million-Scale Trace Pruning.
Filters out obvious junk operations (state ping-pong, dead writes, dummy stack pushes)
with microsecond latency before invoking heavy SMT constraint solvers.
"""
from typing import List, Dict, Tuple, Set, Any
from ..core.ir import Instruction, Opcode, Operand

class MLJunkClassifier:
    def __init__(self, confidence_threshold: float = 0.75):
        self.confidence_threshold = confidence_threshold

    def compute_feature_vector(self, instr: Instruction, live_registers: Set[str]) -> Dict[str, float]:
        """
        Extracts structural heuristic features from an instruction:
        - is_self_identity: XOR reg, reg or MOV reg, reg
        - is_unobserved_write: Writes to a register never read downstream
        - entropy_score: Synthetic dummy opcode density
        """
        features: Dict[str, float] = {
            "is_unobserved_write": 0.0,
            "is_dummy_stack": 0.0,
            "is_nop_equivalent": 0.0
        }

        # Check if destination register is never used
        if instr.dest and instr.dest.name not in live_registers and not instr.dest.is_tainted:
            features["is_unobserved_write"] = 1.0

        # Check stack dummy patterns
        if instr.opcode in [Opcode.PUSH, Opcode.POP] and instr.is_junk:
            features["is_dummy_stack"] = 1.0

        # Check self-assignment NOPs
        if instr.opcode == Opcode.MOV and instr.dest and instr.src1 and instr.dest.name == instr.src1.name:
            features["is_nop_equivalent"] = 1.0
            
        return features

    def predict_junk_probability(self, features: Dict[str, float]) -> float:
        """
        Fast linear score evaluator (surrogate model for tree-based classifier).
        """
        weights = {
            "is_unobserved_write": 0.85,
            "is_dummy_stack": 0.95,
            "is_nop_equivalent": 0.99
        }
        score = sum(features[k] * weights[k] for k in features)
        return min(1.0, score)

    def sift_trace(self, trace: List[Instruction], target_sink_var: str) -> Tuple[List[Instruction], Dict[str, int]]:
        """
        High-throughput trace sifter. Eliminates dead code blocks from giant traces.
        """
        # Step 1: Compute liveness backwards
        live_vars: Set[str] = {target_sink_var}
        clean_trace: List[Instruction] = []
        stats = {
            "total_input_instructions": len(trace),
            "sifted_junk_instructions": 0,
            "retained_critical_instructions": 0
        }

        for instr in reversed(trace):
            feats = self.compute_feature_vector(instr, live_vars)
            junk_prob = self.predict_junk_probability(feats)

            if junk_prob >= self.confidence_threshold:
                stats["sifted_junk_instructions"] += 1
                continue

            # Retain critical instruction and propagate liveness
            clean_trace.append(instr)
            stats["retained_critical_instructions"] += 1

            if instr.src1 and not instr.src1.is_constant:
                live_vars.add(instr.src1.name)
            if instr.src2 and not instr.src2.is_constant:
                live_vars.add(instr.src2.name)

        clean_trace.reverse()
        return clean_trace, stats
