# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Formal AI Dataset Synthesizer for Neural De-obfuscation & LLM Fine-Tuning.
Generates verified pairs of [Obfuscated Representation -> Clean Decompiled C Code] in JSONL format.
"""
import json
import random
from typing import List, Dict, Any
from ..targets.mba_generator import MBAGenerator
from ..engine.simplifier import MBASimplifier
from ..engine.codegen import CCodeGenerator

class AIDatasetGenerator:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.mba_gen = MBAGenerator(seed=seed)
        self.simplifier = MBASimplifier(bit_size=32)
        self.codegen = CCodeGenerator(function_name="deobfuscated_target")

    def generate_sample(self, sample_id: int) -> Dict[str, Any]:
        """
        Generates a single formally verified training instance.
        """
        op_type = self.rng.choice(["ADD_MBA", "XOR_MBA", "COMPLEX_MIX"])
        var_a, var_b = "a", "b"

        if op_type == "ADD_MBA":
            obf_expr_str, ground_truth = self.mba_gen.generate_linear_mba_add(var_a, var_b)
        elif op_type == "XOR_MBA":
            obf_expr_str, ground_truth = self.mba_gen.generate_linear_mba_xor(var_a, var_b)
        else:
            # Complex combination
            part1, _ = self.mba_gen.generate_linear_mba_add(var_a, var_b)
            part2, _ = self.mba_gen.generate_linear_mba_xor(var_a, var_b)
            obf_expr_str = f"({part1}) ^ ({part2})"
            ground_truth = f"({var_a} + {var_b}) ^ ({var_a} ^ {var_b})"

        # SMT Verification
        z3_ast = self.simplifier.parse_python_mba_to_z3(obf_expr_str, (var_a, var_b))
        simplified_ast, is_valid = self.simplifier.simplify_and_verify(z3_ast)
        c_code = self.codegen.generate_c_function(simplified_ast, input_params=[var_a, var_b])

        return {
            "id": f"sample_{sample_id:06d}",
            "type": op_type,
            "obfuscated_expression": obf_expr_str,
            "ground_truth": ground_truth,
            "smt_verified": is_valid,
            "recovered_c_source": c_code,
            "instruction": "De-obfuscate the following arithmetic expression into clean canonical C code.",
            "prompt": f"Input Obfuscated Logic: {obf_expr_str}",
            "response": c_code
        }

    def export_jsonl(self, count: int, output_filepath: str) -> List[Dict[str, Any]]:
        """
        Synthesizes N samples and exports directly to a JSONL dataset file.
        """
        samples = [self.generate_sample(i) for i in range(count)]
        with open(output_filepath, "w", encoding="utf-8") as f:
            for s in samples:
                f.write(json.dumps(s) + "\n")
        return samples
