# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import os
import json
from argus.ai.dataset_gen import AIDatasetGenerator

def test_ai_dataset_generation(tmp_path):
    gen = AIDatasetGenerator(seed=123)
    dataset_file = os.path.join(tmp_path, "train_dataset.jsonl")
    
    samples = gen.export_jsonl(count=20, output_filepath=dataset_file)
    
    assert len(samples) == 20
    assert os.path.exists(dataset_file)
    
    with open(dataset_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 20
        first_item = json.loads(lines[0])
        assert "obfuscated_expression" in first_item
        assert "recovered_c_source" in first_item
        assert first_item["smt_verified"] is True
