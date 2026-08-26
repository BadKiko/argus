# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.abstract_interp import LoopSummarizer, Interval
from argus.targets.loop_heavy_target import LoopHeavyTarget

def test_abstract_interp_loop_summarization():
    target = LoopHeavyTarget(iterations=1_000_000, init=0x1337, step=7)
    summarizer = LoopSummarizer()

    # Summarize in O(1) time
    res = summarizer.summarize_linear_induction_loop(
        init_val=target.init,
        step_val=target.step,
        iterations=target.iterations
    )

    expected_val = target.concrete_execute()
    assert int(res["final_value"], 16) == expected_val
    assert res["is_closed_form"] is True
