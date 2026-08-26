# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.targets.complex_license_vm import ComplexLicenseValidatorVM
from argus.engine.cfg import CFGBuilder

def test_cfg_construction_and_mermaid_export():
    vm = ComplexLicenseValidatorVM(seed=42)
    program = vm.generate_complex_validation_suite()
    
    cfg_builder = CFGBuilder()
    graph = cfg_builder.build_from_bytecode(program)
    
    assert len(graph.nodes) == 4
    assert graph.has_edge(10, 20)
    assert graph.has_edge(20, 30)
    assert graph.has_edge(30, 40)
    
    mermaid_doc = cfg_builder.export_mermaid()
    assert "flowchart TD" in mermaid_doc
    assert "State_10" in mermaid_doc
    assert "State_40" in mermaid_doc
