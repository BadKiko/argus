# ARGUS: Automated Reverse & Graph Slicer Engine
### Deep Graph Neural Network (GNN) Sifter, Advanced VM De-virtualizer & High-Throughput Binary Suite

[![Version](https://img.shields.io/badge/version-v0.3.2-blue.svg)](https://github.com/BadKiko/argus)
[![Tests](https://img.shields.io/badge/tests-44%2F44%20passed-brightgreen.svg)](https://github.com/BadKiko/argus)
[![GPU](https://img.shields.io/badge/GPU%20Training-RTX%205070%20Ti-orange.svg)](https://github.com/BadKiko/argus)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Author](https://img.shields.io/badge/author-k.zhukov-lightgrey.svg)](https://github.com/BadKiko/argus)

---

## 1. Executive Summary

**Argus** is an automated binary analysis, symbolic de-obfuscation, and re-engineering framework. Modern commercial and synthetic binary protections (Control Flow Flattening, Cryptographic Virtual Machines, Degree-$k$ Mixed Boolean-Arithmetic, and Opaque Predicates) cause classical SMT solvers (Z3) to suffer from the **Combinatorial State Space Explosion Barrier** ($O(2^n)$ time complexity), timing out on graphs with more than 50–100 basic blocks.

Argus provides a streaming, memory-mapped pipeline capable of ingesting large-scale (100–500+ MB) Windows PE binaries without memory exhaustion:
1. **Memory-Mapped Streaming Loader (`argus.frontend.mmap_loader`):** On-demand paging and RVA-to-offset reading via `mmap` for low-memory footprint.
2. **x64 `.pdata` Function Boundary Extractor (`argus.frontend.pdata_parser`):** Instantly catalogs function entry/exit addresses via `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (`RUNTIME_FUNCTION`).
3. **Multi-Function Forest GPU Batch Sifter (`argus.ai.batch_sifter`):** Evaluates hundreds of function CFG subgraphs concurrently on CUDA.
4. **High-Level Subsystem & WinAPI Mock Registry (`argus.engine.api_mock`):** Deterministic mock responses for WinAPI/DirectX calls to ensure uninterrupted symbolic analysis.
5. **CPU Emulation Sandbox & OEP Detector (`argus.engine.emulator`):** Emulates unpacking stubs and automatically detects Original Entry Point (OEP) transitions.
6. **Recursive Descent Disassembler (`argus.frontend.recursive_disasm`):** Follows control flow branches, robustly bypassing overlapping instructions (`JMP $+1`) and dead byte traps.
7. **Indirect Branch & Jump Table Resolver (`argus.engine.indirect_resolver`):** Resolves computed switch tables (`JMP [Table + RAX*8]`) into concrete CFG branch targets.
8. **Dynamic API Hash Resolver & IAT Restorer (`argus.engine.iat_reconstructor`):** Automatically maps API hashes (ROR13/CRC32) to reconstruct Import Address Tables.
9. **Automated VM Architecture & Handler Synthesizer (`argus.engine.devirtualizer_v2`):** Extracts `VIP`/`VSP` registers and synthesizes polymorphic VM bytecode handlers via CEGIS over $\mathbb{Z}_{2^{32}}$ into clean micro-IR.
10. **Exception-Driven Control Flow Reconstruction (`argus.engine.exception_cfg`):** Stitches implicit control flow edges caused by intentional hardware exceptions (`STATUS_ACCESS_VIOLATION`, `IDIV 0`) routed through Vectored Exception Handlers (VEH).
11. **Abstract Interpretation & Loop Summarizer (`argus.engine.abstract_interp`):** Computes variable bounds over the Interval Lattice and derives closed-form induction summaries for million-iteration loops in $O(1)$ time.
12. **Static Single Assignment (SSA) Optimization Pipeline (`argus.engine.ssa_optimizer`):** Performs Global Value Numbering (GVN), Constant Folding, and Dead Code Elimination (DCE) on de-obfuscated IR.

```
                              [ RAW LARGE-SCALE PE BINARY ]
                                            │
                                            ▼
                    ┌──────────────────────────────────────────────┐
                    │ 1. Memory-Mapped Streamer & .pdata Catalog   │
                    │    • On-demand mmap paging (low RAM usage)   │
                    │    • Instant x64 RUNTIME_FUNCTION extraction │
                    │    • WinAPI & DirectX High-Level Mock Stubs  │
                    └───────────────────────┬──────────────────────┘
                                            │ (Streamed Function Forest)
                                            ▼
                    ┌──────────────────────────────────────────────┐
                    │ 2. Batched ResGCN Sifter (RTX 5070 Ti)       │
                    │    • Concurrent GPU mini-batches             │
                    │    • 10 Structural Features + Message Passing│
                    │    • Result: 75% Junk & Dispatchers Pruned   │
                    └───────────────────────┬──────────────────────┘
                                            │ (Clean Structural Subgraphs)
                                            ▼
                    ┌──────────────────────────────────────────────┐
                    │ 3. Automated VM Devirtualizer & CEGIS        │
                    │    • VIP & VSP Taint Resolution              │
                    │    • Black-Box Handler Semantics Synthesis   │
                    │    • VEH / SEH Implicit Edge Stitching       │
                    └───────────────────────┬──────────────────────┘
                                            │
                                            ▼
                    ┌──────────────────────────────────────────────┐
                    │ 4. SSA Optimization & Loop Summarizer (O(1)) │
                    │    • Global Value Numbering (GVN) & DCE      │
                    │    • Interval Lattice Invariant Solving      │
                    │    • ABI & Prototype Recovery                │
                    └───────────────────────┬──────────────────────┘
                                            │
                            ┌───────────────┴───────────────┐
                            ▼                               ▼
           ┌────────────────────────────────┐ ┌───────────────────────────┐
           │ 5. Clean C Decompiler CodeGen  │ │ 6. PE Binary Patcher      │
           │    • Human-readable C source   │ │    • Safe Invariant Patch │
           │    • Fully de-virtualized code │ │    • PE Checksum Recalc   │
           └────────────────────────────────┘ └───────────────────────────┘
```

---

## 2. Empirical Scalability Benchmark

| CFG Size ($N$ Nodes) | Pure SMT (Z3 Alone) | Argus Hybrid (GNN + SMT) | Pruned Junk Nodes | Empirical Speedup |
| :---: | :---: | :---: | :---: | :---: |
| **10** | 0.288s | **0.192s** | 9 nodes (90%) | **1.5x** |
| **25** | 0.558s | **0.023s** | 20 nodes (80%) | **24.1x** |
| **50** | 1.137s | **0.042s** | 25 nodes (50%) | **27.0x** |
| **100** | **TIMEOUT (>2.0s)** | **0.110s** | 72 nodes (72%) | **> 18.1x** |
| **250** | **TIMEOUT (>2.0s)** | **0.132s** | 191 nodes (76%) | **> 15.1x** |
| **500** | **TIMEOUT (>2.0s)** | **0.168s** | 378 nodes (76%) | **> 11.9x** |
| **1000** | **TIMEOUT (>2.0s)** | **0.442s** | 754 nodes (75%) | **> 4.5x** |

---

## 3. Quick Start & Usage

### Installation
```bash
# Clone the repository
git clone https://github.com/BadKiko/argus.git
cd argus

# Install dependencies (Capstone, pefile, z3-solver, rich, pytest, torch)
pip install -r requirements.txt
```

### 1. Run Live High-Throughput Protection-Breaking Demo
```bash
python -m argus.cli.main
```

### 2. Analyze Real-World PE Binaries
```bash
python -m argus.cli.main --file angr_test_sample.exe
```

### 3. Run Scalability Benchmarks
```bash
python -m argus.engine.benchmark
```

### 4. Run Automated Test Suite (44 Unit Tests)
```bash
python -m pytest -v
```

---

## 4. Verification & Test Suite Status (44/44 Passed)

```text
tests/test_abi_recoverer.py::test_abi_recoverer_signature_inference PASSED [  2%]
tests/test_abstract_interp.py::test_abstract_interp_loop_summarization PASSED [  4%]
tests/test_api_mock.py::test_api_mock_registry_stubs PASSED              [  6%]
tests/test_assembler.py::test_x86_assembler_encodings PASSED             [  9%]
tests/test_batch_sifter.py::test_batch_forest_sifter_multi_function_pruning PASSED [ 11%]
tests/test_cegis.py::test_cegis_nonlinear_product_recovery PASSED        [ 13%]
tests/test_cegis.py::test_cegis_affine_mba_recovery PASSED               [ 15%]
tests/test_cfg.py::test_cfg_construction_and_mermaid_export PASSED       [ 18%]
tests/test_codegen.py::test_c_code_generation PASSED                     [ 20%]
tests/test_complex_vm.py::test_complex_license_vm_execution PASSED       [ 22%]
tests/test_dataset_gen.py::test_ai_dataset_generation PASSED             [ 25%]
tests/test_devirtualizer.py::test_automated_devirtualization_ground_truth PASSED [ 27%]
tests/test_devirtualizer_v2.py::test_automated_devirtualizer_v2_synthesis PASSED [ 29%]
tests/test_differ.py::test_binary_differ_output PASSED                   [ 31%]
tests/test_dynamic_overlay.py::test_dynamic_overlay_wx_page_capture PASSED [ 34%]
tests/test_emulator.py::test_cpu_sandbox_oep_detection PASSED            [ 36%]
tests/test_exception_cfg.py::test_exception_cfg_veh_edge_recovery PASSED [ 38%]
tests/test_function_scanner.py::test_function_scanner_detection PASSED   [ 40%]
tests/test_gnn_sifter.py::test_gnn_graph_sifter_pruning PASSED           [ 43%]
tests/test_hardcore_vm.py::test_hardcore_feistel_concrete_execution PASSED [ 45%]
tests/test_hardcore_vm.py::test_concolic_symbolic_unrolling PASSED       [ 47%]
tests/test_iat_reconstructor.py::test_iat_reconstructor_api_hash_resolution PASSED [ 50%]
tests/test_indirect_resolver.py::test_indirect_jump_table_resolution PASSED [ 52%]
tests/test_integrity_slicer.py::test_interlocking_integrity_invariant_solving PASSED [ 54%]
tests/test_junk_classifier.py::test_ml_junk_sifter_million_scale_simulation PASSED [ 56%]
tests/test_mba_simplifier.py::test_linear_mba_add_simplification PASSED  [ 59%]
tests/test_mba_simplifier.py::test_linear_mba_xor_simplification PASSED  [ 61%]
tests/test_mba_simplifier.py::test_opaque_predicates PASSED              [ 63%]
tests/test_mega_challenge.py::test_mega_challenge_end_to_end_solving PASSED [ 65%]
tests/test_mmap_loader.py::test_mmap_binary_loader_rva_streaming PASSED  [ 68%]
tests/test_nested_vm.py::test_nested_double_vm_execution PASSED          [ 70%]
tests/test_nonlinear_mba.py::test_nonlinear_mba_smt_hardness_barrier PASSED [ 72%]
tests/test_nonlinear_mba.py::test_affine_masked_mba_ground_truth PASSED  [ 75%]
tests/test_patcher.py::test_binary_patcher_pe_modification PASSED        [ 77%]
tests/test_path_explorer.py::test_symbolic_path_explorer_password_recovery PASSED [ 79%]
tests/test_pdata_parser.py::test_pdata_parser_runtime_function_catalog PASSED [ 81%]
tests/test_pe_parser.py::test_pe_parser_on_system_binary PASSED          [ 84%]
tests/test_recursive_disasm.py::test_recursive_descent_overlapping_resolution PASSED [ 86%]
tests/test_scoped_analyzer.py::test_scoped_analyzer_subgraph_extraction PASSED [ 88%]
tests/test_shadow_state.py::test_shadow_state_peb_and_rdtsc_determinism PASSED [ 90%]
tests/test_ssa_optimizer.py::test_ssa_optimizer_gvn_and_dce PASSED       [ 93%]
tests/test_vm_slicing.py::test_backward_slicing PASSED                   [ 95%]
tests/test_x86_lifter.py::test_x86_lifter_arithmetic_and_bitwise PASSED  [ 97%]
tests/test_xref_engine.py::test_xref_engine_string_discovery PASSED      [100%]

============================= 44 passed in 7.05s ==============================
```

---

## 5. License & Authorship

Copyright (c) 2026 **k.zhukov**  
Licensed under the **MIT License**. See [LICENSE](LICENSE) for details.\n