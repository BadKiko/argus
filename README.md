# Argus: Automated Reverse-Engineering & Symbolic De-obfuscation Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
**Author:** k.zhukov  
**Year:** 2026

## Overview
**Argus** is an academic research framework for automated binary analysis, dynamic taint tracking (DTA), backward program slicing, mixed boolean-arithmetic (MBA) de-obfuscation, and control-flow de-virtualization using the Z3 Theorem Prover.

## Architecture
- `argus.core.ir`: Intermediate representation (IR) supporting SSA-like forms and typed operands.
- `argus.engine.smt`: Z3 SMT solver integration for formal equivalence verification and opaque predicate detection.
- `argus.engine.simplifier`: Algebraic & SMT-guided simplification of complex MBA expressions.
- `argus.engine.taint`: Dynamic taint analysis (DTA) engine for tracking information flow across registers and virtual stacks.
- `argus.engine.slicer`: Backward program slicer for dead code elimination and de-virtualization.
- `argus.engine.devirtualizer`: Automated de-virtualizer reconstructing high-level symbolic expressions from flattened VM dispatch loops.
- `argus.targets`: Synthetic benchmarks including multi-layer VM validators, control-flow flattening, and nonlinear MBA formulas.

## Installation & Testing
```bash
pip install -r requirements.txt
pytest -v
python -m argus.cli.main
```
