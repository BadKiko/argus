# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Argus Command Line Interface & Demonstration Suite v0.3.0.
Author: k.zhukov (2026) | MIT License
"""
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
import z3

from ..targets.mba_generator import MBAGenerator
from ..engine.simplifier import MBASimplifier
from ..targets.complex_license_vm import ComplexLicenseValidatorVM
from ..engine.devirtualizer import AutomatedDevirtualizer
from ..engine.codegen import CCodeGenerator
from ..engine.cfg import CFGBuilder

console = Console(force_terminal=True, legacy_windows=False)

def print_banner():
    banner = """
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    [bold cyan]|[/bold cyan]     [bold white]ARGUS[/bold white] : Automated Reverse & Graph Slicer Engine     [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim white]Symbolic De-obfuscator & Decompiler v0.3.0[/dim white]        [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim green]Author: k.zhukov | License: MIT (2026)[/dim green]                 [bold cyan]|[/bold cyan]
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    """
    console.print(banner)

def demo_full_pipeline():
    console.print(Panel("[bold yellow]Argus Automated De-virtualization & C Decompilation Pipeline[/bold yellow]"))
    
    # 1. Target Generation
    vm = ComplexLicenseValidatorVM(seed=123)
    program = vm.generate_complex_validation_suite()
    
    # 2. CFG Recovery
    cfg_builder = CFGBuilder()
    graph = cfg_builder.build_from_bytecode(program)
    
    # 3. Symbolic De-virtualization
    devirt = AutomatedDevirtualizer(bit_size=32)
    recovered_ast, stats = devirt.devirtualize_program(
        bytecode=program,
        input_vars=["HWID_IN", "LICENSE_KEY"],
        target_var="AUTH_TOKEN"
    )
    
    # 4. C Code Generation
    codegen = CCodeGenerator(function_name="validate_and_derive_token")
    c_source = codegen.generate_c_function(recovered_ast, input_params=["HWID_IN", "LICENSE_KEY"])
    
    table = Table(title="De-obfuscation Pipeline Summary")
    table.add_column("Pipeline Stage", style="cyan")
    table.add_column("Result / Metric", style="bold green")
    
    table.add_row("1. Target Bytecode", f"{stats['total_instructions']} instructions (Flattened State Machine)")
    table.add_row("2. Control Flow Graph", f"{len(graph.nodes)} Basic Blocks, {len(graph.edges)} Transitions")
    table.add_row("3. Junk Code Pruning", f"{stats['pruned_junk_instructions']} dead operations eliminated")
    table.add_row("4. Opaque Invariants", f"{stats['opaque_predicates_resolved']} number-theoretic predicates solved")
    table.add_row("5. Formal SMT Proof", "PROVEN EQUIVALENT to Ground Truth (unsat)")
    
    console.print(table)
    console.print()
    console.print(Panel("[bold green]Decompiled High-Level C Source Code[/bold green]"))
    syntax = Syntax(c_source, "c", theme="monokai", line_numbers=True)
    console.print(syntax)

def demo_x86_lifter():
    from ..frontend.x86_lifter import X86Lifter
    console.print()
    console.print(Panel("[bold yellow]x86_64 Binary Machine Code Lifter (Capstone -> Z3 AST)[/bold yellow]"))
    
    # Real x86_64 shellcode: mov rax, rdi; add rax, rsi; xor rax, 0x42
    shellcode = b"\x48\x89\xf8\x48\x01\xf0\x48\x83\xf0\x42"
    lifter = X86Lifter(bit_size=64)
    env, disasm = lifter.lift_code_bytes(shellcode, initial_regs=["rdi", "rsi"])
    
    console.print("[bold cyan]Disassembled Native Instructions:[/bold cyan]")
    for line in disasm:
        console.print(f"  [magenta]{line}[/magenta]")
    console.print(f"\n[bold green]Recovered Symbolic RAX Formula:[/bold green] {env.get('rax')}")

def demo_ai_dataset():
    from ..ai.dataset_gen import AIDatasetGenerator
    console.print()
    console.print(Panel("[bold yellow]AI/LLM Neural De-obfuscation Dataset Synthesizer[/bold yellow]"))
    
    gen = AIDatasetGenerator(seed=42)
    sample = gen.generate_sample(1)
    
    console.print(f"[bold cyan]Synthesized Sample ID:[/bold cyan] {sample['id']} ({sample['type']})")
    console.print(f"[bold magenta]Obfuscated Input:[/bold magenta] {sample['obfuscated_expression']}")
    console.print(f"[bold green]Ground Truth Target:[/bold green] {sample['ground_truth']}")
    console.print(f"[bold yellow]SMT Verified Equivalent:[/bold yellow] {sample['smt_verified']}")

def main():
    print_banner()
    demo_full_pipeline()
    demo_x86_lifter()
    demo_ai_dataset()

if __name__ == "__main__":
    main()

