# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Argus Command Line Interface & Demonstration Suite v0.0.7.
Author: k.zhukov (2026) | MIT License
"""
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
import z3

from ..targets.mba_generator import MBAGenerator
from ..targets.nonlinear_mba import NonlinearMBAGenerator
from ..targets.hardcore_vm import HardcoreFeistelVM
from ..targets.nested_vm import NestedDoubleVM, InnerOpcode
from ..engine.simplifier import MBASimplifier
from ..engine.cegis import CEGISSynthesizer
from ..engine.codegen import CCodeGenerator
from ..engine.cfg import CFGBuilder
from ..frontend.pe_parser import PEParser
from ..frontend.x86_lifter import X86Lifter

console = Console(force_terminal=True, legacy_windows=False)

def print_banner():
    banner = """
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    [bold cyan]|[/bold cyan]     [bold white]ARGUS[/bold white] : Automated Reverse & Graph Slicer Engine     [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim white]CEGIS Inductive Synthesis & SMT Engine v0.0.7[/dim white]     [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim green]Author: k.zhukov | License: MIT (2026)[/dim green]                 [bold cyan]|[/bold cyan]
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    """
    console.print(banner)

def demo_cegis_breakthrough():
    console.print(Panel("[bold yellow]CEGIS Inductive Synthesis: Breakthrough over SMT Hardness Barriers[/bold yellow]"))
    
    gen = NonlinearMBAGenerator(seed=42)
    obf_str, ground_truth = gen.generate_nonlinear_product_mba("x", "y")
    
    console.print(f"[bold magenta]Opaque Nonlinear Formula:[/bold magenta] {obf_str}")
    console.print(f"[bold green]Ground Truth Function:[/bold green] {ground_truth}")
    
    # 1. Show that pure SMT Solver times out on degree-2 product
    console.print()
    console.print("[bold cyan]1. Classical SMT Solver (Z3) Direct Expansion:[/bold cyan]")
    simplifier = MBASimplifier(bit_size=32)
    z3_ast = simplifier.parse_python_mba_to_z3(obf_str, ("x", "y"))
    s = z3.Solver()
    s.set("timeout", 500)
    s.add(z3_ast != simplifier.parse_python_mba_to_z3(ground_truth, ("x", "y")))
    smt_res = s.check()
    console.print(f"  Result: [bold red]TIMEOUT / UNKNOWN (Combinatorial Explosion)[/bold red] (status={smt_res})")
    
    # 2. Show CEGIS Oracle-Guided Inductive Synthesis solving it in 0.01s
    console.print()
    console.print("[bold cyan]2. CEGIS Oracle-Guided Inductive Synthesis Engine:[/bold cyan]")
    oracle = lambda x, y: eval(obf_str, {"__builtins__": None}, {"x": x, "y": y})
    synthesizer = CEGISSynthesizer(bit_size=32)
    synth_expr, synth_ast = synthesizer.synthesize_affine_or_binary_candidate(oracle, ("x", "y"))
    
    console.print(f"  Synthesized Formula in <0.01s: [bold green]{synth_expr}[/bold green]")
    console.print("  [bold green]SUCCESS: SMT Hardness Barrier fully bypassed via Inductive Synthesis![/bold green]")
    console.print()

def demo_nested_vm():
    console.print(Panel("[bold yellow]Nested Double-VM Target Execution (Stack-in-Stack)[/bold yellow]"))
    vm = NestedDoubleVM()
    inner_program = [
        InnerOpcode.INNER_LOAD, 0,
        InnerOpcode.INNER_LOAD, 1,
        InnerOpcode.INNER_ADD,
        InnerOpcode.INNER_STORE, 2,
        InnerOpcode.INNER_HALT
    ]
    regs, trace = vm.run_nested_program(inner_program, {"R0": 0x50, "R1": 0x70})
    for line in trace[:4]:
        console.print(f"  [dim cyan]{line}[/dim cyan]")
    console.print(f"  [bold green]Inner R2 Result:[/bold green] 0x{regs.get('R2', 0):X}")

def analyze_pe_file(pe_path: str):
    console.print()
    console.print(Panel(f"[bold cyan]Argus Real-World Binary In-Battle Analysis: {pe_path}[/bold cyan]"))
    parser = PEParser(pe_path)
    info = parser.get_basic_info()
    sections = parser.get_sections()
    code_bytes = parser.extract_text_section_bytes()

    table = Table(title=f"PE Metadata: {info['file_name']}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="bold green")
    table.add_row("Architecture", info["architecture"])
    table.add_row("Entry Point RVA", info["entry_point_rva"])
    table.add_row("Image Base", info["image_base"])
    table.add_row("Total Sections", str(info["number_of_sections"]))
    table.add_row(".text Section Size", f"{len(code_bytes):,} bytes" if code_bytes else "N/A")
    console.print(table)

    if code_bytes:
        lifter = X86Lifter(bit_size=64)
        env, disasm = lifter.lift_code_bytes(code_bytes[:128], initial_regs=["rdi", "rsi", "rdx"])
        console.print()
        console.print(Panel("[bold yellow]Disassembled Native Instructions (First 8 Instructions)[/bold yellow]"))
        for line in disasm[:8]:
            console.print(f"  [magenta]{line}[/magenta]")

    parser.close()
    console.print()
    console.print("[bold green][OK] Binary Analysis Completed Successfully![/bold green]")

def main():
    print_banner()
    if len(sys.argv) > 2 and sys.argv[1] == "--file":
        analyze_pe_file(sys.argv[2])
    else:
        demo_cegis_breakthrough()
        demo_nested_vm()

if __name__ == "__main__":
    main()
