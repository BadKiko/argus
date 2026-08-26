# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Argus Command Line Interface & Demonstration Suite v0.0.6.
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
from ..targets.complex_license_vm import ComplexLicenseValidatorVM
from ..engine.simplifier import MBASimplifier
from ..engine.devirtualizer import AutomatedDevirtualizer
from ..engine.concolic import ConcolicPathEngine
from ..engine.codegen import CCodeGenerator
from ..engine.cfg import CFGBuilder
from ..frontend.pe_parser import PEParser

console = Console(force_terminal=True, legacy_windows=False)

def print_banner():
    banner = """
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    [bold cyan]|[/bold cyan]     [bold white]ARGUS[/bold white] : Automated Reverse & Graph Slicer Engine     [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim white]Symbolic De-obfuscator & SMT Verifier v0.0.6[/dim white]     [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim green]Author: k.zhukov | License: MIT (2026)[/dim green]                 [bold cyan]|[/bold cyan]
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    """
    console.print(banner)

def demo_nonlinear_frontier():
    console.print()
    console.print(Panel("[bold yellow]Frontier Demo 1: Nonlinear Polynomial MBA (High-Degree SMT Hardness)[/bold yellow]"))
    
    gen = NonlinearMBAGenerator(seed=42)
    obf_prod, truth_prod = gen.generate_nonlinear_product_mba("x", "y")
    obf_affine, truth_affine = gen.generate_affine_masked_mba("x", "y")
    
    table = Table(title="Nonlinear MBA SMT Solver Verification")
    table.add_column("Complexity Class", style="cyan")
    table.add_column("Expanded Nonlinear Formula", style="magenta")
    table.add_column("Ground Truth", style="green")
    table.add_column("SMT Proof", style="bold green")

    simplifier = MBASimplifier(bit_size=32)
    for name, obf, truth in [("Degree-2 Product MBA", obf_prod, truth_prod), ("Affine Masked MBA", obf_affine, truth_affine)]:
        z3_expr = simplifier.parse_python_mba_to_z3(obf, ("x", "y"))
        _, is_valid = simplifier.simplify_and_verify(z3_expr)
        table.add_row(name, obf, truth, "[bold green]VERIFIED (unsat)[/bold green]" if is_valid else "[bold red]FAIL[/bold red]")

    console.print(table)

def demo_hardcore_feistel():
    console.print()
    console.print(Panel("[bold yellow]Frontier Demo 2: 16-Round Nonlinear Feistel Network Target[/bold yellow]"))
    
    vm = HardcoreFeistelVM(rounds=16, seed=42)
    l_out, r_out, trace = vm.execute_concrete(0xDEADBEEF, 0xCAFEBABE)
    
    console.print(f"[bold cyan]Input State:[/bold cyan]  L=0xDEADBEEF, R=0xCAFEBABE")
    console.print(f"[bold green]Output State (16 Rounds):[/bold green] L=0x{l_out:08X}, R=0x{r_out:08X}")
    console.print("[dim]First 4 Rounds of Cryptographic Feistel Trace:[/dim]")
    for line in trace[:4]:
        console.print(f"  [magenta]{line}[/magenta]")
    console.print("  [dim]... [12 additional nonlinear rounds executed] ...[/dim]")

def main():
    print_banner()
    demo_nonlinear_frontier()
    demo_hardcore_feistel()

if __name__ == "__main__":
    main()
