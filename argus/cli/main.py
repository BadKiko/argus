# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Argus Command Line Interface & Demonstration Suite v0.0.8.
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
from ..engine.path_explorer import SymbolicPathExplorer
from ..scanner.function_scanner import FunctionScanner
from ..engine.codegen import CCodeGenerator
from ..engine.cfg import CFGBuilder
from ..frontend.pe_parser import PEParser
from ..frontend.x86_lifter import X86Lifter

console = Console(force_terminal=True, legacy_windows=False)

def print_banner():
    banner = """
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    [bold cyan]|[/bold cyan]     [bold white]ARGUS[/bold white] : Automated Reverse & Graph Slicer Engine     [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim white]Goal-Driven Path Explorer & Sink Solver v0.0.8[/dim white]    [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim green]Author: k.zhukov | License: MIT (2026)[/dim green]                 [bold cyan]|[/bold cyan]
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    """
    console.print(banner)

def demo_path_explorer_sink_solver():
    console.print(Panel("[bold yellow]Goal-Driven Symbolic Path Explorer: Automated Password / Key Recovery[/bold yellow]"))
    
    explorer = SymbolicPathExplorer(bit_size=32)
    passwd = explorer.create_symbolic_byte_buffer("key", 8)
    
    # Target obfuscated key check: "ARGUSKEY"
    expected = b"ARGUSKEY"
    console.print(f"[bold cyan]Input Parameter:[/bold cyan] 8-Byte Symbolic Buffer [key_0 .. key_7]")
    console.print(f"[bold magenta]Target Condition:[/bold magenta] Multilevel Obfuscated Key Verification Endpoint")

    # Add branch conditions
    for i, exp_byte in enumerate(expected):
        mask = (i * 17 + 0x33) & 0xFF
        obf_val = exp_byte ^ mask
        explorer.add_path_constraint((passwd[i] ^ z3.BitVecVal(mask, 8)) == z3.BitVecVal(obf_val, 8))

    is_sat, assignments, recovered_bytes = explorer.solve_for_target_sink()
    
    table = Table(title="Symbolic Path Exploration & SMT Solver Result")
    table.add_column("Property", style="cyan")
    table.add_column("Value / State", style="bold green")
    table.add_row("SMT Satisfiability", "[bold green]SATISFIABLE (SAT)[/bold green]" if is_sat else "[bold red]UNSAT[/bold red]")
    table.add_row("Branch Equations", f"{len(expected)} Constraints Verified")
    table.add_row("Recovered Key Bytes", f"{recovered_bytes.decode('ascii', errors='ignore') if recovered_bytes else 'N/A'}")
    
    console.print(table)
    console.print()
    console.print("[bold green][SUCCESS] Automated Goal-Driven Path Solving Completed![/bold green]")
    console.print()

def analyze_pe_file(pe_path: str):
    console.print()
    console.print(Panel(f"[bold cyan]Argus Real-World Binary Analysis: {pe_path}[/bold cyan]"))
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
        scanner = FunctionScanner(bit_size=64)
        funcs = scanner.scan_functions_in_bytes(code_bytes[:1024], base_address=0x1000)
        console.print()
        console.print(Panel(f"[bold yellow]Discovered Functions & Endpoints ({len(funcs)} detected in initial block)[/bold yellow]"))
        for f in funcs[:5]:
            status = "[bold green]Candidate Validator[/bold green]" if f["is_potential_validator"] else "[dim]Normal Routine[/dim]"
            console.print(f"  Start: [cyan]{f['start_address']}[/cyan] | Ins: [magenta]{f['instruction_count']}[/magenta] | Status: {status}")

    parser.close()
    console.print()
    console.print("[bold green][OK] Binary Analysis Completed Successfully![/bold green]")

def main():
    print_banner()
    if len(sys.argv) > 2 and sys.argv[1] == "--file":
        analyze_pe_file(sys.argv[2])
    else:
        demo_path_explorer_sink_solver()

if __name__ == "__main__":
    main()
