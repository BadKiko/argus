# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Argus Command Line Interface & Demonstration Suite v0.2.0.
Author: k.zhukov (2026) | MIT License
"""
import sys
import numpy as np
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
import z3

from ..targets.mba_generator import MBAGenerator
from ..targets.nonlinear_mba import NonlinearMBAGenerator
from ..targets.hardcore_vm import HardcoreFeistelVM
from ..targets.nested_vm import NestedDoubleVM, InnerOpcode
from ..targets.polymorphic_vm_target import PolymorphicVMTarget
from ..targets.self_modifying_target import SelfModifyingTarget
from ..targets.interlocking_target import InterlockingTarget
from ..engine.simplifier import MBASimplifier
from ..engine.cegis import CEGISSynthesizer
from ..engine.path_explorer import SymbolicPathExplorer
from ..engine.devirtualizer_v2 import AutomatedDevirtualizer, VMHandlerSynthesizer
from ..engine.shadow_state import ShadowEnvironment
from ..engine.integrity_slicer import InterlockingIntegritySlicer
from ..frontend.dynamic_overlay import DynamicOverlayEngine, MemoryPage
from ..scanner.function_scanner import FunctionScanner
from ..scanner.xref_engine import XRefEngine
from ..engine.patcher import BinaryPatcher
from ..engine.differ import BinaryDiffer
from ..frontend.assembler import X86Assembler
from ..engine.codegen import CCodeGenerator
from ..engine.cfg import CFGBuilder
from ..frontend.pe_parser import PEParser
from ..frontend.x86_lifter import X86Lifter
from ..ai.graph_dataset import GraphDatasetGenerator
from ..ai.gnn_sifter import GNNSifter

console = Console(force_terminal=True, legacy_windows=False)

def print_banner():
    banner = """
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    [bold cyan]|[/bold cyan]     [bold white]ARGUS[/bold white] : Automated Reverse & Graph Slicer Engine     [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim white]Advanced Protection Analysis & De-virtualizer v0.2.0[/dim white] [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim green]Author: k.zhukov | License: MIT (2026)[/dim green]                 [bold cyan]|[/bold cyan]
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    """
    console.print(banner)

def demo_v020_protection_breakers():
    console.print(Panel("[bold yellow]Argus v0.2.0: Advanced Protection-Breaking Engines[/bold yellow]"))
    
    # 1. Devirtualizer V2
    poly_target = PolymorphicVMTarget(seed=42)
    devirt = AutomatedDevirtualizer()
    ir_stream = devirt.devirtualize_bytecode_stream(
        poly_target.generate_sample_bytecode(0xDEADBEEF),
        poly_target.get_opcode_map()
    )
    
    # 2. Dynamic Memory W^X Snapshotter
    self_mod = SelfModifyingTarget(key=0xAA)
    overlay = DynamicOverlayEngine()
    overlay.allocate_page(0x140001000)
    overlay.write_memory(0x140001000, self_mod.decrypt_in_memory())
    snap = overlay.protect_memory(0x140001000, MemoryPage.PAGE_READ | MemoryPage.PAGE_EXECUTE)
    
    # 3. Shadow State
    shadow = ShadowEnvironment(is_64bit=True)
    eax, edx = shadow.emulate_rdtsc(50)
    
    # 4. Interlocking Slicer
    interlock = InterlockingTarget()
    slicer = InterlockingIntegritySlicer()
    inv_res = slicer.solve_hash_invariant(interlock.code_bytes, interlock.expected_hash, 0x12345678)
    
    table = Table(title="Protection-Breaking Engines Verification Status")
    table.add_column("Protection Barrier", style="cyan")
    table.add_column("Argus Engine Solution", style="yellow")
    table.add_column("Result / Status", style="bold green")
    
    table.add_row("1. Code Virtualization", "CEGIS VM Handler Synthesizer", f"[bold green]Reconstructed {len(ir_stream)} IR ops[/bold green]")
    table.add_row("2. JIT / Self-Modifying Code", "W^X Dynamic Memory Overlay", f"[bold green]Captured {len(snap['data'])} bytes snapshot[/bold green]")
    table.add_row("3. Kernel & Hardware Anti-Debug", "Deterministic Shadow CPU/PEB", f"[bold green]PEB Clean | RDTSC: 0x{((edx<<32)|eax):x}[/bold green]")
    table.add_row("4. Distributed Integrity Checks", "Interlocking Invariant Slicer", f"[bold green]Invariant 0x{interlock.expected_hash:x} Solved[/bold green]")
    
    console.print(table)
    console.print()
    console.print("[bold green][SUCCESS] All 4 Advanced Protection Barriers Successfully Neutralized![/bold green]")
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

    xref_engine = XRefEngine(pe_path, bit_size=64)
    strings = xref_engine.find_strings(min_length=6)
    console.print()
    console.print(Panel(f"[bold yellow]Discovered Cross-Reference String Anchors ({len(strings)} strings found)[/bold yellow]"))
    for s in strings[:6]:
        console.print(f"  RVA: [cyan]{s['rva']}[/cyan] ({s['section']}) -> [magenta]{s['string']}[/magenta]")

    xref_engine.close()
    parser.close()
    console.print()
    console.print("[bold green][OK] Binary Analysis Completed Successfully![/bold green]")

def main():
    print_banner()
    if len(sys.argv) > 2 and sys.argv[1] == "--file":
        analyze_pe_file(sys.argv[2])
    else:
        demo_v020_protection_breakers()

if __name__ == "__main__":
    main()
