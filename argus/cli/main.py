# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Argus Command Line Interface & Demonstration Suite v0.0.9.
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
from ..scanner.xref_engine import XRefEngine
from ..engine.patcher import BinaryPatcher
from ..engine.differ import BinaryDiffer
from ..frontend.assembler import X86Assembler
from ..engine.codegen import CCodeGenerator
from ..engine.cfg import CFGBuilder
from ..frontend.pe_parser import PEParser
from ..frontend.x86_lifter import X86Lifter

console = Console(force_terminal=True, legacy_windows=False)

def print_banner():
    banner = """
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    [bold cyan]|[/bold cyan]     [bold white]ARGUS[/bold white] : Automated Reverse & Graph Slicer Engine     [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim white]Reverse-Engineering & Binary Rewriter Suite v0.0.9[/dim white] [bold cyan]|[/bold cyan]
    [bold cyan]|[/bold cyan]     [dim green]Author: k.zhukov | License: MIT (2026)[/dim green]                 [bold cyan]|[/bold cyan]
    [bold cyan]+-------------------------------------------------------+[/bold cyan]
    """
    console.print(banner)

def demo_patcher_and_differ():
    console.print(Panel("[bold yellow]Binary Patcher & Code Differ Demonstration[/bold yellow]"))
    
    assembler = X86Assembler(bit_size=64)
    orig_code = b"\x83\xF8\x00\x74\x05\x31\xC0\xC3\xB8\x01\x00\x00\x00\xC3" # CMP EAX, 0; JZ +5; XOR EAX, EAX; RET; MOV EAX, 1; RET
    
    # Patch: replace JZ (0x74) with JNZ (0x75) and NOP out the XOR EAX, EAX
    patched_code = bytearray(orig_code)
    patched_code[3] = 0x75 # Invert JZ -> JNZ
    patched_code[5:7] = assembler.nop(2) # NOP XOR EAX, EAX
    
    differ = BinaryDiffer(bit_size=64)
    diffs = differ.diff_buffers(orig_code, bytes(patched_code), base_address=0x140001000)
    
    table = Table(title="Binary Modification & Assembly Diff")
    table.add_column("Address", style="cyan")
    table.add_column("Original Code", style="bold red")
    table.add_column("Patched Code", style="bold green")
    
    for d in diffs:
        table.add_row(
            d["address"],
            f"{d['orig_hex']} ({', '.join(d['orig_disasm'])})",
            f"{d['patched_hex']} ({', '.join(d['patched_disasm'])})"
        )
    console.print(table)
    console.print()
    console.print("[bold green][SUCCESS] Binary Patch & Diff Engine Operational![/bold green]")
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
        demo_patcher_and_differ()

if __name__ == "__main__":
    main()
