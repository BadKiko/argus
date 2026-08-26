from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from argus import __version__

console = Console()


def cmd_analyze(args: argparse.Namespace) -> int:
    from argus.binary import load_binary

    img = load_binary(args.binary)
    table = Table(title=f"Argus analyze: {Path(args.binary).name}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("format", img.fmt)
    table.add_row("arch", img.arch)
    table.add_row("entry", hex(img.entry))
    table.add_row("sections", str(len(img.sections)))
    table.add_row("symbols", str(len(img.symbols)))
    table.add_row("imports/PLT", str(len(img.imports)))
    console.print(table)
    if args.imports:
        for addr, name in sorted(img.imports.items()):
            console.print(f"  {hex(addr)}  {name}")
    funcs = [s for s in img.symbols.values() if s.is_function and not s.is_import and s.addr]
    console.print(f"[green]functions:[/green] {len(funcs)}")
    for s in sorted(funcs, key=lambda x: x.addr)[:20]:
        console.print(f"  {hex(s.addr)}  {s.name}")
    return 0


def cmd_cfg(args: argparse.Namespace) -> int:
    from argus.binary import load_binary
    from argus.disasm import build_cfg, build_function_cfg

    img = load_binary(args.binary)
    if args.entry:
        cfg = build_cfg(img, entry=int(args.entry, 0))
    elif args.function and args.function in img.symbols:
        cfg = build_function_cfg(img, args.function)
    else:
        cfg = build_cfg(img, entry=img.entry)
    console.print(f"CFG entry={hex(cfg.entry)} blocks={len(cfg.blocks)} edges={cfg.graph.number_of_edges()}")
    if args.dot:
        out = Path(args.dot)
        out.write_text(cfg.to_dot())
        console.print(f"wrote {out}")
    return 0


def cmd_solve(args: argparse.Namespace) -> int:
    from argus.symbolic import solve_binary

    res = solve_binary(args.binary)
    console.print(f"success={res.success} paths={res.paths_explored} msg={res.message}")
    if res.stdin is not None:
        console.print(f"stdin bytes: {res.stdin!r}")
        try:
            console.print(f"stdin text:  {res.stdin.decode('latin1')!r}")
        except Exception:
            pass
    if res.stdout:
        console.print(f"stdout: {res.stdout!r}")
    return 0 if res.success else 1


def cmd_prune(args: argparse.Namespace) -> int:
    from argus.binary import load_binary
    from argus.disasm import build_function_cfg
    from argus.ml import Pruner

    img = load_binary(args.binary)
    fn = args.function or "main"
    cfg = build_function_cfg(img, fn)
    pruner = Pruner(tau=args.tau, require_proof=not args.no_proof)
    pr = pruner.prune(cfg)
    console.print(f"backend={pr.backend} kept={len(pr.kept)} pruned={len(pr.pruned)}")
    for a in pr.pruned[:30]:
        console.print(f"  prune {hex(a)}")
    if pruner.last_certificate:
        c = pruner.last_certificate
        console.print(
            f"[cyan]certificate[/cyan] proposed={len(c.proposed)} "
            f"approved={len(c.approved)} rejected={len(c.rejected)}"
        )
        for bc in c.block_certs[:15]:
            mark = "OK" if bc.allowed_prune else "NO"
            console.print(f"  [{mark}] {hex(bc.addr)} {bc.kind.value} — {bc.detail}")
    return 0


def cmd_deobf(args: argparse.Namespace) -> int:
    from argus.binary import load_binary
    from argus.deobf import recover_cff
    from argus.disasm import build_function_cfg
    from argus.eval import ArgusReport

    img = load_binary(args.binary)
    fn = args.function or "main"
    cfg = build_function_cfg(img, fn)
    report = recover_cff(cfg)
    console.print(f"dispatcher={hex(report.dispatcher) if report.dispatcher else None}")
    console.print(f"state_slot={report.state_slot!r}")
    console.print(f"cases={len(report.case_map)} edges={len(report.recovered_edges)}")
    for n in report.notes:
        console.print(f"  {n}", markup=False)
    for imm, tgt in list(report.case_map.items())[:12]:
        console.print(f"  case {hex(imm)} -> {hex(tgt)}")
    if args.json:
        rep = ArgusReport(
            binary=str(args.binary),
            fmt=img.fmt,
            entry=hex(img.entry),
            functions=[fn],
            cff=report.to_dict(),
        )
        Path(args.json).write_text(rep.to_json())
        console.print(f"wrote {args.json}")
    return 0


def cmd_mba(args: argparse.Namespace) -> int:
    from argus.mba import MBASimplifier, mba_x_plus_y, mba_x_xor_y

    s = MBASimplifier(32)
    for name, fn in [("plus_mba", mba_x_plus_y), ("xor_mba", mba_x_xor_y)]:
        r = s.simplify_binary_expr(fn)
        console.print(f"{name}: simplified={r.simplified} proved={r.proved}")
    return 0


def cmd_patch(args: argparse.Namespace) -> int:
    from argus.patch import Patcher
    from argus.prove import certify_nop_patches

    p = Patcher.from_path(args.binary)
    if args.nop:
        addr, length = args.nop
        ok = p.nop(int(addr, 0), int(length), note="cli nop")
        console.print(f"nop @{addr} len={length} ok={ok}")
    if args.invert:
        ok = p.invert_short_jz(int(args.invert, 0))
        console.print(f"invert @{args.invert} ok={ok}")
    out = args.output or (str(args.binary) + ".patched")
    p.save(out)
    console.print(f"wrote {out} patches={len(p.patches)}")
    verify = None
    if args.verify:
        verify = p.verify_runs(stdin=args.stdin.encode() if args.stdin else b"")
        console.print(verify)
    if p.patches:
        cert = certify_nop_patches(p.patches, verify)
        console.print(f"patch_certificate proven={cert.proven} notes={cert.notes}")
    return 0


def cmd_certify(args: argparse.Namespace) -> int:
    """Full certified pipeline: prune-with-proof + CFF state recovery + optional solve."""
    from argus.binary import load_binary
    from argus.deobf import recover_cff
    from argus.disasm import build_function_cfg
    from argus.eval import ArgusReport
    from argus.ml import Pruner
    from argus.symbolic import solve_binary

    img = load_binary(args.binary)
    fn = args.function or "main"
    cfg = build_function_cfg(img, fn)
    pruner = Pruner(require_proof=True)
    pr = pruner.prune(cfg)
    cff = recover_cff(cfg)
    solve = None
    if args.solve:
        res = solve_binary(args.binary)
        solve = {
            "success": res.success,
            "stdin": None if res.stdin is None else res.stdin.decode("latin1", errors="replace"),
            "paths": res.paths_explored,
            "message": res.message,
        }
    cert = pruner.last_certificate.to_dict() if pruner.last_certificate else None
    rep = ArgusReport(
        binary=str(args.binary),
        fmt=img.fmt,
        entry=hex(img.entry),
        functions=[fn],
        prune={"backend": pr.backend, "kept": len(pr.kept), "pruned": [hex(a) for a in pr.pruned]},
        certificate=cert,
        cff=cff.to_dict(),
        solve=solve,
        notes=[
            "Certified Argus run",
            "Drops require deadness proof; CFF uses state-variable recovery",
        ],
    )
    text = rep.to_json()
    if args.output:
        Path(args.output).write_text(text)
        console.print(f"wrote {args.output}")
    else:
        console.print(text)
    console.print(
        f"[bold green]certify[/bold green] prune_approved="
        f"{len(pruner.last_certificate.approved) if pruner.last_certificate else 0} "
        f"cff_cases={len(cff.case_map)} edges={len(cff.recovered_edges)}"
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from argus.binary import load_binary
    from argus.deobf import recover_cff
    from argus.disasm import build_function_cfg
    from argus.eval import ArgusReport
    from argus.ml import Pruner
    from argus.symbolic import solve_binary

    img = load_binary(args.binary)
    fn = args.function or "main"
    cfg = build_function_cfg(img, fn)
    pruner = Pruner(require_proof=True)
    pr = pruner.prune(cfg)
    cff = recover_cff(cfg)
    solve = None
    if args.solve:
        res = solve_binary(args.binary)
        solve = {
            "success": res.success,
            "stdin": None if res.stdin is None else res.stdin.decode("latin1", errors="replace"),
            "paths": res.paths_explored,
            "message": res.message,
        }
    rep = ArgusReport(
        binary=str(args.binary),
        fmt=img.fmt,
        entry=hex(img.entry),
        functions=[fn],
        prune={"backend": pr.backend, "kept": len(pr.kept), "pruned": [hex(a) for a in pr.pruned]},
        certificate=pruner.last_certificate.to_dict() if pruner.last_certificate else None,
        cff=cff.to_dict(),
        solve=solve,
        notes=["Argus hybrid report"],
    )
    text = rep.to_json()
    if args.output:
        Path(args.output).write_text(text)
        console.print(f"wrote {args.output}")
    else:
        console.print(text)
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from argus.binary import load_binary
    from argus.ml import TORCH_AVAILABLE, train_on_image

    if not TORCH_AVAILABLE:
        console.print("[yellow]torch not installed; install argus[ml] / pip install torch[/yellow]")
        return 1
    img = load_binary(args.binary)
    model = train_on_image(img, epochs=args.epochs, save_path=args.output)
    console.print(f"trained={model is not None} saved={args.output}")
    return 0 if model is not None else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="argus",
        description=f"Argus {__version__} — certified hybrid deobfuscation (ML proposes, math proves)",
    )
    p.add_argument("--version", action="version", version=__version__)
    sp = p.add_subparsers(dest="cmd", required=True)

    a = sp.add_parser("analyze", help="Show binary metadata")
    a.add_argument("binary")
    a.add_argument("--imports", action="store_true")
    a.set_defaults(func=cmd_analyze)

    c = sp.add_parser("cfg", help="Build CFG")
    c.add_argument("binary")
    c.add_argument("-f", "--function", default="main")
    c.add_argument("--entry", help="VA to start CFG (hex/dec), for PE/VMP without symbols")
    c.add_argument("--dot", help="Write Graphviz DOT")
    c.set_defaults(func=cmd_cfg)

    s = sp.add_parser("solve", help="Symbolic solve (ELF crackme)")
    s.add_argument("binary")
    s.set_defaults(func=cmd_solve)

    pr = sp.add_parser("prune", help="Proof-carrying CFG prune")
    pr.add_argument("binary")
    pr.add_argument("-f", "--function", default="main")
    pr.add_argument("--tau", type=float, default=0.85)
    pr.add_argument("--no-proof", action="store_true", help="Allow ML-only drops (unsafe)")
    pr.set_defaults(func=cmd_prune)

    d = sp.add_parser("deobf", help="CFF state-variable recovery")
    d.add_argument("binary")
    d.add_argument("-f", "--function", default="main")
    d.add_argument("--json", help="Write report JSON")
    d.set_defaults(func=cmd_deobf)

    m = sp.add_parser("mba", help="MBA simplification with Z3 proofs")
    m.set_defaults(func=cmd_mba)

    pa = sp.add_parser("patch", help="Patch binary bytes with certificate")
    pa.add_argument("binary")
    pa.add_argument("-o", "--output")
    pa.add_argument("--nop", nargs=2, metavar=("ADDR", "LEN"))
    pa.add_argument("--invert", metavar="ADDR")
    pa.add_argument("--verify", action="store_true")
    pa.add_argument("--stdin", default="")
    pa.set_defaults(func=cmd_patch)

    t = sp.add_parser("train", help="Train ResGCN on binary CFGs (needs torch)")
    t.add_argument("binary")
    t.add_argument("-o", "--output", default="argus/ml/models/res_gcn.pt")
    t.add_argument("--epochs", type=int, default=40)
    t.set_defaults(func=cmd_train)

    cert = sp.add_parser("certify", help="Full certified pipeline report")
    cert.add_argument("binary")
    cert.add_argument("-f", "--function", default="main")
    cert.add_argument("-o", "--output")
    cert.add_argument("--solve", action="store_true")
    cert.set_defaults(func=cmd_certify)

    r = sp.add_parser("report", help="JSON pipeline report")
    r.add_argument("binary")
    r.add_argument("-f", "--function", default="main")
    r.add_argument("-o", "--output")
    r.add_argument("--solve", action="store_true")
    r.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    rc = args.func(args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
