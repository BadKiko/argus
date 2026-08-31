from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from argus import __version__
from argus.ask import PatchKind, Want

console = Console()


def cmd_analyze(args: argparse.Namespace) -> int:
    from argus.binary import load_binary
    from argus.deobf import detect_protection

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
    prot = detect_protection(img)
    table.add_row("protection", f"{prot.kind} ({prot.confidence:.2f})")
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

    if args.deobf:
        from argus.deobf import solve_after_deobf

        res = solve_after_deobf(args.binary)
    else:
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
    from argus.deobf import deobf_and_patch, detect_protection, recover_cff
    from argus.disasm import build_cfg, build_function_cfg
    from argus.eval import ArgusReport

    img = load_binary(args.binary)
    prot = detect_protection(img)
    console.print(f"detect={prot.kind} conf={prot.confidence:.2f}")
    if prot.kind == "stripped":
        console.print(
            "[yellow]stripped binary[/yellow]: CFF unflatten needs a recoverable function; "
            "use --entry 0xVA for CFG probe or argus find → gate_candidates"
        )

    if args.entry:
        entry = int(args.entry, 0)
        cfg = build_cfg(img, entry=entry, max_blocks=400)
        fn = f"sub_{entry:x}"
    else:
        fn = args.function or "main"
        if fn in img.symbols:
            cfg = build_function_cfg(img, fn)
        else:
            cfg = build_cfg(img, entry=img.entry, max_blocks=400)
            fn = fn if fn != "main" else f"entry_{img.entry:x}"

    report = recover_cff(cfg)
    console.print(f"dispatcher={hex(report.dispatcher) if report.dispatcher else None}")
    console.print(f"state_slot={report.state_slot!r}", markup=False)
    console.print(f"cases={len(report.case_map)} edges={len(report.recovered_edges)}")
    for n in report.notes:
        console.print(f"  {n}", markup=False)
    for imm, tgt in list(report.case_map.items())[:12]:
        console.print(f"  case {hex(imm)} -> {hex(tgt)}")

    if not report.dispatcher and prot.kind == "stripped":
        console.print("[yellow]no CFF dispatcher — skip patch; use license-slice / gate_candidates[/yellow]")
        return 1

    patch_info = None
    if args.patch:
        if args.entry:
            console.print("[yellow]--patch with --entry: use named -f for unflatten write[/yellow]")
            return 1
        fns = [fn]
        if args.all_cff and args.function:
            pass
        result = deobf_and_patch(
            args.binary,
            fns,
            args.patch,
            verify_stdin=(args.stdin.encode() if args.stdin else b""),
        )
        console.print(f"[green]patched[/green] {args.patch} applied={result.patches_applied}")
        for n in result.notes:
            console.print(f"  {n}", markup=False)
        patch_info = result.to_dict()
        if args.verify and img.fmt == "elf":
            from argus.patch import Patcher

            v = Patcher.from_path(args.patch).verify_runs(stdin=args.stdin.encode() if args.stdin else b"")
            console.print(f"verify ok={v.get('ok')} rc={v.get('returncode')} stdout={v.get('stdout', b'')[:80]!r}")

    if args.json:
        rep = ArgusReport(
            binary=str(args.binary),
            fmt=img.fmt,
            entry=hex(img.entry),
            functions=[fn],
            cff=report.to_dict() if hasattr(report, "to_dict") else {},
            patches=[patch_info] if patch_info else [],
            patch_certificate=(patch_info or {}).get("certificate") if patch_info else None,
            notes=[f"detect={prot.kind}"],
        )
        Path(args.json).write_text(rep.to_json())
        console.print(f"wrote {args.json}")
    return 0


def cmd_mba(args: argparse.Namespace) -> int:
    from argus.deobf import prove_mba_catalog
    from argus.mba import MBASimplifier, mba_x_plus_y, mba_x_xor_y

    s = MBASimplifier(32)
    for name, fn in [("plus_mba", mba_x_plus_y), ("xor_mba", mba_x_xor_y)]:
        r = s.simplify_binary_expr(fn)
        console.print(f"{name}: simplified={r.simplified} proved={r.proved}")
    for row in prove_mba_catalog():
        console.print(row)
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
    """Full certified pipeline: prune-with-proof + CFF + MBA/bogus + optional solve."""
    from argus.binary import load_binary
    from argus.deobf import analyze_bogus_cf, prove_mba_catalog, recover_cff, solve_after_deobf
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
    bogus = analyze_bogus_cf(cfg)
    mba = prove_mba_catalog()
    solve = None
    if args.solve:
        if cff.case_map:
            res = solve_after_deobf(args.binary)
        else:
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
        certificate={
            "prune": cert,
            "mba": mba,
            "bogus": bogus.to_dict(),
        },
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
        f"cff_cases={len(cff.case_map)} edges={len(cff.recovered_edges)} "
        f"bogus={len(bogus.hits)}"
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


def cmd_run(args: argparse.Namespace) -> int:
    from argus.pipeline import run_pipeline

    res = run_pipeline(
        args.binary,
        function=args.function,
        output=args.output,
        verify_stdin=args.stdin.encode() if args.stdin else b"",
        do_patch=not args.no_patch,
    )
    text = res.report.to_json()
    if args.json:
        Path(args.json).write_text(text)
        console.print(f"wrote {args.json}")
    else:
        console.print(text)
    if res.output_path:
        console.print(f"[green]output[/green] {res.output_path}")
    return 0


def cmd_memory(args: argparse.Namespace) -> int:
    """Query remote Argus memory backend."""
    import json

    from argus.memory.client import MemoryClient, maybe_warn_memory_usage, memory_url

    maybe_warn_memory_usage()
    url = memory_url()
    client = MemoryClient(url)
    if args.memory_cmd == "search":
        hints = client.search_hints(args.query, k=args.k)
        console.print(json.dumps({"ok": True, "hints": hints}, indent=2))
        return 0
    if args.memory_cmd == "stats":
        console.print(json.dumps(client.stats(), indent=2))
        return 0
    console.print(f"unknown memory subcommand: {args.memory_cmd}")
    return 1


def cmd_debug_fast_path(args: argparse.Namespace) -> int:
    """Legacy deterministic gate pipeline (opt-in — agent uses LLM by default in 0.5)."""
    import json

    from argus.llm.autopilot import run_gate_fast_path
    from argus.llm.session import reset_session
    from argus.llm.workspace import prepare_work_binary

    if not args.binary:
        console.print("[red]binary path required[/red]")
        return 1
    reset_session()
    work, orig = prepare_work_binary(args.binary)
    fp = run_gate_fast_path(
        work,
        args.prompt,
        original_binary=orig,
        verbose=bool(args.verbose),
    )
    if args.json:
        Path(args.json).write_text(json.dumps(fp, ensure_ascii=False, indent=2), encoding="utf-8")
    console.print(f"done={fp.get('done')} trace_len={len(fp.get('trace') or [])}")
    if fp.get("result"):
        console.print(json.dumps(fp["result"], ensure_ascii=False, indent=2)[:4000])
    return 0 if fp.get("done") else 1


def cmd_agent(args: argparse.Namespace) -> int:
    """LLM agent (OpenAI-compat or native Gemini AI Studio) with Argus tools."""
    import json
    import os
    import sys

    if args.no_memory:
        os.environ["ARGUS_MEMORY"] = "0"
    if getattr(args, "permissive_plan", False):
        os.environ["ARGUS_STRICT_PLAN"] = "0"
    else:
        os.environ.setdefault("ARGUS_STRICT_PLAN", "1")

    from argus.llm.agent import binary_missing, missing_binary_message, resolve_provider, run_agent

    if args.binary and binary_missing(args.binary):
        console.print(missing_binary_message(args.binary))
        return 1

    provider = resolve_provider(args.provider)
    model = args.model
    if provider == "gemini" and not model:
        model = "gemini-3.5-flash-lite"

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if getattr(args, "no_interactive", False):
        interactive = False

    verbose = bool(args.verbose) and not bool(getattr(args, "quiet", False))
    memory_on = not args.no_memory

    trace_ui = None
    if verbose and not getattr(args, "plain_trace", False):
        from argus.cli.trace_ui import AgentTraceUI

        trace_ui = AgentTraceUI(console)

    run_kwargs = dict(
        provider=provider,
        url=args.url,
        key=args.key,
        model=model,
        max_steps=args.max_steps,
        verbose=verbose,
        store_memory=not interactive,
        trace_ui=trace_ui,
        transcript_path=getattr(args, "transcript", None),
        transcript_enabled=not getattr(args, "no_transcript", False),
    )

    if not getattr(args, "no_transcript", False):
        from argus.llm.transcript import tail_log_hint

        console.print(f"[dim]session log:[/dim] [cyan]tail -f {tail_log_hint()}[/cyan]")

    if interactive:
        from argus.cli.agent_ui import interactive_session, render_banner

        render_banner(
            console,
            binary=args.binary,
            provider=provider,
            model=model or "",
        )

        def run_once_wrapped(prompt: str):
            try:
                return run_agent(prompt, args.binary, **run_kwargs)
            except Exception as e:
                console.print(f"[red]agent error:[/red] {e}")
                from argus.llm.agent import AgentResult

                return AgentResult(ok=False, answer=str(e), provider=provider, binary=args.binary)

        code = interactive_session(
            console,
            run_once=run_once_wrapped,
            original_prompt=args.prompt,
            binary=args.binary,
            max_retries=args.max_retries,
            show_trace=False,
            memory_enabled=memory_on,
        )
        if args.json:
            console.print("[dim]--json ignored in interactive mode (use --no-interactive)[/dim]")
        return code

    console.print(f"provider={provider} model={model or '(default)'}")
    if not getattr(args, "no_transcript", False):
        from argus.llm.transcript import tail_log_hint

        console.print(f"session log: tail -f {tail_log_hint()}")
    try:
        res = run_agent(args.prompt, binary=args.binary, **run_kwargs)
    except Exception as e:
        console.print(f"agent error: {e}")
        return 1
    if res.steps == 0 and res.planner == "fast_path_legacy":
        console.print(
            "[yellow]warning:[/yellow] finished with steps=0 via legacy fast-path "
            "(set ARGUS_FAST_PATH=0 for LLM-only planning)"
        )
    elif res.steps == 0:
        console.print(
            "[yellow]warning:[/yellow] agent finished with steps=0 — model may not have run tools"
        )
    console.print(f"[{res.provider}] {res.answer}")
    if args.json:
        Path(args.json).write_text(json.dumps(res.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"wrote {args.json}")
    if verbose and not trace_ui:
        for t in res.tool_trace:
            console.print(f"  tool {t['tool']} -> {t['result_preview'][:160]!r}")
    return 0 if res.ok else 1


def cmd_ask(args: argparse.Namespace) -> int:
    """LLM-facing intent API: hint in → answer / readable / patched out."""
    import json

    from argus.ask import Hint, PatchKind, Want, ask

    want = Want(args.want)
    patch_kind = PatchKind(args.patch_kind) if args.patch_kind else None
    hint = Hint(
        want=want,
        function=args.function,
        entry=int(args.entry, 0) if args.entry else None,
        query=getattr(args, "query", None),
        patch_kind=patch_kind,
        find=args.find.encode() if args.find else None,
        output=args.output,
        note=args.hint or "",
        force_taken=not args.force_not_taken,
        branch_addr=int(args.branch, 0) if args.branch else None,
    )
    res = ask(args.binary, hint)
    if args.json:
        Path(args.json).write_text(json.dumps(res.to_dict(), indent=2))
        console.print(f"wrote {args.json}")
    else:
        console.print(json.dumps(res.to_dict(), indent=2))
    if res.answer:
        console.print(f"[bold green]answer[/bold green] {res.answer}")
    if res.readable and not args.json:
        console.print(res.readable[:2000], markup=False)
    if res.patched_path:
        console.print(f"[green]patched[/green] {res.patched_path}")
    return 0 if res.ok else 1


def cmd_lift(args: argparse.Namespace) -> int:
    """Universal stripped/named annotated lift."""
    import json

    from argus.ask import Hint, Want, ask

    hint = Hint(
        want=Want.IR if args.ir else Want.LIFT,
        function=args.function,
        entry=int(args.entry, 0) if args.entry else None,
        query=args.query,
        note=args.query or "",
    )
    res = ask(args.binary, hint)
    if args.json:
        Path(args.json).write_text(json.dumps(res.to_dict(), indent=2))
        console.print(f"wrote {args.json}")
    if res.answer:
        console.print(f"[bold]{res.answer}[/bold]")
    if res.readable:
        console.print(res.readable, markup=False)
    return 0 if res.ok else 1


def cmd_eval(args: argparse.Namespace) -> int:
    import json
    import time
    from pathlib import Path

    from argus.binary import load_binary
    from argus.deobf import detect_protection, recover_cff
    from argus.disasm import build_cfg, build_function_cfg

    if args.corpus:
        root = Path(args.corpus)
        rows = []
        for p in sorted(root.rglob("*")):
            if not p.is_file() or p.suffix.lower() in (".md", ".txt", ".json"):
                continue
            if p.stat().st_size > 50_000_000:
                continue
            try:
                t0 = time.perf_counter()
                img = load_binary(str(p))
                prot = detect_protection(img)
                cfg = build_cfg(img, entry=img.entry, max_blocks=200)
                ms = (time.perf_counter() - t0) * 1000
                rows.append(
                    {
                        "path": str(p.relative_to(root)),
                        "fmt": img.fmt,
                        "protection": prot.kind,
                        "blocks": len(cfg.blocks),
                        "ms": round(ms, 2),
                    }
                )
            except Exception as e:
                rows.append({"path": str(p), "error": str(e)})
        text = json.dumps({"n": len(rows), "rows": rows}, indent=2)
        if args.json:
            Path(args.json).write_text(text)
            console.print(f"wrote {args.json}")
        else:
            console.print(text)
        return 0

    if not args.binary:
        console.print("eval: need binary or --corpus")
        return 2

    img = load_binary(args.binary)
    fn = args.function or "main"
    t0 = time.perf_counter()
    if fn in img.symbols:
        cfg = build_function_cfg(img, fn)
    else:
        cfg = build_cfg(img, entry=img.entry, max_blocks=400)
    t1 = time.perf_counter()
    cff = recover_cff(cfg)
    t2 = time.perf_counter()
    console.print(
        f"fn={fn} blocks={len(cfg.blocks)} cfg_ms={(t1-t0)*1000:.1f} "
        f"cff_ms={(t2-t1)*1000:.1f} cases={len(cff.case_map)}"
    )
    return 0


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
    s.add_argument("--deobf", action="store_true", help="Unflatten CFF then solve")
    s.set_defaults(func=cmd_solve)

    pr = sp.add_parser("prune", help="Proof-carrying CFG prune")
    pr.add_argument("binary")
    pr.add_argument("-f", "--function", default="main")
    pr.add_argument("--tau", type=float, default=0.85)
    pr.add_argument("--no-proof", action="store_true", help="Allow ML-only drops (unsafe)")
    pr.set_defaults(func=cmd_prune)

    d = sp.add_parser("deobf", help="CFF state-variable recovery + optional patch")
    d.add_argument("binary")
    d.add_argument("-f", "--function", default="main")
    d.add_argument("--entry", help="VA for CFG/CFF probe on stripped binaries (hex/dec)")
    d.add_argument("--patch", help="Write unflattened binary")
    d.add_argument("--verify", action="store_true", help="Run patched ELF smoke verify")
    d.add_argument("--stdin", default="", help="stdin for verify")
    d.add_argument("--all-cff", action="store_true", help="Also unflatten companion functions from -f list")
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

    run = sp.add_parser("run", help="Detect → deobf classes → patch → verify")
    run.add_argument("binary")
    run.add_argument("-f", "--function")
    run.add_argument("-o", "--output", help="Patched binary path")
    run.add_argument("--json", help="Certificate bundle JSON")
    run.add_argument("--stdin", default="")
    run.add_argument("--no-patch", action="store_true")
    run.set_defaults(func=cmd_run)

    ask_p = sp.add_parser(
        "ask",
        help="Structured intent API (e.g. argus ask --want lift -f main binary)",
    )
    ask_p.add_argument("binary")
    ask_p.add_argument(
        "--want",
        required=True,
        choices=["password", "lift", "patch", "deobf", "report", "ir"],
        help="What the model needs back",
    )
    ask_p.add_argument("-f", "--function", help="Target function hint")
    ask_p.add_argument("--hint", default="", help="Free-text hint from the LLM")
    ask_p.add_argument(
        "--patch-kind",
        choices=[k.value for k in PatchKind],
        help="Patch intent",
    )
    ask_p.add_argument("-o", "--output", help="Patched/deobf output path")
    ask_p.add_argument("--find", default=None, help="Success needle for password")
    ask_p.add_argument("--entry", help="Optional entry VA")
    ask_p.add_argument("--query", help="String query → xref → function")
    ask_p.add_argument("--branch", help="VA for force_branch")
    ask_p.add_argument("--force-not-taken", action="store_true")
    ask_p.add_argument("--ret-value", type=int, help="Immediate value for ret_imm")
    ask_p.add_argument("--note", default="", help="Freeform note for certificate/log")
    ask_p.add_argument("--json", help="Write full AskResult JSON")
    ask_p.add_argument("-v", "--verbose", action="store_true", help="Dump full result")
    ask_p.set_defaults(func=cmd_ask)

    lift_p = sp.add_parser(
        "lift",
        help="Annotated pseudo-C lift (VA / function / string query; works on stripped ELF)",
    )
    lift_p.add_argument("binary")
    lift_p.add_argument("-f", "--function", help="Symbol name, sub_HEX, or 0xVA")
    lift_p.add_argument("--entry", help="Code VA to lift (hex/dec)")
    lift_p.add_argument("--query", help="String in binary → xref → covering function")
    lift_p.add_argument("--json", help="Write AskResult JSON")
    lift_p.add_argument("--ir", action="store_true", help="Emit JSON IR instead of pseudo-C")
    lift_p.set_defaults(func=cmd_lift)

    ag = sp.add_parser(
        "agent",
        help="LLM agent with Argus tools (OpenAI-compat or native Gemini AI Studio)",
    )
    ag.add_argument("prompt", help="What you want from the binary")
    ag.add_argument(
        "binary",
        nargs="?",
        help="Path to binary (optional: discover from prompt path or cwd ELF/PE + linked DLL/SO)",
    )
    ag.add_argument(
        "--provider",
        choices=["auto", "gemini", "openai"],
        default="auto",
        help="gemini = AI Studio generateContent; openai = OpenAI-compatible URL",
    )
    ag.add_argument(
        "--no-memory",
        action="store_true",
        help="Disable shared remote case memory (ARGUS_MEMORY=0 for this run)",
    )
    ag.add_argument("--url", help="API base URL (openai compat, or gemini v1beta root)")
    ag.add_argument("--key", help="API key (GEMINI_API_KEY / OPENAI_API_KEY)")
    ag.add_argument("--model", help="Model id (e.g. gemini-3.5-flash-lite or gpt-4o-mini)")
    ag.add_argument(
        "--max-steps",
        type=int,
        default=0,
        help="Max LLM tool rounds (0 = unlimited until model stops or task done)",
    )
    ag.add_argument("--json", help="Write AgentResult JSON")
    ag.add_argument(
        "--no-interactive",
        action="store_true",
        help="Plain output, auto-save memory (no prompts: run binary / success feedback)",
    )
    ag.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Interactive mode: max follow-up attempts after user feedback (default 3)",
    )
    ag.add_argument(
        "--permissive-plan",
        action="store_true",
        help="Disable strict patch-plan gates (allow model-invented steps; debug only)",
    )
    ag.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=True,
        help="Print step/tool logs (default on)",
    )
    ag.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Disable step/tool logs and trace UI",
    )
    ag.add_argument(
        "--plain-trace",
        action="store_true",
        help="Old [tool] JSON lines instead of Rich investigation trace",
    )
    ag.add_argument(
        "--transcript",
        metavar="FILE",
        default=None,
        help="Custom JSONL session log path (default: ~/.cache/argus/current.jsonl + /tmp/argus.jsonl)",
    )
    ag.add_argument(
        "--no-transcript",
        action="store_true",
        help="Disable automatic session JSONL logging",
    )
    ag.set_defaults(func=cmd_agent)

    dbg = sp.add_parser("debug", help="Debug / legacy pipelines (not used by default agent)")
    dbg_sub = dbg.add_subparsers(dest="debug_cmd", required=True)
    fp = dbg_sub.add_parser(
        "fast-path",
        help="Run legacy gate fast-path without LLM (ARGUS_FAST_PATH for agent)",
    )
    fp.add_argument("prompt", help="Task text")
    fp.add_argument("binary", help="Path to binary")
    fp.add_argument("--json", help="Write result JSON")
    fp.add_argument("-v", "--verbose", action="store_true")
    fp.set_defaults(func=cmd_debug_fast_path)

    mem = sp.add_parser("memory", help="Remote case memory (vector search on argus.cloud.badkiko.ru)")
    mem_sub = mem.add_subparsers(dest="memory_cmd", required=True)
    mem_search = mem_sub.add_parser("search", help="Search similar past cases")
    mem_search.add_argument("query", help="Search query text")
    mem_search.add_argument("--k", type=int, default=5)
    mem_search.set_defaults(func=cmd_memory, memory_cmd="search")
    mem_stats = mem_sub.add_parser("stats", help="Memory backend stats")
    mem_stats.set_defaults(func=cmd_memory, memory_cmd="stats")

    ev = sp.add_parser("eval", help="Timing metrics (ms/function) or --corpus scan")
    ev.add_argument("binary", nargs="?", default=None)
    ev.add_argument("-f", "--function", default="main")
    ev.add_argument("--corpus", help="Scan sample tree; emit JSON metrics")
    ev.add_argument("--json", help="Write corpus JSON")
    ev.set_defaults(func=cmd_eval)

    return p


def main(argv: list[str] | None = None) -> None:
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    rc = args.func(args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
