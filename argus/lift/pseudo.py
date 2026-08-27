from __future__ import annotations

"""Annotated pseudo-C / JSON IR lift for named and stripped binaries."""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from argus.binary.image import BinaryImage

_MAX_LIFT_BLOCKS = 48
_MAX_CALLEES = 40
_RIP_RX = re.compile(
    r"\[(?:rip|eip)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]",
    re.IGNORECASE,
)


def _cstr_preview(img: BinaryImage, addr: int, limit: int = 48) -> Optional[str]:
    try:
        raw = img.read_bytes(addr, limit + 1)
    except Exception:
        return None
    if not raw or raw[0] == 0:
        return None
    # printable-ish
    out = []
    for b in raw:
        if b == 0:
            break
        if 32 <= b < 127:
            out.append(chr(b))
        elif b in (10, 13, 9):
            out.append("\\n" if b == 10 else "\\t" if b == 9 else "\\r")
        else:
            if len(out) < 4:
                return None
            break
        if len(out) >= limit:
            out.append("…")
            break
    if len(out) < 2:
        return None
    return "".join(out)


def _rip_target(insn_addr: int, insn_size: int, op_str: str) -> Optional[int]:
    m = _RIP_RX.search(op_str or "")
    if not m:
        return None
    sign, imm = m.group(1), m.group(2)
    disp = int(imm, 0)
    if sign == "-":
        disp = -disp
    return insn_addr + insn_size + disp


def _annotate_insn(
    img: BinaryImage,
    insn,
    *,
    idx_label,
) -> Tuple[str, Dict[str, Any]]:
    """Return display annotation string + meta."""
    meta: Dict[str, Any] = {}
    m, o = insn.mnemonic, insn.op_str or ""
    ann_parts: List[str] = []

    # RIP-relative string/data
    tgt = _rip_target(insn.address, insn.size, o)
    if tgt is not None:
        preview = _cstr_preview(img, tgt)
        if preview is not None:
            ann_parts.append(f'str="{preview}"')
            meta["string"] = preview
            meta["data_addr"] = hex(tgt)
        else:
            meta["data_addr"] = hex(tgt)

    # calls
    if m == "call":
        name = None
        targets = list(insn.targets or [])
        if targets:
            t = targets[0]
            name = img.imports.get(t) or idx_label(t)
            meta["target"] = hex(t)
            if name:
                meta["callee"] = name
                ann_parts.append(name)
        elif o.startswith("0x") or (o[:1].isdigit()):
            try:
                t = int(o, 0)
                name = img.imports.get(t) or idx_label(t)
                meta["target"] = hex(t)
                if name:
                    meta["callee"] = name
                    ann_parts.append(name)
            except ValueError:
                pass
        if "[" in o and "rip" not in o.lower():
            meta["indirect"] = True
            ann_parts.append("indirect?")

    # GOT/PLT via rip
    if m == "call" and tgt is not None and tgt in img.imports:
        ann_parts.append(img.imports[tgt])
        meta["callee"] = img.imports[tgt]
        meta["indirect"] = False

    ann = "; ".join(ann_parts) if ann_parts else ""
    return ann, meta


def annotated_lift(
    path: str,
    *,
    function: Optional[str] = None,
    entry: Optional[int] = None,
    query: Optional[str] = None,
    max_blocks: int = _MAX_LIFT_BLOCKS,
    resolve_indirects: bool = False,
) -> Tuple[str, Dict[str, Any]]:
    """
    Pseudo-C style lift with string/import annotations.
    Returns (readable, evidence).
    """
    from argus.binary import load_binary
    from argus.deobf.cff import cleaned_adjacency, recover_cff
    from argus.disasm import build_cfg, build_function_cfg
    from argus.disasm.recovery import recover_functions
    from argus.disasm.resolve import resolve_lift_target

    img = load_binary(path)
    fidx = recover_functions(img)

    def idx_label(addr: int) -> Optional[str]:
        if addr in img.imports:
            return img.imports[addr]
        for name, sym in img.symbols.items():
            if sym.addr == addr and sym.is_function:
                return name
        b = fidx.covering(addr)
        return b.name if b else None

    # Named symbol path when function is a known symbol and no entry/query override
    if (
        function
        and function in img.symbols
        and entry is None
        and not query
    ):
        cfg = build_function_cfg(img, function)
        label = function
        reason = "symbol"
        target_va = cfg.entry
    else:
        target = resolve_lift_target(img, function=function, entry=entry, query=query)
        label = target.label
        reason = target.reason
        target_va = target.va
        if label in img.symbols:
            cfg = build_function_cfg(img, label)
        else:
            cfg = build_cfg(img, entry=target_va, function_name=label, max_blocks=max_blocks * 2)

    cff = recover_cff(cfg)
    adj = cleaned_adjacency(cfg, cff) if cff.case_map else {
        a: list(cfg.blocks[a].successors) for a in cfg.blocks
    }

    callees: List[dict] = []
    string_anns = 0
    resolved_calls = 0
    total_calls = 0
    indirect_unresolved = 0
    insn_records: List[dict] = []

    total_blocks = len(cfg.blocks)
    block_addrs = sorted(cfg.blocks)[:max_blocks]
    truncated = total_blocks > max_blocks

    lines: List[str] = [
        f"/* Argus lift: {label} @ {hex(cfg.entry)} reason={reason} */",
        f"/* cff_cases={len(cff.case_map)} dispatcher="
        f"{hex(cff.dispatcher) if cff.dispatcher else 'none'} */",
        f"/* blocks={total_blocks} shown={len(block_addrs)} truncated={truncated} */",
        f"int {label}(/* args */) {{",
    ]

    for addr in block_addrs:
        blk = cfg.blocks[addr]
        succs = adj.get(addr, list(blk.successors))
        block_strs: List[str] = []
        lines.append(f"  L_{addr:x}:")
        body_lines: List[str] = []
        for ins in blk.instructions[:24]:
            ann, meta = _annotate_insn(img, ins, idx_label=idx_label)
            if meta.get("string"):
                string_anns += 1
                block_strs.append(meta["string"])
            m, o = ins.mnemonic, ins.op_str
            if m == "call":
                total_calls += 1
                if meta.get("callee") or meta.get("target"):
                    resolved_calls += 1
                if meta.get("indirect"):
                    indirect_unresolved += 1
                callees.append(
                    {
                        "from": hex(addr),
                        "at": hex(ins.address),
                        "to": o,
                        "callee": meta.get("callee"),
                        "targets": [hex(t) for t in (ins.targets or [])],
                    }
                )
                if len(callees) > _MAX_CALLEES:
                    callees[:] = callees[:_MAX_CALLEES]

            tag = f"  /* {ann} */" if ann else ""
            if m == "ret":
                body_lines.append(f"    return /* eax */;{tag}")
            elif m in ("je", "jz") and succs:
                t = succs[0] if len(succs) >= 1 else 0
                f = succs[1] if len(succs) >= 2 else (addr + ins.size)
                body_lines.append(f"    if (ZF) goto L_{t:x}; else goto L_{f:x}; /* {m} {o} */{tag}")
            elif m in ("jne", "jnz") and succs:
                t = succs[0] if succs else 0
                body_lines.append(f"    if (!ZF) goto L_{t:x}; /* {m} {o} */{tag}")
            elif m == "jmp" and succs:
                body_lines.append(f"    goto L_{succs[0]:x};{tag}")
            elif m == "call":
                callee = meta.get("callee") or o
                body_lines.append(f"    call({callee});{tag}")
            elif m.startswith("lea") and meta.get("string"):
                body_lines.append(f"    /* lea → \"{meta['string']}\" */ /* {m} {o} */")
            elif m.startswith("mov"):
                left = o.split(",")[0].strip() if o else "?"
                right = ",".join(o.split(",")[1:]).strip() if o and "," in o else ""
                body_lines.append(f"    {left} = {right}; /* mov */{tag}")
            elif m == "cmp":
                body_lines.append(f"    /* cmp {o} → ZF */{tag}")
            else:
                body_lines.append(f"    /* {m} {o} */{tag}")

        if block_strs:
            uniq = list(dict.fromkeys(block_strs))[:3]
            lines.append(f"    // xref: {', '.join(repr(s) for s in uniq)}")
        lines.extend(body_lines)
        if len(blk.instructions) > 24:
            lines.append(f"    /* … {len(blk.instructions) - 24} more */")
        for u, v in cff.recovered_edges:
            if u == addr:
                lines.append(f"    /* CFF edge → L_{v:x} */")
        if len(succs) == 1 and blk.instructions and blk.instructions[-1].mnemonic not in (
            "jmp",
            "ret",
            "je",
            "jz",
            "jne",
            "jnz",
        ):
            lines.append(f"    goto L_{succs[0]:x};")

    if truncated:
        lines.append(f"  /* … {total_blocks - max_blocks} blocks omitted */")
    lines.append("}")
    if cff.case_map:
        lines.append("/* state machine cases */")
        for imm, tgt in list(sorted(cff.case_map.items()))[:32]:
            lines.append(f"/* case {hex(imm)} → L_{tgt:x} */")

    resolved_targets: List[str] = []
    do_indirect = resolve_indirects and indirect_unresolved > 2 and (
        entry is not None or (function and function.startswith("0x"))
    )
    if do_indirect:
        try:
            from argus.concrete.indirect import resolve_indirect

            ri = resolve_indirect(path, target_va, max_steps=8_000)
            resolved_targets = [hex(x) for x in (ri.get("targets") or [])]
            if resolved_targets:
                lines.append(f"/* dynamic indirect targets: {', '.join(resolved_targets[:8])} */")
        except Exception as e:
            lines.append(f"/* indirect resolve skipped: {e} */")

    known = label in img.symbols
    call_ratio = (resolved_calls / total_calls) if total_calls else 1.0
    if known and cff.case_map:
        confidence = "high"
    elif (known or string_anns >= 2) and call_ratio >= 0.5 and not truncated:
        confidence = "medium"
    elif string_anns or resolved_calls:
        confidence = "medium" if call_ratio >= 0.35 else "low"
    else:
        confidence = "low"

    evidence: Dict[str, Any] = {
        "cff": cff.to_dict(),
        "blocks": total_blocks,
        "shown_blocks": len(block_addrs),
        "style": "pseudo_c_annotated",
        "callees": callees,
        "confidence": confidence,
        "truncated": truncated,
        "entry": hex(cfg.entry),
        "function": label,
        "resolve_reason": reason,
        "string_annotations": string_anns,
        "resolved_calls": resolved_calls,
        "total_calls": total_calls,
        "indirect_unresolved": indirect_unresolved,
        "resolved_targets": resolved_targets,
    }
    return "\n".join(lines), evidence


def annotated_ir(
    path: str,
    *,
    function: Optional[str] = None,
    entry: Optional[int] = None,
    query: Optional[str] = None,
    max_blocks: int = _MAX_LIFT_BLOCKS,
) -> Tuple[str, Dict[str, Any]]:
    """Compact JSON IR for agents."""
    from argus.binary import load_binary
    from argus.deobf.cff import cleaned_adjacency, recover_cff
    from argus.disasm import build_cfg, build_function_cfg
    from argus.disasm.recovery import recover_functions
    from argus.disasm.resolve import resolve_lift_target

    img = load_binary(path)
    fidx = recover_functions(img)

    def idx_label(addr: int) -> Optional[str]:
        if addr in img.imports:
            return img.imports[addr]
        for name, sym in img.symbols.items():
            if sym.addr == addr and sym.is_function:
                return name
        b = fidx.covering(addr)
        return b.name if b else None

    if function and function in img.symbols and entry is None and not query:
        cfg = build_function_cfg(img, function)
        label = function
        reason = "symbol"
    else:
        target = resolve_lift_target(img, function=function, entry=entry, query=query)
        label = target.label
        reason = target.reason
        if label in img.symbols:
            cfg = build_function_cfg(img, label)
        else:
            cfg = build_cfg(img, entry=target.va, function_name=label, max_blocks=max_blocks * 2)

    cff = recover_cff(cfg)
    adj = cleaned_adjacency(cfg, cff) if cff.case_map else {
        a: list(cfg.blocks[a].successors) for a in cfg.blocks
    }
    blocks = []
    for addr in sorted(cfg.blocks)[:max_blocks]:
        blk = cfg.blocks[addr]
        insns = []
        for i in blk.instructions[:32]:
            ann, meta = _annotate_insn(img, i, idx_label=idx_label)
            insns.append({"m": i.mnemonic, "o": i.op_str, "a": hex(i.address), "ann": ann or None, **meta})
        blocks.append(
            {
                "addr": hex(addr),
                "succs": [hex(s) for s in adj.get(addr, list(blk.successors))],
                "insns": insns,
            }
        )
    payload = {
        "function": label,
        "entry": hex(cfg.entry),
        "resolve_reason": reason,
        "cff": cff.to_dict(),
        "blocks": blocks,
    }
    return json.dumps(payload, indent=2), {
        "blocks": len(blocks),
        "cff_cases": len(cff.case_map),
        "function": label,
        "entry": hex(cfg.entry),
        "resolve_reason": reason,
        "confidence": "medium" if blocks else "low",
    }
