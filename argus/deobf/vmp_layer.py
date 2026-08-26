from __future__ import annotations

"""VMProtect / Themida research hooks: detect + optional external trace → synth."""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Protocol

from argus.binary.image import BinaryImage
from argus.deobf.detect import ProtectionReport, detect_protection
from argus.deobf.vm import HandlerSynthesizer, HandlerSynthResult


class VMPTraceProvider(Protocol):
    """External pin/trace provider (Salwan-style) feeding handler I/O samples."""

    def handler_samples(self) -> Dict[int, List[tuple]]:
        """opcode -> list of (a, b, result) concrete triples."""
        ...


@dataclass
class VMPLayerReport:
    protection: ProtectionReport
    stub_blocks: List[int] = field(default_factory=list)
    import_hints: List[str] = field(default_factory=list)
    handlers: Dict[int, HandlerSynthResult] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "protection": self.protection.to_dict(),
            "stub_blocks": [hex(a) for a in self.stub_blocks],
            "import_hints": self.import_hints,
            "handlers": {hex(k): {"name": v.name, "proved": v.proved} for k, v in self.handlers.items()},
            "notes": self.notes,
        }


def map_entry_stub(image: BinaryImage, max_blocks: int = 40) -> List[int]:
    from argus.disasm import build_cfg

    try:
        cfg = build_cfg(image, entry=image.entry, max_blocks=max_blocks)
    except Exception:
        return []
    return sorted(cfg.blocks.keys())[:max_blocks]


def analyze_vmp_layer(
    image: BinaryImage,
    trace: Optional[VMPTraceProvider] = None,
) -> VMPLayerReport:
    prot = detect_protection(image)
    notes = list(prot.indicators)
    stubs = []
    if prot.kind in ("vmp", "themida", "mixed", "unknown"):
        stubs = map_entry_stub(image)
        notes.append(f"entry stub blocks={len(stubs)}")
    hints = []
    for addr, name in sorted(image.imports.items())[:30]:
        hints.append(f"{hex(addr)}:{name}")
    handlers: Dict[int, HandlerSynthResult] = {}
    if trace is not None:
        synth = HandlerSynthesizer()
        for opc, samples in trace.handler_samples().items():
            handlers[opc] = synth.synthesize_from_samples(list(samples))
            notes.append(f"synth opc={opc:#x} -> {handlers[opc].name}")
    elif prot.kind in ("vmp", "themida", "mixed"):
        notes.append("no VMPTraceProvider; detect+stub only (partial layer)")

    return VMPLayerReport(
        protection=prot,
        stub_blocks=stubs,
        import_hints=hints,
        handlers=handlers,
        notes=notes,
    )


@dataclass
class DictTraceProvider:
    """In-process stand-in for an external tracer."""

    samples: Dict[int, List[tuple]]

    def handler_samples(self) -> Dict[int, List[tuple]]:
        return self.samples
