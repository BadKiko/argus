from __future__ import annotations

"""Protection detection heuristics (OLLVM / VMP / Themida / stripped)."""

from dataclasses import dataclass, field
from typing import List

from argus.binary.image import BinaryImage


@dataclass
class ProtectionReport:
    kind: str  # none|ollvm|vmp|themida|mixed|stripped|unknown
    confidence: float
    indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "confidence": self.confidence,
            "indicators": self.indicators,
        }


def _section_entropy_high(image: BinaryImage, threshold: float = 7.0) -> List[str]:
    import math
    from collections import Counter

    hits = []
    for s in image.sections:
        if not s.data or len(s.data) < 256:
            continue
        c = Counter(s.data)
        ent = -sum((n / len(s.data)) * math.log2(n / len(s.data)) for n in c.values())
        if ent >= threshold and (s.executable or "vmp" in s.name.lower() or ".vmp" in s.name.lower()):
            hits.append(f"high entropy {s.name}={ent:.2f}")
        if ent >= 7.2 and len(s.data) > 4096:
            hits.append(f"packed-like {s.name}={ent:.2f}")
    return hits


def _text_size(image: BinaryImage) -> int:
    best = 0
    for s in image.sections:
        if s.executable and s.data:
            best = max(best, len(s.data))
    return best


def _local_functions(image: BinaryImage) -> list:
    return [s for s in image.symbols.values() if s.is_function and not s.is_import and s.addr]


def _looks_stripped(image: BinaryImage) -> bool:
    """Few named locals + large .text → commercial stripped (not OLLVM CFF)."""
    locals_ = _local_functions(image)
    text = _text_size(image)
    # allocator-only / CRT leftovers don't count as app functions
    junk = ("malloc", "free", "calloc", "realloc", "memalign", "valloc", "aligned_alloc", "posix_memalign")
    real = [s for s in locals_ if s.name and not any(s.name == j or s.name.startswith(j + "@") for j in junk)]
    if text >= 2_000_000 and len(real) < 30:
        return True
    if text >= 500_000 and len(real) < 5:
        return True
    return False


def _probe_cff_signal(image: BinaryImage) -> bool:
    """Cheap structural OLLVM signal: recover_cff finds a dispatcher on a known func/entry."""
    try:
        from argus.deobf.cff import recover_cff
        from argus.disasm import build_cfg, build_function_cfg
    except Exception:
        return False

    targets: list[str | None] = []
    if "main" in image.symbols:
        targets.append("main")
    targets.append(None)  # entry CFG

    for name in targets[:2]:
        try:
            if name:
                cfg = build_function_cfg(image, name)
            else:
                cfg = build_cfg(image, entry=image.entry, max_blocks=120)
            if len(cfg.blocks) < 8:
                continue
            report = recover_cff(cfg)
            if report.dispatcher and len(report.case_map) >= 3:
                return True
        except Exception:
            continue
    return False


def detect_protection(image: BinaryImage) -> ProtectionReport:
    indicators: List[str] = []
    scores = {"ollvm": 0.0, "vmp": 0.0, "themida": 0.0, "stripped": 0.0, "none": 0.1}

    names = [s.name.lower() for s in image.sections]

    # VMProtect
    if any(any(k in n for k in (".vmp", "vmp0", "vmp1")) for n in names):
        scores["vmp"] += 0.6
        indicators.append("vmp section name")
    indicators.extend(_section_entropy_high(image))
    if image.fmt == "pe" and len(image.sections) >= 7 and any(
        "high entropy" in i or "packed" in i for i in indicators
    ):
        scores["vmp"] += 0.2

    # Themida
    if any("themida" in n or "winlice" in n or ".themida" in n for n in names):
        scores["themida"] += 0.7
        indicators.append("themida section")
    path_l = image.path.lower()
    if "themida" in path_l:
        scores["themida"] += 0.3
        indicators.append("filename themida")
    if "vmp" in path_l or ".vmp." in path_l:
        scores["vmp"] += 0.55
        indicators.append("filename vmp")

    stripped = _looks_stripped(image)
    if stripped:
        scores["stripped"] += 0.55
        locals_n = len(_local_functions(image))
        indicators.append(f"stripped-like locals={locals_n} text={_text_size(image)}")

    # OLLVM only with structural CFF signal — NOT "large symbols" alone (false on Qt apps)
    if image.fmt == "elf" and not stripped:
        func_syms = _local_functions(image)
        large = [s for s in func_syms if s.size >= 400]
        if large and _probe_cff_signal(image):
            scores["ollvm"] += 0.55
            indicators.append(f"cff dispatcher + large funcs x{len(large)}")
        elif large:
            # soft hint only — do not win kind on this alone
            indicators.append(f"large functions x{len(large)} (not enough for ollvm)")

    # Filename/corpus hints (samples), still require not stripped-commercial
    if ("fla" in path_l or "flatten" in path_l or "ollvm" in path_l) and not stripped:
        if _probe_cff_signal(image):
            scores["ollvm"] += 0.35
            indicators.append("filename flatten/ollvm + cff")
        else:
            indicators.append("filename flatten/ollvm without cff probe")

    # String markers sometimes left by toolchains
    for s in image.sections:
        if not s.data:
            continue
        chunk = s.data[: min(len(s.data), 200000)]
        if b"VMProtect" in chunk:
            scores["vmp"] += 0.5
            indicators.append("VMProtect string")
            break
        if b"Themida" in chunk or b"Oreans" in chunk:
            scores["themida"] += 0.5
            indicators.append("Themida/Oreans string")
            break

    kind = max(scores, key=scores.get)
    conf = scores[kind]
    if conf < 0.3:
        kind = "unknown" if indicators else "none"
        conf = 0.2 if indicators else 0.5
    if scores["vmp"] >= 0.3 and scores["themida"] >= 0.3:
        kind = "mixed"
        conf = max(scores["vmp"], scores["themida"])
    return ProtectionReport(kind=kind, confidence=min(conf, 1.0), indicators=indicators[:20])
