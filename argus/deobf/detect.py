from __future__ import annotations

"""Protection detection heuristics (OLLVM / VMP / Themida)."""

from dataclasses import dataclass, field
from typing import List, Optional

from argus.binary.image import BinaryImage


@dataclass
class ProtectionReport:
    kind: str  # none|ollvm|vmp|themida|mixed|unknown
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


def detect_protection(image: BinaryImage) -> ProtectionReport:
    indicators: List[str] = []
    scores = {"ollvm": 0.0, "vmp": 0.0, "themida": 0.0, "none": 0.1}

    names = [s.name.lower() for s in image.sections]
    joined = " ".join(names)

    # VMProtect
    vmp_names = (".vmp", "vmp0", "vmp1", ".themida", ".winlice", ".nsp")
    if any(any(k in n for k in (".vmp", "vmp0", "vmp1")) for n in names):
        scores["vmp"] += 0.6
        indicators.append("vmp section name")
    indicators.extend(_section_entropy_high(image))
    if image.fmt == "pe" and len(image.sections) >= 7 and any("high entropy" in i or "packed" in i for i in indicators):
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

    # OLLVM: many conditional blocks / symbols often still present; weak static signal
    func_syms = [s for s in image.symbols.values() if s.is_function and not s.is_import and s.addr]
    if image.fmt == "elf" and len(func_syms) >= 3:
        # flattened functions tend to be large
        large = [s for s in func_syms if s.size >= 400]
        if large:
            scores["ollvm"] += 0.35
            indicators.append(f"large functions x{len(large)}")

    # String markers sometimes left by toolchains
    for s in image.sections:
        if not s.data:
            continue
        if b"VMProtect" in s.data[: min(len(s.data), 200000)]:
            scores["vmp"] += 0.5
            indicators.append("VMProtect string")
            break
        if b"Themida" in s.data[: min(len(s.data), 200000)] or b"Oreans" in s.data[: min(len(s.data), 200000)]:
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
