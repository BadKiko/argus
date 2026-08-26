from __future__ import annotations

"""Concolic helpers: concrete Unicorn run until branch, then symbolic fork."""

from dataclasses import dataclass
from typing import List, Optional, Set

from argus.binary.image import BinaryImage
from argus.concrete import unicorn_available
from argus.symbolic.engine import Engine
from argus.symbolic.state import SimState


@dataclass
class ConcolicSeed:
    stdin: bytes
    hit: Optional[int]
    stdout: bytes
    steps: int


def concrete_until_branch(
    image: BinaryImage,
    stdin: bytes = b"",
    max_steps: int = 50_000,
) -> Optional[ConcolicSeed]:
    """Run Unicorn concretely; return seed metadata for explorer warm-start."""
    if not unicorn_available() or image.fmt != "elf" or image.arch != "x86_64":
        return None
    try:
        from argus.concrete.runner import UnicornRunner

        r = UnicornRunner(image, max_steps=max_steps).run(stdin=stdin)
        return ConcolicSeed(
            stdin=stdin[: r.stdin_consumed] if r.stdin_consumed else stdin,
            hit=r.hit_addresses[0] if r.hit_addresses else None,
            stdout=r.stdout,
            steps=r.steps,
        )
    except Exception:
        return None


def parse_stdin_hint(note: str) -> Optional[bytes]:
    """NLP-lite: extract stdin seed from free-text hint."""
    import re

    m = re.search(r"stdin\s*=\s*['\"]([^'\"]+)['\"]", note, re.I)
    if m:
        return m.group(1).encode("latin1").replace(b"\\n", b"\n")
    m = re.search(r"password\s*length\s*(\d+)", note, re.I)
    if m:
        return b"A" * int(m.group(1)) + b"\n"
    m = re.search(r"len(?:gth)?\s*=?\s*(\d+)", note, re.I)
    if m and int(m.group(1)) <= 64:
        return b"A" * int(m.group(1))
    return None
