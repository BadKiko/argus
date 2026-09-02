"""Optional reverse-engineering archetypes (NOT auto-injected into the agent).

Do not call match_archetype from investigate/agent — a keyword like "license" must not
become "AppState bitfield" or "two-stage crypto" in the LLM context. The model forms
hypotheses from tool evidence on the current binary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ProtectionArchetype:
    name: str
    category: str
    description: str
    indicators: List[str]
    vulnerability: str
    recommended_strategy: str


ARCHETYPES: List[ProtectionArchetype] = [
    ProtectionArchetype(
        name="Two-Stage Verification Dialog (Format Parser + Crypto Engine)",
        category="Commercial Software",
        description=(
            "User input is processed in two sequential stages: "
            "Stage 1 checks length, base64/hex encoding, or syntax header. "
            "Stage 2 performs RSA/ECC signature verification or cryptographic hash checks."
        ),
        indicators=[
            "Multiple gates in input handler function",
            "Error dialog triggered before crypto validator",
            "String formatting or base64 decoding calls before validator hub",
        ],
        vulnerability=(
            "Patching the crypto hub alone causes arbitrary keys to be rejected by the syntax parser. "
            "The syntax gate must also be bypassed."
        ),
        recommended_strategy=(
            "Use argus_decision_flow to view the complete gate sequence. "
            "NOP the Stage 1 jump into the error switch (or force Stage 1 gate), "
            "and stub the Stage 2 crypto validator with ret_imm (mov eax, 1; ret)."
        ),
    ),
    ProtectionArchetype(
        name="Global State Struct Invariant (AppState Bitfield)",
        category="Enterprise / Productivity Tools",
        description=(
            "Application maintains an internal session/license struct in heap memory. "
            "A specific byte field (e.g. [reg + 0x9] or [reg + 0x18]) is checked across 20+ functions "
            "to determine whether the UI displays 'Unregistered', enables export, or restricts features."
        ),
        indicators=[
            "Repeated cmp [reg + offset], 1 across multiple modules",
            "Window title formatting checks byte field in state struct",
            "sete / setne instructions setting a struct field",
        ],
        vulnerability=(
            "Patching individual caller checks is fragile. "
            "Forcing the single state writer site unlocks all features globally."
        ),
        recommended_strategy=(
            "Run argus_state_flags(binary) to identify the global struct offset. "
            "Patch the writer site (sete -> mov byte [reg + offset], 1) or force the caller branch."
        ),
    ),
    ProtectionArchetype(
        name="Time-Trial / Expiration Date Check",
        category="Shareware / Demos",
        description=(
            "Application queries system time (GetSystemTime, clock_gettime, time()) "
            "and compares against an expiration timestamp or installation date."
        ),
        indicators=[
            "Calls to GetSystemTime, GetLocalTime, time, or clock_gettime",
            "Comparisons of 64-bit timestamp values followed by jbe / ja",
            "Strings like 'trial expired', 'evaluation period', 'days remaining'",
        ],
        vulnerability="The decision rests on a single time comparison branch.",
        recommended_strategy=(
            "Locate the caller of the time API using argus_decision_flow. "
            "Invert the conditional jump (e.g. ja -> jmp) to permanently treat the trial as valid."
        ),
    ),
    ProtectionArchetype(
        name="Nag Screen / Countdown Delay Timer",
        category="Shareware",
        description=(
            "Application displays a splash nag screen or disables the 'Continue' button "
            "for 5–10 seconds using SetTimer, sleep, or nanosleep."
        ),
        indicators=[
            "Calls to SetTimer, Sleep, usleep, nanosleep",
            "Timer callback functions checking tick counters",
        ],
        vulnerability="Timer duration is stored as an immediate argument (e.g. 5000ms = 0x1388).",
        recommended_strategy=(
            "Patch the sleep/timer duration argument to 0, or force the timer callback to trigger immediately."
        ),
    ),
    ProtectionArchetype(
        name="Exact Checksum / Hash Crackme",
        category="Crackmes / CTF",
        description=(
            "Input is hashed or transformed via custom math loops, then compared "
            "character-by-character or via memcmp against an expected target string."
        ),
        indicators=[
            "Loop containing xor, rol, ror, add with character indexing",
            "Calls to strcmp, memcmp, or string comparison loop",
        ],
        vulnerability="Linear mathematical transformation solvable by SMT/Z3 solvers.",
        recommended_strategy=(
            "Map the compare with argus_find / argus_peek, then argus_exec if you need a solver probe. "
            "Alternatively stub authenticate to return 1."
        ),
    ),
]


def match_archetype(
    query_or_task: str,
    *,
    has_multiple_gates: bool = False,
    has_state_struct: bool = False,
    has_time_apis: bool = False,
) -> ProtectionArchetype:
    """Classify target scenario into a known reverse-engineering archetype."""
    low = (query_or_task or "").lower()

    if "trial" in low or "expire" in low or "days" in low or has_time_apis:
        return ARCHETYPES[2]  # Time-Trial

    if "nag" in low or "wait" in low or "timer" in low or "delay" in low:
        return ARCHETYPES[3]  # Nag Screen

    if has_state_struct or "unregistered" in low or "license" in low:
        if has_multiple_gates:
            return ARCHETYPES[0]  # Two-Stage Dialog
        return ARCHETYPES[1]  # Global State Struct

    if "password" in low or "crackme" in low or "serial" in low:
        return ARCHETYPES[4]  # Hash Crackme

    return ARCHETYPES[0]  # Default to Two-stage verification
