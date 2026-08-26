from __future__ import annotations

"""Natural-language prompt → Hint for `argus ai \"…\" binary`."""

import re
from typing import Optional, Tuple

from argus.ask import Hint, PatchKind, Want
from argus.concrete.concolic import parse_stdin_hint


_RULES: list[Tuple[re.Pattern, Want, Optional[PatchKind]]] = [
    (re.compile(r"(парол|password|passwd|secret|флаг|flag|crack|ключ|key\b|логин|login|админ|admin)", re.I), Want.PASSWORD, None),
    (
        re.compile(
            r"(всегда\s*true|always\s*true|bypass|обойд|пропуск|без\s*парол|skip\s*auth|"
            r"force\s*success|всегда\s*успех|всегда\s*пускай|auth\s*true)",
            re.I,
        ),
        Want.PATCH,
        PatchKind.ALWAYS_TRUE,
    ),
    # Remove / disable license or check → patch (must beat lift rule with «проверк|лиценз»)
    (
        re.compile(
            r"(убер(и|ать)\s*(проверк|лиценз)|отключ(и|ить)\s*(проверк|лиценз)|"
            r"обойд\w*\s*(лиценз|license|проверк)|bypass\s*(licen|check)|"
            r"disable\s*(licen|check)|патч\w*\s*(лиценз|проверк|license)|"
            r"убери\s*лиценз|nop\s*call|force\s*branch|ret_imm|nop_bytes)",
            re.I,
        ),
        Want.PATCH,
        PatchKind.SKIP_CHECK,
    ),
    (re.compile(r"(всегда\s*false|always\s*false|force\s*fail)", re.I), Want.PATCH, PatchKind.ALWAYS_FALSE),
    (re.compile(r"(skip\s*check|убери\s*проверк|nop\s*strcmp|отключ(и|ить)\s*проверк)", re.I), Want.PATCH, PatchKind.SKIP_CHECK),
    (re.compile(r"(убер(и|ать)\s*(запрос|промпт)|nop\s*prompt|без\s*username|убери\s*password)", re.I), Want.PATCH, PatchKind.NOP_PROMPTS),
    (re.compile(r"(деобф|deobf|unflatten|распрям|убер(и|ать)\s*fla|cff|flatten)", re.I), Want.DEOBF, None),
    (re.compile(r"\bir\b|json\s*ir|блок(и|ов)\s*ir", re.I), Want.IR, None),
    # How-it-works / show code (license as topic, not remove)
    (
        re.compile(
            r"(покаж(и|ать)|lift|прочит|читаем|псевдо|disasm|код\s*функ|разбер|"
            r"как\s*работ|vmp|лиценз|license|проверк)",
            re.I,
        ),
        Want.LIFT,
        None,
    ),
    (re.compile(r"(отчёт|отчет|report|анализ|analyze|что\s*за\s*защит|detect)", re.I), Want.REPORT, None),
]


_FN_PATTERNS = [
    re.compile(r"(?:функци[яи]|function|в)\s+[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?", re.I),
    re.compile(r"\b(authenticate|check_password|verify|target_function|main)\b", re.I),
]

_ADDR_PAT = re.compile(r"(?:@|addr(?:ess)?\s*[:=]?\s*|по\s+адресу\s+)(0x[0-9a-fA-F]+|\d+)", re.I)
_SIZE_PAT = re.compile(r"(?:size|разм\w*|байт)\s*[:=]?\s*(\d+)", re.I)


def parse_prompt(prompt: str, output: Optional[str] = None) -> Hint:
    text = (prompt or "").strip()
    want = Want.PASSWORD
    patch_kind: Optional[PatchKind] = None
    # Prefer non-password rules first, then password (index 0 last among matches)
    priority_idx = list(range(1, len(_RULES))) + [0]
    for i in priority_idx:
        rx, w, pk = _RULES[i]
        if rx.search(text):
            want, patch_kind = w, pk
            break

    # Fine-tune patch kind from wording
    if want == Want.PATCH:
        if re.search(r"nop_bytes|nop\s+call", text, re.I):
            patch_kind = PatchKind.NOP_BYTES
        elif re.search(r"force\s*branch|force_branch", text, re.I):
            patch_kind = PatchKind.FORCE_BRANCH
        elif re.search(r"ret_imm|ret\s+imm", text, re.I):
            patch_kind = PatchKind.RET_IMM
        elif re.search(r"always\s*true|всегда\s*true", text, re.I):
            patch_kind = PatchKind.ALWAYS_TRUE

    fn = None
    for rx in _FN_PATTERNS:
        m = rx.search(text)
        if m:
            fn = m.group(1)
            break

    patch_addr = None
    m = _ADDR_PAT.search(text)
    if m:
        patch_addr = int(m.group(1), 0)

    patch_size = None
    m = _SIZE_PAT.search(text)
    if m:
        patch_size = int(m.group(1))

    seed = parse_stdin_hint(text)
    return Hint(
        want=want,
        function=fn,
        patch_kind=patch_kind,
        find=b"Welcome",
        output=output,
        note=text,
        stdin_seed=seed,
        patch_addr=patch_addr,
        branch_addr=patch_addr if patch_kind == PatchKind.FORCE_BRANCH else None,
        patch_size=patch_size,
    )


def ai(path: str, prompt: str, output: Optional[str] = None):
    from argus.ask import ask

    return ask(path, parse_prompt(prompt, output=output))
