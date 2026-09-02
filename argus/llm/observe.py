from __future__ import annotations

"""Start-of-session observe plan: where to look first.

A short ranking pass (deterministic, optionally refined by a second LLM call)
turns TARGET BRIEF + user task into CHECK FIRST for the agent. Paths are snapped
to files that exist in the brief; queries must share tokens with the user prompt.
"""

import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from argus.payload import demote_observe_name, format_brief_text, rank_observe_modules

PLANNER_SYSTEM = """You rank where a reverse-engineering agent should LOOK FIRST.

You receive TARGET BRIEF (files, sizes, kinds) and USER TASK.
Output JSON only, no markdown:
{
  "check_first": [{"name": "filename", "why": "one line"}],
  "find_queries": ["phrase copied from the user task"],
  "skip": ["filename"],
  "notes": "one line"
}

Rules:
- check_first names MUST be files listed in the brief (payload modules or siblings).
- If execution is host_runtime or payload_ir is text/archive: check_first is those payload archives/text files, never the host ELF/PE, never LICENSE*/LICENSES*, never GPU libs (libGLES, libEGL).
- find_queries: copy nouns/phrases from USER TASK. Do not invent UI strings the user did not write. Do not use generic engine legalese (Origin Trial, LICENSE.txt).
- skip: legal dumps, chrome-sandbox, crashpad, GPU libs.
- No product names. No virtual addresses.
"""

_STOP = frozenset(
    {
        "this",
        "that",
        "with",
        "from",
        "please",
        "just",
        "want",
        "need",
        "make",
        "сделай",
        "чтобы",
        "этот",
        "эта",
        "это",
        "файл",
        "путь",
        "программа",
        "просто",
        "нужно",
        "надо",
        "можно",
        "also",
        "then",
        "into",
        "your",
        "have",
        "will",
    }
)
_QUOTE_RX = re.compile(r"[\"«»']([^\"«»']{3,80})[\"«»']")
_WORD_RX = re.compile(r"[A-Za-zА-Яа-яЁё]{4,}")


def planner_enabled() -> bool:
    raw = (os.environ.get("ARGUS_OBSERVE_PLANNER") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def needles_from_task(prompt: str, *, cap: int = 6) -> List[str]:
    """Needles that actually appear in the user task — no invented UI copy."""
    text = prompt or ""
    out: List[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        t = " ".join((s or "").split())
        if len(t) < 3:
            return
        key = t.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(t)

    for m in _QUOTE_RX.finditer(text):
        _add(m.group(1).strip())
    for w in _WORD_RX.findall(text):
        if w.lower() in _STOP:
            continue
        _add(w)
        if len(out) >= cap:
            break
    return out[:cap]


def _pool_files(brief: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for key in ("payloads", "siblings"):
        for r in brief.get(key) or []:
            pth = str(r.get("path") or "")
            if not pth or pth in seen:
                continue
            seen.add(pth)
            rec = dict(r)
            rec.setdefault("name", Path(pth).name)
            rows.append(rec)
    return rows


def _resolve_named(name: str, pool: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    want = (name or "").strip()
    if not want:
        return None
    want_l = want.lower()
    for r in pool:
        nm = str(r.get("name") or "")
        pth = str(r.get("path") or "")
        if nm == want or Path(pth).name == want:
            return r
        if nm.lower() == want_l or Path(pth).name.lower() == want_l:
            return r
        if pth == want or pth.endswith("/" + want) or pth.endswith("\\" + want):
            return r
    for r in pool:
        nm = str(r.get("name") or "")
        if want_l in nm.lower() or nm.lower() in want_l:
            return r
    return None


def _query_grounded(q: str, prompt: str) -> bool:
    ql = (q or "").strip().lower()
    pl = (prompt or "").lower()
    if len(ql) < 3:
        return False
    if ql in pl:
        return True
    tokens = _WORD_RX.findall(ql)
    return any(t.lower() in pl for t in tokens if len(t) >= 4)


def deterministic_observe_plan(brief: Dict[str, Any], user_prompt: str) -> Dict[str, Any]:
    try:
        from argus.deobf.commercial import commercial_observe_plan

        comm_plan = commercial_observe_plan(brief, user_prompt)
        if comm_plan:
            return comm_plan
    except Exception:
        pass
    pool = _pool_files(brief)
    ranked = rank_observe_modules(pool)
    skip = [
        str(r.get("name") or Path(str(r.get("path") or "")).name)
        for r in ranked
        if demote_observe_name(str(r.get("name") or ""), str(r.get("path") or ""))
    ]
    keep: List[Dict[str, Any]] = []
    for r in ranked:
        name = str(r.get("name") or Path(str(r.get("path") or "")).name)
        if demote_observe_name(name, str(r.get("path") or "")):
            continue
        kind = str(r.get("kind") or "")
        if brief.get("execution") == "host_runtime" and kind not in ("archive", "text"):
            continue
        keep.append(r)
        if len(keep) >= 5:
            break
    if not keep:
        keep = [
            r
            for r in ranked
            if not demote_observe_name(str(r.get("name") or ""), str(r.get("path") or ""))
        ][:5]
    queries = needles_from_task(user_prompt)
    host = brief.get("execution") == "host_runtime" or str(brief.get("payload_ir") or "") in (
        "text",
        "archive",
    )
    notes = ""
    if host:
        notes = (
            "payload_ir is not native — first argus_find/atlas on CHECK FIRST modules "
            "(pass binary= that payload path); do not argus_analyze host _start or apply native jcc on the shell"
        )
    check_first = []
    for r in keep:
        kind = str(r.get("kind") or "")
        why = "payload module listed in the brief"
        if kind == "archive":
            why = "largest/highest-rank payload archive"
        elif kind == "text":
            why = "sidecar text payload"
        check_first.append(
            {
                "name": str(r.get("name") or Path(str(r.get("path") or "")).name),
                "path": str(r.get("path") or ""),
                "kind": kind,
                "why": why,
            }
        )
    return {
        "source": "deterministic",
        "check_first": check_first,
        "find_queries": queries,
        "skip": skip[:12],
        "first_tools": ["argus_find"],
        "notes": notes,
    }


def _parse_json_obj(text: str) -> Optional[Dict[str, Any]]:
    raw = (text or "").strip()
    if not raw:
        return None
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def merge_llm_plan(
    base: Dict[str, Any],
    llm: Dict[str, Any],
    brief: Dict[str, Any],
    user_prompt: str,
) -> Dict[str, Any]:
    pool = _pool_files(brief)
    check: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in llm.get("check_first") or []:
        if isinstance(item, str):
            name, why = item, ""
        elif isinstance(item, dict):
            name = str(item.get("name") or item.get("path") or "")
            why = str(item.get("why") or "")
        else:
            continue
        hit = _resolve_named(name, pool)
        if not hit:
            continue
        pth = str(hit.get("path") or "")
        if pth in seen:
            continue
        seen.add(pth)
        nm = str(hit.get("name") or Path(pth).name)
        if demote_observe_name(nm, pth):
            continue
        check.append(
            {
                "name": nm,
                "path": pth,
                "kind": str(hit.get("kind") or ""),
                "why": (why or "ranked for this task")[:160],
            }
        )
        if len(check) >= 5:
            break
    queries: List[str] = []
    qseen: set[str] = set()
    for q in list(llm.get("find_queries") or []) + list(base.get("find_queries") or []):
        s = str(q or "").strip()
        if not s or not _query_grounded(s, user_prompt):
            continue
        key = s.lower()
        if key in qseen:
            continue
        qseen.add(key)
        queries.append(s)
        if len(queries) >= 6:
            break
    skip: List[str] = []
    sseen: set[str] = set()
    for name in list(llm.get("skip") or []) + list(base.get("skip") or []):
        hit = _resolve_named(str(name), pool)
        label = str(hit.get("name") if hit else name)
        if not label or label.lower() in sseen:
            continue
        sseen.add(label.lower())
        skip.append(label)
        if len(skip) >= 12:
            break
    notes = str(llm.get("notes") or base.get("notes") or "")[:400]
    out = dict(base)
    out["source"] = "llm"
    if check:
        out["check_first"] = check
    if queries:
        out["find_queries"] = queries
    out["skip"] = skip
    if notes:
        out["notes"] = notes
    return out


def format_observe_plan(plan: Dict[str, Any]) -> str:
    lines = [
        "CHECK FIRST (ranking pass — do these finds before peeking the host ELF):",
    ]
    queries = [str(q) for q in (plan.get("find_queries") or []) if q]
    q0 = queries[0] if queries else "<nouns from USER TASK>"
    for i, row in enumerate(plan.get("check_first") or [], 1):
        name = row.get("name") or Path(str(row.get("path") or "")).name
        kind = row.get("kind") or ""
        why = row.get("why") or ""
        path = row.get("path") or ""
        extra = f"  {why}" if why else ""
        lines.append(f"  {i}. {name}  kind={kind}{extra}")
        if path:
            lines.append(f"     argus_find(binary={path}, query={q0})")
    if queries:
        lines.append("  queries: " + ", ".join(queries[:6]))
    skip = plan.get("skip") or []
    if skip:
        lines.append("  skip: " + ", ".join(str(s) for s in skip[:10]))
    if plan.get("notes"):
        lines.append(f"  note: {plan['notes']}")
    tools = plan.get("first_tools") or ["argus_find"]
    lines.append("  first tools: " + ", ".join(str(t) for t in tools[:4]))
    return "\n".join(lines)


def _one_shot_openai(system: str, user: str, *, url: Optional[str], key: Optional[str], model: Optional[str]) -> str:
    from argus.llm.client import LLMConfig, OpenAICompatClient

    cfg = LLMConfig.from_env(url=url, key=key, model=model)
    cfg.timeout = min(float(cfg.timeout or 120), 25.0)
    client = OpenAICompatClient(cfg)
    resp = client.chat(
        [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        tools=None,
        temperature=0.1,
    )
    text, _ = client.message_content(resp)
    return text or ""


def _one_shot_gemini(system: str, user: str, *, url: Optional[str], key: Optional[str], model: Optional[str]) -> str:
    from argus.llm.gemini import DEFAULT_GEMINI_BASE, DEFAULT_GEMINI_MODEL, GeminiConfig

    cfg = GeminiConfig.from_env(key=key, model=model, url=url)
    mdl = cfg.model or DEFAULT_GEMINI_MODEL
    if mdl.startswith("models/"):
        mdl = mdl[len("models/") :]
    base = (url or cfg.base_url or DEFAULT_GEMINI_BASE).rstrip("/")
    if base.endswith("/openai"):
        base = base[: -len("/openai")]
    endpoint = f"{base}/models/{mdl}:generateContent"
    payload = {
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "systemInstruction": {"parts": [{"text": system}]},
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 512},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "argus-re/0.2",
            "x-goog-api-key": cfg.api_key,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=min(float(cfg.timeout or 60), 25.0)) as resp:
        body = json.loads(resp.read().decode("utf-8", errors="replace"))
    cands = body.get("candidates") or []
    if not cands:
        return ""
    parts = (cands[0].get("content") or {}).get("parts") or []
    return "\n".join(str(p.get("text") or "") for p in parts if p.get("text")).strip()


def llm_refine_observe_plan(
    base: Dict[str, Any],
    brief: Dict[str, Any],
    user_prompt: str,
    *,
    generate_text: Optional[Callable[[str, str], str]] = None,
    provider: str = "",
    url: Optional[str] = None,
    key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    user = (
        format_brief_text(brief)
        + "\n\nUSER TASK:\n"
        + (user_prompt or "").strip()
        + "\n\nDETERMINISTIC RANKING (you may reorder, not invent files):\n"
        + format_observe_plan(base)
    )
    if generate_text is not None:
        raw = generate_text(PLANNER_SYSTEM, user)
    elif (provider or "").lower() == "gemini":
        raw = _one_shot_gemini(PLANNER_SYSTEM, user, url=url, key=key, model=model)
    else:
        raw = _one_shot_openai(PLANNER_SYSTEM, user, url=url, key=key, model=model)
    obj = _parse_json_obj(raw)
    if not obj:
        return base
    return merge_llm_plan(base, obj, brief, user_prompt)


def build_observe_plan(
    brief: Optional[Dict[str, Any]],
    user_prompt: str,
    *,
    generate_text: Optional[Callable[[str, str], str]] = None,
    provider: str = "",
    url: Optional[str] = None,
    key: Optional[str] = None,
    model: Optional[str] = None,
    use_llm: Optional[bool] = None,
) -> Dict[str, Any]:
    brief = brief or {}
    base = deterministic_observe_plan(brief, user_prompt)
    want_llm = planner_enabled() if use_llm is None else use_llm
    if generate_text is not None and use_llm is not False:
        want_llm = True
    elif (
        use_llm is None
        and generate_text is None
        and os.environ.get("PYTEST_CURRENT_TEST")
        and (os.environ.get("ARGUS_OBSERVE_PLANNER") or "").strip().lower() != "force"
    ):
        want_llm = False
    if not want_llm or not brief:
        return base
    try:
        return llm_refine_observe_plan(
            base,
            brief,
            user_prompt,
            generate_text=generate_text,
            provider=provider,
            url=url,
            key=key,
            model=model,
        )
    except Exception:
        return base
