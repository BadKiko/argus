from __future__ import annotations

"""LLM agent loop: OpenAI-compat OR native Gemini (AI Studio) with Argus tools."""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from argus.llm.tools import ARGUS_TOOLS, dispatch_tool

SYSTEM = """You are Argus Agent — a reverse-engineering assistant backed by the Argus binary toolkit.

Rules:
- MUST use tools; never invent passwords, function names, license logic, or patch results.
- Answer ONLY from tool JSON fields (summary/evidence/readable/patched_path). If evidence is weak or confidence=low, say so ("неизвестно" / "гипотеза") — do not invent roles for addresses.
- How-it-works / license questions: call argus_find (and argus_analyze) first; then argus_lift only on a hit's nearby_fn or 0xaddr. Do not lift main twice hoping for a story.
- Bypass / remove check / patch:
  1) argus_find with query like "free version" / "license"
  2) Read patch_candidates from the result (or call argus_xrefs on a string addr)
  3) argus_patch kind=force_branch or nop_bytes with that addr
  4) If safety refuses / unsafe — try the NEXT candidate. Do not stop after one refuse.
  NEVER stub main/entry with always_true/ret_imm.
- After every patch the toolkit runs a safety check. If ok=false / safety.safe=false / «unsafe:» — re-patch with next candidate.
- If a patch tool returns ok=false with «refused:», use find/xrefs candidates — do not invent success or retry stubbing main.
- After a successful patch (ok=true AND safety ok), include patched file path + one-line cert.
- Prefer argus_ai for 'дай пароль'.
- Binary paths: pass unchanged. Missing file («нет файла») → stop.
- If a tool fails transiently, retry once.
"""


@dataclass
class AgentResult:
    ok: bool
    answer: str
    steps: int = 0
    provider: str = "openai"
    tool_trace: List[Dict[str, Any]] = field(default_factory=list)
    raw_messages: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "answer": self.answer,
            "steps": self.steps,
            "provider": self.provider,
            "tool_trace": self.tool_trace,
        }


def resolve_provider(provider: Optional[str] = None) -> str:
    p = (provider or os.environ.get("ARGUS_LLM_PROVIDER") or "").strip().lower()
    if p in ("gemini", "google", "ai-studio", "aistudio"):
        return "gemini"
    if p in ("openai", "openai-compat", "compatible"):
        return "openai"
    # auto: prefer gemini if GEMINI key set without openai url override intent
    if os.environ.get("ARGUS_GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    return "openai"


def missing_binary_message(path: str) -> str:
    return f"нет файла: {path}"


def binary_missing(path: Optional[str]) -> bool:
    if not path:
        return False
    return not os.path.isfile(path)


def run_agent(
    user_prompt: str,
    binary: Optional[str] = None,
    *,
    provider: Optional[str] = None,
    url: Optional[str] = None,
    key: Optional[str] = None,
    model: Optional[str] = None,
    max_steps: int = 32,
    verbose: bool = False,
) -> AgentResult:
    # Fail fast — do not call the LLM when the binary path is wrong
    if binary and binary_missing(binary):
        msg = missing_binary_message(binary)
        if verbose:
            print(msg, flush=True)
        return AgentResult(ok=False, answer=msg, steps=0, provider=resolve_provider(provider))

    prov = resolve_provider(provider)
    if prov == "gemini":
        return _run_gemini(user_prompt, binary, key=key, model=model, url=url, max_steps=max_steps, verbose=verbose)
    return _run_openai(user_prompt, binary, key=key, model=model, url=url, max_steps=max_steps, verbose=verbose)


def _run_openai(
    user_prompt: str,
    binary: Optional[str],
    *,
    key: Optional[str],
    model: Optional[str],
    url: Optional[str],
    max_steps: int,
    verbose: bool,
) -> AgentResult:
    from argus.llm.client import LLMConfig, OpenAICompatClient

    cfg = LLMConfig.from_env(url=url, key=key, model=model)
    client = OpenAICompatClient(cfg)

    content = user_prompt
    if binary:
        content = f"{user_prompt}\n\nBinary path: {binary}"

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": content},
    ]
    trace: List[Dict[str, Any]] = []

    for step in range(max_steps):
        resp = client.chat(messages, tools=ARGUS_TOOLS, tool_choice="auto")
        text, tool_calls = client.message_content(resp)
        assistant_msg: Dict[str, Any] = {"role": "assistant", "content": text or ""}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        messages.append(assistant_msg)

        if not tool_calls:
            answer = (text or "").strip() or "(empty model response)"
            return AgentResult(ok=True, answer=answer, steps=step + 1, provider="openai", tool_trace=trace, raw_messages=messages)

        for tc in tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except json.JSONDecodeError:
                args = {}
            if binary and "binary" not in args:
                args["binary"] = binary
            result = dispatch_tool(name, args)
            trace.append({"tool": name, "args": args, "result_preview": result[:500]})
            if verbose:
                print(f"[tool] {name}({json.dumps(args, ensure_ascii=False)[:120]})")
                try:
                    preview = json.loads(result)
                    if preview.get("patched_path"):
                        print(f"patched → {preview['patched_path']}", flush=True)
                except json.JSONDecodeError:
                    pass
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.get("id") or name,
                    "content": result,
                }
            )

    return AgentResult(
        ok=False,
        answer="max tool steps reached — try a narrower prompt",
        steps=max_steps,
        provider="openai",
        tool_trace=trace,
        raw_messages=messages,
    )


def _run_gemini(
    user_prompt: str,
    binary: Optional[str],
    *,
    key: Optional[str],
    model: Optional[str],
    url: Optional[str],
    max_steps: int,
    verbose: bool,
) -> AgentResult:
    from argus.llm.gemini import GeminiClient, GeminiConfig

    cfg = GeminiConfig.from_env(key=key, model=model, url=url)
    if cfg.model.startswith("gemini-3.7"):
        # 3.7-flash often hangs with 0-byte responses on some keys/regions
        import sys

        print(
            f"[warn] model {cfg.model} may hang; prefer gemini-3.6-flash",
            file=sys.stderr,
            flush=True,
        )
    client = GeminiClient(cfg)

    text = user_prompt
    if binary:
        text = f"{user_prompt}\n\nBinary path: {binary}"

    contents: List[Dict[str, Any]] = [{"role": "user", "parts": [{"text": text}]}]
    trace: List[Dict[str, Any]] = []

    for step in range(max_steps):
        if verbose:
            print(f"[gemini] step {step + 1}/{max_steps} model={cfg.model} …", flush=True)
        try:
            resp = client.generate(contents, system=SYSTEM, tools=ARGUS_TOOLS)
        except RuntimeError as e:
            if verbose:
                print(f"[gemini] retryable/error: {e}", flush=True)
            raise
        out_text, calls, model_content = client.parse_response(resp)
        if model_content:
            contents.append(model_content)

        if not calls:
            answer = (out_text or "").strip() or "(empty model response)"
            return AgentResult(
                ok=True,
                answer=answer,
                steps=step + 1,
                provider="gemini",
                tool_trace=trace,
                raw_messages=contents,
            )

        # Gemini: function responses go as a user turn with functionResponse parts
        fr_parts: List[Dict[str, Any]] = []
        for call in calls:
            name = call["name"]
            args = dict(call.get("args") or {})
            if binary and "binary" not in args:
                args["binary"] = binary
            if verbose:
                print(f"[tool] {name}({json.dumps(args, ensure_ascii=False)[:120]})", flush=True)
            result = dispatch_tool(name, args)
            trace.append({"tool": name, "args": args, "result_preview": result[:500]})
            try:
                payload = json.loads(result)
            except json.JSONDecodeError:
                payload = {"result": result}
            if verbose and isinstance(payload, dict) and payload.get("patched_path"):
                print(f"patched → {payload['patched_path']}", flush=True)
            fr_parts.append(
                {
                    "functionResponse": {
                        "name": name,
                        "response": payload if isinstance(payload, dict) else {"result": payload},
                    }
                }
            )
        contents.append({"role": "user", "parts": fr_parts})

    return AgentResult(
        ok=False,
        answer="max tool steps reached — try a narrower prompt",
        steps=max_steps,
        provider="gemini",
        tool_trace=trace,
        raw_messages=contents,
    )
