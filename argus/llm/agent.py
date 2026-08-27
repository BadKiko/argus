from __future__ import annotations

"""LLM agent loop: OpenAI-compat OR native Gemini (AI Studio) with Argus tools."""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from argus.llm.tools import ARGUS_TOOLS, dispatch_tool

SYSTEM = """You are Argus Agent — a reverse-engineering assistant backed by the Argus binary toolkit.

Rules:
- MUST use tools; never invent results.
- The user message lists TASKS (free-form). Address EVERY task. Bind EVERY tool call with for_task=<id>.
- Do not invent success. Runtime finalizes each task from tool evidence; your closing prose is ignored for status.
- Prefer argus_find then argus_patch. For text changes: replace_string with exact old from hits; new ≤ len(old) bytes (pad spaces).
- Never shorten resource filenames. Never stub main/entry.
- Logic patches (force_branch/ret_imm) alone do NOT auto-complete a TASK — use argus_unlock_apply for unlock.
- If ETXTBSY / Text file busy: stop claiming that task done; user must quit the app.
- Missing file → stop.
- Stripped: argus_lift with entry=0x… or query=\"exact string\" — do not claim CFF deobf success.
- Unlock/license: (1) argus_slice (2) ONE argus_unlock_apply using unlock_plan steps (or omit steps to auto-apply).
  Do not freestyle-patch parser gates outside unlock_plan. Honor taken=/value= from the plan.
  Never claim GUI activation; done only when unlock_bytes verify.ok. rodata Unregistered may remain.
"""


@dataclass
class AgentResult:
    ok: bool
    answer: str
    steps: int = 0
    provider: str = "openai"
    tool_trace: List[Dict[str, Any]] = field(default_factory=list)
    raw_messages: List[Dict[str, Any]] = field(default_factory=list)
    task_statuses: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "answer": self.answer,
            "steps": self.steps,
            "provider": self.provider,
            "tool_trace": self.tool_trace,
            "task_statuses": self.task_statuses,
        }


def resolve_provider(provider: Optional[str] = None) -> str:
    p = (provider or os.environ.get("ARGUS_LLM_PROVIDER") or "").strip().lower()
    if p in ("gemini", "google", "ai-studio", "aistudio"):
        return "gemini"
    if p in ("openai", "openai-compat", "compatible"):
        return "openai"
    if os.environ.get("ARGUS_GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    return "openai"


def missing_binary_message(path: str) -> str:
    return f"нет файла: {path}"


def binary_missing(path: Optional[str]) -> bool:
    if not path:
        return False
    return not os.path.isfile(path)


def _build_user_content(user_prompt: str, binary: Optional[str], tasks_block: str) -> str:
    parts = [user_prompt.strip()]
    if tasks_block:
        parts.append("")
        parts.append(tasks_block)
    if binary:
        parts.append("")
        parts.append(f"Binary path: {binary}")
    return "\n".join(parts)


def _trace_append(trace: List[Dict[str, Any]], name: str, args: Dict[str, Any], result: str) -> None:
    entry: Dict[str, Any] = {
        "tool": name,
        "args": args,
        "result_preview": result[:2000],
    }
    try:
        entry["result"] = json.loads(result)
    except json.JSONDecodeError:
        pass
    trace.append(entry)


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
    from argus.llm.tasks import finalize_agent, format_tasks_block, split_user_tasks

    if binary and binary_missing(binary):
        msg = missing_binary_message(binary)
        if verbose:
            print(msg, flush=True)
        return AgentResult(ok=False, answer=msg, steps=0, provider=resolve_provider(provider))

    tasks = split_user_tasks(user_prompt)
    tasks_block = format_tasks_block(tasks)
    prov = resolve_provider(provider)
    if prov == "gemini":
        return _run_gemini(
            user_prompt,
            binary,
            tasks=tasks,
            tasks_block=tasks_block,
            key=key,
            model=model,
            url=url,
            max_steps=max_steps,
            verbose=verbose,
        )
    return _run_openai(
        user_prompt,
        binary,
        tasks=tasks,
        tasks_block=tasks_block,
        key=key,
        model=model,
        url=url,
        max_steps=max_steps,
        verbose=verbose,
    )


def _run_openai(
    user_prompt: str,
    binary: Optional[str],
    *,
    tasks,
    tasks_block: str,
    key: Optional[str],
    model: Optional[str],
    url: Optional[str],
    max_steps: int,
    verbose: bool,
) -> AgentResult:
    from argus.llm.client import LLMConfig, OpenAICompatClient
    from argus.llm.tasks import finalize_agent, open_tasks_hint

    cfg = LLMConfig.from_env(url=url, key=key, model=model)
    client = OpenAICompatClient(cfg)

    content = _build_user_content(user_prompt, binary, tasks_block)
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
            return finalize_agent(
                tasks,
                trace,
                text or "",
                steps=step + 1,
                provider="openai",
                raw_messages=messages,
            )

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
            _trace_append(trace, name, args, result)
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

        hint = open_tasks_hint(tasks, trace)
        messages.append({"role": "user", "content": hint})

    return finalize_agent(
        tasks,
        trace,
        "max tool steps reached",
        steps=max_steps,
        provider="openai",
        raw_messages=messages,
    )


def _run_gemini(
    user_prompt: str,
    binary: Optional[str],
    *,
    tasks,
    tasks_block: str,
    key: Optional[str],
    model: Optional[str],
    url: Optional[str],
    max_steps: int,
    verbose: bool,
) -> AgentResult:
    from argus.llm.gemini import GeminiClient, GeminiConfig
    from argus.llm.tasks import finalize_agent, open_tasks_hint

    cfg = GeminiConfig.from_env(key=key, model=model, url=url)
    if cfg.model.startswith("gemini-3.7"):
        import sys

        print(
            f"[warn] model {cfg.model} may hang; prefer gemini-3.6-flash",
            file=sys.stderr,
            flush=True,
        )
    client = GeminiClient(cfg)

    text = _build_user_content(user_prompt, binary, tasks_block)
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
            return finalize_agent(
                tasks,
                trace,
                out_text or "",
                steps=step + 1,
                provider="gemini",
                raw_messages=contents,
            )

        fr_parts: List[Dict[str, Any]] = []
        for call in calls:
            name = call["name"]
            args = dict(call.get("args") or {})
            if binary and "binary" not in args:
                args["binary"] = binary
            if verbose:
                print(f"[tool] {name}({json.dumps(args, ensure_ascii=False)[:120]})", flush=True)
            result = dispatch_tool(name, args)
            _trace_append(trace, name, args, result)
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
        hint = open_tasks_hint(tasks, trace)
        contents.append({"role": "user", "parts": [{"text": hint}]})

    return finalize_agent(
        tasks,
        trace,
        "max tool steps reached",
        steps=max_steps,
        provider="gemini",
        raw_messages=contents,
    )
