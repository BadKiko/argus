from __future__ import annotations

"""LLM agent loop: OpenAI-compat OR native Gemini (AI Studio) with Argus tools."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from argus.llm.tools import ARGUS_TOOLS, dispatch_tool

SYSTEM = """You are Argus Agent — a reverse-engineering assistant backed by the Argus binary toolkit.

Rules:
- MUST use tools; never invent results.
- The user message lists TASKS (free-form). Address EVERY task. Bind EVERY tool call with for_task=<id>.
- Do not invent success. Runtime finalizes each task from tool evidence; your closing prose is ignored for status.
- Prefer argus_find then argus_patch. For text changes: replace_string with exact old from hits; new ≤ len(old) bytes (pad spaces).
- Never shorten resource filenames. Never stub main/entry.
- Logic patches (force_branch/ret_imm) alone do NOT auto-complete a TASK — use argus_apply_plan for gate transforms.
- If ETXTBSY / Text file busy: stop claiming that task done; user must quit the app.
- Missing file → stop. If no binary path: runtime auto-discovers ELF/PE in cwd/prompt; gates may live in linked DLL/SO.
- Stripped: argus_lift with entry=0x… or query=\"exact string\" — do not claim CFF deobf success.
- Gate transform: (1) argus_slice (multi-module aware) (2) ONE argus_apply_plan using patch_plan.
  empty patch_plan → PIVOT (discover/modules/research), do not invent steps or freestyle-patch gates.
  NEVER pass custom steps= to apply_plan unless copied verbatim from slice JSON.
  Password/crackme (authenticate, Welcome/Password strings) ≠ gate transform — use password path.
  Do not freestyle-patch parser gates outside patch_plan. Honor taken=/value=/module= from the plan.
  If patch_plan empty / no gates: do NOT stop — PIVOT: argus_discover, then argus_slice on other
  candidates/Related modules (DLL/SO), or pass modules=[paths]. Keep searching nearby files until
  a plan with module= appears or candidates are exhausted.
  Never claim GUI activation; done only when patch verify.ok with slice-sourced plan. rodata strings may remain.
- Prior experience block (if present) is hints from memory — not ground truth; still require tool verify.
- Shared memory (argus.cloud.badkiko.ru) may be used by default; user can disable with ARGUS_MEMORY=0.
- NEVER modify the original binary on disk. Runtime gives you a work copy path — patch ONLY that copy.
- Do NOT stop until runtime marks every TASK done (tool evidence). Prose alone never completes a task.
- If a approach fails: call argus_research, pivot strategy, try argus_slice/apply_plan/other module — do NOT give up.
- Patch loop on same addr → pivot (different gate/module/kind), not stop.
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
    patched_path: Optional[str] = None
    binary: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "answer": self.answer,
            "steps": self.steps,
            "provider": self.provider,
            "tool_trace": self.tool_trace,
            "task_statuses": self.task_statuses,
            "patched_path": self.patched_path,
            "binary": self.binary,
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


def _absolute_max_steps() -> int:
    raw = (os.environ.get("ARGUS_AGENT_ABSOLUTE_MAX") or "150").strip()
    try:
        return max(20, int(raw))
    except ValueError:
        return 150


def _hard_step_cap(max_steps: int) -> bool:
    """Only enforce CLI max_steps when ARGUS_AGENT_HARD_MAX=1."""
    if max_steps <= 0:
        return False
    return os.environ.get("ARGUS_AGENT_HARD_MAX", "").strip().lower() in ("1", "true", "yes")


def _maybe_finalize_or_research(
    *,
    tasks,
    trace: List[Dict[str, Any]],
    user_prompt: str,
    binary: Optional[str],
    original_binary: Optional[str],
    discover: Optional[dict],
    model_answer: str,
    step: int,
    provider: str,
    raw_messages: Any,
    store_memory: bool,
) -> Tuple[Optional["AgentResult"], Optional[str]]:
    """Return (AgentResult, None) to stop, or (None, research_brief) to continue."""
    from argus.llm.research import build_research_brief, tasks_all_done
    from argus.llm.session import get_session
    from argus.llm.tasks import finalize_agent

    mem_binary = original_binary or binary
    if tasks_all_done(tasks, trace, binary=mem_binary):
        return (
            finalize_agent(
                tasks,
                trace,
                model_answer,
                steps=step,
                provider=provider,
                raw_messages=raw_messages,
                binary=mem_binary,
                user_prompt=user_prompt,
                discover=discover,
                store_memory=store_memory,
            ),
            None,
        )

    sess = get_session()
    sess.research_round += 1
    brief = build_research_brief(
        user_prompt,
        tasks,
        trace,
        binary=binary,
        original_binary=original_binary,
        discover=discover,
        research_round=sess.research_round,
    )
    return None, brief


def _build_user_content(
    user_prompt: str,
    binary: Optional[str],
    tasks_block: str,
    *,
    discover: Optional[dict] = None,
    memory_hints: str = "",
) -> str:
    parts = [user_prompt.strip()]
    if tasks_block:
        parts.append("")
        parts.append(tasks_block)
    try:
        from argus.llm.intent import routing_hint

        hint = routing_hint(user_prompt, binary=binary, discover=discover)
        if hint:
            parts.append("")
            parts.append(hint)
    except Exception:
        pass
    if memory_hints:
        parts.append("")
        parts.append(memory_hints)
    if binary:
        parts.append("")
        parts.append(f"Binary path (work copy — patch ONLY this): {binary}")
        try:
            from argus.llm.session import get_session

            sess = get_session()
            if sess.original_binary and sess.original_binary != binary:
                parts.append(f"Original (read-only): {sess.original_binary}")
        except Exception:
            pass
    if discover:
        inst = discover.get("install_dir")
        if inst:
            parts.append(f"Install directory (discover/scan siblings here — NOT workspace cache): {inst}")
        linked = discover.get("linked") or []
        if linked:
            parts.append("Related modules (license may be here):")
            for m in linked[:8]:
                parts.append(f"  - {m.get('path')} (score={m.get('score')})")
        mod_hint = discover.get("install_modules_hint") or []
        if mod_hint:
            parts.append(
                "Suggested argus_slice modules (install dir): "
                + ", ".join(os.path.basename(p) for p in mod_hint[:6])
            )
        cands = discover.get("candidates") or []
        if len(cands) > 1:
            parts.append("Other candidates:")
            for c in cands[1:6]:
                parts.append(f"  - {c.get('path')} (score={c.get('score')})")
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


def _effective_max_steps(max_steps: int) -> int:
    """0 = unlimited (default). ARGUS_AGENT_MAX_STEPS overrides CLI."""
    raw = (os.environ.get("ARGUS_AGENT_MAX_STEPS") or "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return max_steps


def _patch_loop_detected(trace: List[Dict[str, Any]], *, window: int = 6) -> bool:
    recent = [e for e in trace[-window:] if e.get("tool") == "argus_patch"]
    if len(recent) < window:
        return False
    addrs = {(e.get("args") or {}).get("addr") for e in recent}
    return len(addrs) <= 2


def _agent_dispatch_tool(
    name: str,
    args: Dict[str, Any],
    *,
    binary: Optional[str],
    trace: List[Dict[str, Any]],
    verbose: bool,
    trace_ui: Any,
    transcript: Any,
    step: int,
) -> str:
    injected: Optional[str] = None
    if binary and "binary" not in args:
        injected = binary
        args["binary"] = binary
    if transcript is not None:
        extra = {"injected_binary": injected} if injected else {}
        transcript.tool_begin(step, name, dict(args), **extra)
    result = dispatch_tool(name, args)
    _trace_append(trace, name, args, result)
    _log_tool(name, args, result, verbose=verbose, trace_ui=trace_ui)
    if transcript is not None:
        transcript.tool_result(
            step, name, args, result, injected_binary=injected
        )
    return result


def _log_tool(
    name: str,
    args: Dict[str, Any],
    result: str,
    *,
    verbose: bool,
    trace_ui: Any = None,
) -> None:
    if trace_ui is not None:
        trace_ui.tool_done(name, args, result)
        return
    if not verbose:
        return
    print(f"[tool] {name}({json.dumps(args, ensure_ascii=False)[:120]})", flush=True)
    try:
        preview = json.loads(result)
        if preview.get("patched_path"):
            print(f"patched → {preview['patched_path']}", flush=True)
    except json.JSONDecodeError:
        pass


def run_agent(
    user_prompt: str,
    binary: Optional[str] = None,
    *,
    provider: Optional[str] = None,
    url: Optional[str] = None,
    key: Optional[str] = None,
    model: Optional[str] = None,
    max_steps: int = 0,
    verbose: bool = False,
    store_memory: bool = True,
    trace_ui: Any = None,
    transcript_path: Optional[str] = None,
    transcript_enabled: bool = True,
) -> AgentResult:
    from argus.discover import discover_targets
    from argus.llm.session import reset_session
    from argus.llm.tasks import finalize_agent, format_tasks_block, split_user_tasks
    from argus.llm.transcript import resolve_transcript

    reset_session()
    transcript = resolve_transcript(transcript_path, enabled=transcript_enabled)
    result: Optional[AgentResult] = None
    try:
        result = _run_agent_inner(
            user_prompt,
            binary,
            provider=provider,
            url=url,
            key=key,
            model=model,
            max_steps=max_steps,
            verbose=verbose,
            store_memory=store_memory,
            trace_ui=trace_ui,
            transcript=transcript,
        )
        return result
    finally:
        if transcript is not None:
            if result is not None:
                transcript.session_end(
                    ok=result.ok,
                    steps=result.steps,
                    provider=result.provider,
                    answer_preview=(result.answer or "")[:500],
                    tool_calls=len(result.tool_trace),
                )
            else:
                transcript.session_end(ok=False, steps=0, error="aborted")
            transcript.close()
        if trace_ui is not None and hasattr(trace_ui, "finish"):
            trace_ui.finish()


def _run_agent_inner(
    user_prompt: str,
    binary: Optional[str] = None,
    *,
    provider: Optional[str] = None,
    url: Optional[str] = None,
    key: Optional[str] = None,
    model: Optional[str] = None,
    max_steps: int = 0,
    verbose: bool = False,
    store_memory: bool = True,
    trace_ui: Any = None,
    transcript: Any = None,
) -> AgentResult:
    from argus.discover import discover_targets
    from argus.llm.tasks import format_tasks_block, split_user_tasks

    discover_info: Optional[dict] = None
    original_binary: Optional[str] = None
    prov = resolve_provider(provider)
    if transcript is not None:
        transcript.session_start(
            user_prompt=user_prompt,
            binary=binary,
            provider=prov,
        )

    if binary and binary_missing(binary):
        msg = missing_binary_message(binary)
        if verbose:
            print(msg, flush=True)
        if transcript is not None:
            transcript.note("binary_missing", path=binary, detail=msg)
        return AgentResult(ok=False, answer=msg, steps=0, provider=prov)

    if binary:
        from argus.llm.session import get_session
        from argus.llm.workspace import prepare_work_binary

        try:
            work, original_binary = prepare_work_binary(binary)
            sess = get_session()
            sess.original_binary = original_binary
            sess.work_binary = work
            sess.install_dir = str(Path(original_binary).resolve().parent)
            binary = work
            if verbose:
                print(f"[workspace] work={work} original={original_binary}", flush=True)
            if transcript is not None:
                transcript.note("workspace", work=work, original=original_binary)
        except OSError as e:
            msg = f"не удалось создать рабочую копию: {e}"
            if transcript is not None:
                transcript.note("workspace_error", error=str(e))
            return AgentResult(
                ok=False,
                answer=msg,
                steps=0,
                provider=prov,
                binary=binary,
            )

    # Deterministic discover when path missing; always attach linked modules when possible
    from argus.discover import merge_install_discover

    install_root = ""
    try:
        from argus.llm.session import get_session

        install_root = get_session().install_dir or ""
    except Exception:
        pass
    if not install_root and original_binary:
        install_root = str(Path(original_binary).resolve().parent)

    discover_info = discover_targets(
        user_prompt,
        binary=original_binary or binary,
        root=install_root or None,
    )
    if install_root:
        discover_info = merge_install_discover(
            discover_info,
            install_root,
            binary=original_binary or binary,
        )
    if not binary and discover_info.get("primary"):
        binary = discover_info["primary"]
        if verbose:
            print(f"[discover] primary={binary}", flush=True)
        if transcript is not None:
            transcript.note("discover_primary", primary=binary, summary=discover_info.get("summary"))
    elif binary and discover_info.get("linked") and verbose:
        print(f"[discover] linked={len(discover_info['linked'])}", flush=True)
    if not binary:
        msg = (
            "нет binary: укажите путь или запустите из каталога с ELF/PE "
            "(argus_discover / auto-scan cwd)"
        )
        if verbose:
            print(msg, flush=True)
        if transcript is not None:
            transcript.note("no_binary", detail=msg)
        return AgentResult(ok=False, answer=msg, steps=0, provider=prov)

    tasks = split_user_tasks(user_prompt)
    tasks_block = format_tasks_block(tasks)
    memory_hints = ""
    try:
        from argus.memory import maybe_warn_memory_usage, retrieve_hints

        maybe_warn_memory_usage()
        memory_hints = retrieve_hints(original_binary or binary, user_prompt, discover=discover_info)
    except Exception:
        pass
    if transcript is not None:
        transcript.note(
            "tasks",
            count=len(tasks),
            ids=[t.id for t in tasks],
            discover_primary=(discover_info or {}).get("primary"),
        )
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
            discover=discover_info,
            memory_hints=memory_hints,
            store_memory=store_memory,
            trace_ui=trace_ui,
            original_binary=original_binary,
            transcript=transcript,
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
        discover=discover_info,
        memory_hints=memory_hints,
        store_memory=store_memory,
        trace_ui=trace_ui,
        original_binary=original_binary,
        transcript=transcript,
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
    discover: Optional[dict] = None,
    memory_hints: str = "",
    store_memory: bool = True,
    trace_ui: Any = None,
    original_binary: Optional[str] = None,
    transcript: Any = None,
) -> AgentResult:
    from argus.llm.client import LLMConfig, OpenAICompatClient
    from argus.llm.tasks import finalize_agent, open_tasks_hint

    cfg = LLMConfig.from_env(url=url, key=key, model=model)
    client = OpenAICompatClient(cfg)
    model_name = cfg.model or "openai"

    content = _build_user_content(
        user_prompt, binary, tasks_block, discover=discover, memory_hints=memory_hints
    )
    if transcript is not None:
        transcript.initial_prompt(content)
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": content},
    ]
    trace: List[Dict[str, Any]] = []
    limit = _effective_max_steps(max_steps)
    absolute = _absolute_max_steps()
    step = 0

    while True:
        step += 1
        if step > absolute:
            res = finalize_agent(
                tasks,
                trace,
                f"absolute safety limit ({absolute} steps)",
                steps=step,
                provider="openai",
                raw_messages=messages,
                binary=original_binary or binary,
                user_prompt=user_prompt,
                discover=discover,
                store_memory=store_memory,
            )
            res.binary = original_binary or binary
            return res

        if limit > 0 and step > limit and _hard_step_cap(limit):
            res = finalize_agent(
                tasks,
                trace,
                "max tool steps reached (ARGUS_AGENT_HARD_MAX=1)",
                steps=limit,
                provider="openai",
                raw_messages=messages,
                binary=original_binary or binary,
                user_prompt=user_prompt,
                discover=discover,
                store_memory=store_memory,
            )
            res.binary = original_binary or binary
            return res

        if trace_ui is not None:
            trace_ui.step_begin(step, limit, model_name)
        elif verbose:
            suffix = f"/{limit}" if limit > 0 else ""
            print(f"[openai] step {step}{suffix} …", flush=True)
        if transcript is not None:
            transcript.step_begin(step, provider="openai", model=model_name)
        resp = client.chat(messages, tools=ARGUS_TOOLS, tool_choice="auto")
        text, tool_calls = client.message_content(resp)
        if transcript is not None:
            tc_log = [
                {
                    "name": (tc.get("function") or {}).get("name"),
                    "arguments": (tc.get("function") or {}).get("arguments"),
                }
                for tc in (tool_calls or [])
            ]
            transcript.model_response(step, text=text or "", tool_calls=tc_log)
        assistant_msg: Dict[str, Any] = {"role": "assistant", "content": text or ""}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        messages.append(assistant_msg)

        if not tool_calls:
            done, brief = _maybe_finalize_or_research(
                tasks=tasks,
                trace=trace,
                user_prompt=user_prompt,
                binary=binary,
                original_binary=original_binary,
                discover=discover,
                model_answer=text or "",
                step=step,
                provider="openai",
                raw_messages=messages,
                store_memory=store_memory,
            )
            if done is not None:
                done.binary = original_binary or binary
                return done
            if trace_ui is not None:
                trace_ui.note("research — задача не закрыта, продолжаем", style="yellow")
            if transcript is not None and brief:
                transcript.user_message(step, brief, kind="research")
            messages.append({"role": "user", "content": brief or ""})
            continue

        for tc in tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except json.JSONDecodeError:
                args = {}
            result = _agent_dispatch_tool(
                name,
                args,
                binary=binary,
                trace=trace,
                verbose=verbose,
                trace_ui=trace_ui,
                transcript=transcript,
                step=step,
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.get("id") or name,
                    "content": result,
                }
            )

        hint = open_tasks_hint(tasks, trace)
        if _patch_loop_detected(trace):
            hint += (
                "\nPatch loop — same addresses retried. PIVOT: argus_research / "
                "different gate or argus_slice+apply_plan; do NOT stop."
            )
        if transcript is not None:
            transcript.user_message(step, hint, kind="open_tasks_hint")
        messages.append({"role": "user", "content": hint})

    # unreachable


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
    discover: Optional[dict] = None,
    memory_hints: str = "",
    store_memory: bool = True,
    trace_ui: Any = None,
    original_binary: Optional[str] = None,
    transcript: Any = None,
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
    def _status_cb(msg: str) -> None:
        if trace_ui is not None:
            trace_ui.note(msg)
        if transcript is not None:
            transcript.note("gemini_status", detail=msg)

    status_cb = _status_cb if (trace_ui is not None or transcript is not None) else None
    try:
        text = _build_user_content(
            user_prompt, binary, tasks_block, discover=discover, memory_hints=memory_hints
        )
        if transcript is not None:
            transcript.initial_prompt(text)
        contents: List[Dict[str, Any]] = [{"role": "user", "parts": [{"text": text}]}]
        trace: List[Dict[str, Any]] = []
        limit = _effective_max_steps(max_steps)
        absolute = _absolute_max_steps()
        step = 0

        while True:
            step += 1
            if step > absolute:
                res = finalize_agent(
                    tasks,
                    trace,
                    f"absolute safety limit ({absolute} steps)",
                    steps=step,
                    provider="gemini",
                    raw_messages=contents,
                    binary=original_binary or binary,
                    user_prompt=user_prompt,
                    discover=discover,
                    store_memory=store_memory,
                )
                res.binary = original_binary or binary
                return res

            if limit > 0 and step > limit and _hard_step_cap(limit):
                res = finalize_agent(
                    tasks,
                    trace,
                    "max tool steps reached (ARGUS_AGENT_HARD_MAX=1)",
                    steps=limit,
                    provider="gemini",
                    raw_messages=contents,
                    binary=original_binary or binary,
                    user_prompt=user_prompt,
                    discover=discover,
                    store_memory=store_memory,
                )
                res.binary = original_binary or binary
                return res

            if trace_ui is not None:
                trace_ui.step_begin(step, limit, cfg.model)
            elif verbose:
                suffix = f"/{limit}" if limit > 0 else ""
                print(f"[gemini] step {step}{suffix} model={cfg.model} …", flush=True)
            if transcript is not None:
                transcript.step_begin(step, provider="gemini", model=cfg.model)
            try:
                resp = client.generate(
                    contents,
                    system=SYSTEM,
                    tools=ARGUS_TOOLS,
                    status_cb=status_cb,
                )
            except RuntimeError as e:
                if verbose and trace_ui is None:
                    print(f"[gemini] retryable/error: {e}", flush=True)
                raise
            out_text, calls, model_content = client.parse_response(resp)
            if transcript is not None:
                transcript.model_response(
                    step,
                    text=out_text or "",
                    tool_calls=[{"name": c.get("name"), "args": c.get("args")} for c in calls],
                )
            if model_content:
                contents.append(model_content)

            if not calls:
                done, brief = _maybe_finalize_or_research(
                    tasks=tasks,
                    trace=trace,
                    user_prompt=user_prompt,
                    binary=binary,
                    original_binary=original_binary,
                    discover=discover,
                    model_answer=out_text or "",
                    step=step,
                    provider="gemini",
                    raw_messages=contents,
                    store_memory=store_memory,
                )
                if done is not None:
                    done.binary = original_binary or binary
                    return done
                if trace_ui is not None:
                    trace_ui.note("research — задача не закрыта, продолжаем", style="yellow")
                if transcript is not None and brief:
                    transcript.user_message(step, brief, kind="research")
                contents.append({"role": "user", "parts": [{"text": brief or ""}]})
                continue

            fr_parts: List[Dict[str, Any]] = []
            for call in calls:
                name = call["name"]
                args = dict(call.get("args") or {})
                result = _agent_dispatch_tool(
                    name,
                    args,
                    binary=binary,
                    trace=trace,
                    verbose=verbose,
                    trace_ui=trace_ui,
                    transcript=transcript,
                    step=step,
                )
                try:
                    payload = json.loads(result)
                except json.JSONDecodeError:
                    payload = {"result": result}
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
            if _patch_loop_detected(trace):
                hint += (
                    "\nPatch loop — same addresses retried. PIVOT: argus_research / "
                    "different gate or argus_slice+apply_plan; do NOT stop."
                )
            if transcript is not None:
                transcript.user_message(step, hint, kind="open_tasks_hint")
            contents.append({"role": "user", "parts": [{"text": hint}]})

        # unreachable
    finally:
        client.close()
