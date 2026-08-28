from __future__ import annotations

"""Rich interactive UI for `argus agent`: results, run patched binary, feedback loop."""

import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from argus.llm.agent import AgentResult


def _patched_path(res: AgentResult) -> Optional[str]:
    if getattr(res, "patched_path", None):
        p = Path(res.patched_path)
        return str(p) if p.is_file() else None
    for entry in reversed(res.tool_trace):
        raw = entry.get("result")
        payload: Dict[str, Any] = {}
        if isinstance(raw, dict):
            payload = raw
        path = payload.get("patched_path")
        if path and Path(path).is_file():
            return str(path)
    return None


def _status_style(status: str) -> str:
    return {"done": "green", "failed": "red"}.get(status, "yellow")


def render_banner(console: Console, *, binary: Optional[str], provider: str, model: str) -> None:
    title = Text("Argus Agent", style="bold cyan")
    meta = Text.assemble(
        ("binary ", "dim"),
        (binary or "(auto)", "white"),
        ("  ·  provider ", "dim"),
        (provider, "white"),
        ("  ·  model ", "dim"),
        (model or "(default)", "white"),
    )
    console.print(Panel(meta, title=title, border_style="bright_blue", padding=(0, 1)))


def render_progress(console: Console, step: int, max_steps: int, tool: str) -> None:
    console.print(
        Rule(
            title=f"[dim]step {step}/{max_steps}[/dim]  [cyan]{tool}[/cyan]",
            style="dim",
        )
    )


def render_agent_result(console: Console, res: AgentResult, *, show_trace: bool = False) -> None:
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Задача", ratio=2)
    table.add_column("Статус", width=12)
    table.add_column("Детали", ratio=2)

    explanations: List[str] = []
    for s in res.task_statuses or []:
        st = s.get("status") or "?"
        style = _status_style(st)
        table.add_row(
            str(s.get("id", "?")),
            (s.get("text") or "")[:120],
            f"[{style}]{st}[/{style}]",
            (s.get("detail") or "")[:160],
        )
        expl = (s.get("explanation") or "").strip()
        if expl and st != "done":
            explanations.append(f"#{s.get('id', '?')}: {expl}")

    verdict = "[green]все задачи закрыты[/green]" if res.ok else "[yellow]частичный / неполный[/yellow]"
    console.print(Panel(table, title=f"Итог — {verdict}", border_style="green" if res.ok else "yellow"))

    if (not res.task_statuses or res.steps == 0) and (res.answer or "").strip():
        console.print(
            Panel(
                (res.answer or "").strip()[:4000],
                title="[red]Ошибка запуска[/red]" if res.steps == 0 else "Ответ",
                border_style="red" if res.steps == 0 and not res.ok else "dim",
                padding=(0, 1),
            )
        )

    if explanations:
        body = "\n\n".join(explanations)
        console.print(
            Panel(body[:4000], title="Почему не готово", border_style="yellow", padding=(0, 1))
        )

    patched = _patched_path(res)
    if patched:
        console.print(Panel(f"[bold]{patched}[/bold]", title="Patched binary", border_style="cyan"))

    if show_trace and res.tool_trace:
        tt = Table(show_header=True, header_style="bold dim")
        tt.add_column("Tool", style="cyan")
        tt.add_column("Result", ratio=2)
        for entry in res.tool_trace[-12:]:
            preview = (entry.get("result_preview") or "")[:140]
            tt.add_row(entry.get("tool") or "?", preview)
        console.print(Panel(tt, title="Tool trace (last 12)", border_style="dim"))


def run_patched_binary(console: Console, path: str, *, stdin: bytes = b"\n\n") -> None:
    p = Path(path)
    if not p.is_file():
        console.print(f"[red]нет файла:[/red] {path}")
        return
    console.print(Rule("[cyan]Запуск patched binary[/cyan]", style="dim"))
    try:
        proc = subprocess.run(
            [str(p)],
            input=stdin,
            capture_output=True,
            timeout=12,
            cwd=str(p.parent),
        )
        out = (proc.stdout or b"").decode("utf-8", errors="replace")
        err = (proc.stderr or b"").decode("utf-8", errors="replace")
        text = out or err or "(no output)"
        if err and out:
            text = out + "\n--- stderr ---\n" + err
        console.print(
            Panel(
                text[:8000] or "(empty)",
                title=f"exit={proc.returncode}",
                border_style="magenta",
            )
        )
    except subprocess.TimeoutExpired:
        console.print("[yellow]timeout — процесс убит[/yellow]")
    except OSError as e:
        console.print(f"[red]не удалось запустить:[/red] {e}")


def build_retry_prompt(original: str, feedback: str, res: AgentResult) -> str:
    tried: List[str] = []
    for entry in res.tool_trace[-8:]:
        tool = entry.get("tool") or "?"
        args = entry.get("args") or {}
        brief = ", ".join(f"{k}={v}" for k, v in list(args.items())[:4])
        tried.append(f"- {tool}({brief})")
    tools_block = "\n".join(tried) if tried else "- (no tools)"
    return (
        f"{original.strip()}\n\n"
        "USER FEEDBACK (previous attempt failed):\n"
        f"{feedback.strip()}\n\n"
        "What was already tried:\n"
        f"{tools_block}\n\n"
        "Address the feedback; do not repeat failed approaches blindly."
    )


def push_user_case(
    *,
    binary: str,
    task: str,
    tool_trace: List[Dict[str, Any]],
    task_statuses: List[Dict[str, Any]],
    outcome: str,
    user_feedback: str = "",
    user_confirmed: bool = False,
    discover: Optional[dict] = None,
    steps: int = 0,
) -> Optional[str]:
    from argus.memory import store_session_case

    return store_session_case(
        binary,
        task,
        tool_trace,
        task_statuses,
        discover=discover,
        steps=steps,
        outcome_override=outcome,
        user_feedback=user_feedback,
        user_confirmed=user_confirmed,
    )


def _startup_failure(res: AgentResult) -> bool:
    """Agent died before any LLM tool round (transient API / init bugs)."""
    return res.steps == 0 and not res.ok


def interactive_session(
    console: Console,
    *,
    run_once: Callable[[str], AgentResult],
    original_prompt: str,
    binary: Optional[str],
    discover: Optional[dict] = None,
    max_retries: int = 3,
    show_trace: bool = False,
    memory_enabled: bool = True,
) -> int:
    """Post-run UX: optional run patched, success confirm, retry or save failure."""
    prompt = original_prompt
    merged_trace: List[Dict[str, Any]] = []
    total_steps = 0
    attempt = 0
    startup_failures = 0
    last_res: Optional[AgentResult] = None

    while True:
        attempt += 1
        if attempt > 1 and startup_failures == 0:
            console.print(Rule(f"[bold]Повтор #{attempt}[/bold]", style="cyan"))

        res = run_once(prompt)
        last_res = res

        if _startup_failure(res):
            startup_failures += 1
            if startup_failures <= max_retries:
                detail = (res.answer or "unknown startup error").strip()[:240]
                console.print(
                    f"[yellow]падение на старте ({startup_failures}/{max_retries})[/yellow] "
                    f"[dim]{detail}[/dim] — повтор…"
                )
                time.sleep(min(startup_failures, 3))
                continue

        startup_failures = 0
        merged_trace.extend(res.tool_trace)
        total_steps += res.steps

        render_agent_result(console, res, show_trace=show_trace)

        patched = _patched_path(res)
        if patched and sys.stdin.isatty():
            if Confirm.ask("Запустить patched binary?", default=True, console=console):
                run_patched_binary(console, patched)

        if not sys.stdin.isatty():
            return 0 if res.ok else 1

        if Confirm.ask("Справился?", default=res.ok, console=console):
            if memory_enabled and binary:
                case_id = push_user_case(
                    binary=binary,
                    task=original_prompt,
                    tool_trace=merged_trace,
                    task_statuses=res.task_statuses,
                    outcome="success",
                    user_confirmed=True,
                    discover=discover,
                    steps=total_steps,
                )
                if case_id:
                    console.print(f"[green]✓[/green] case saved [dim]{case_id}[/dim]")
                elif memory_enabled:
                    console.print("[dim]memory: не удалось отправить (httpx?)[/dim]")
            console.print("[green]Отлично![/green]")
            return 0

        feedback = Prompt.ask(
            "Что не так? (Enter = сохранить failure и выйти)",
            default="",
            console=console,
        ).strip()

        if not feedback or feedback.lower() in ("стоп", "stop", "quit", "exit", "q"):
            if memory_enabled and binary:
                case_id = push_user_case(
                    binary=binary,
                    task=original_prompt,
                    tool_trace=merged_trace,
                    task_statuses=res.task_statuses,
                    outcome="failed",
                    user_feedback=feedback or "user rejected result",
                    user_confirmed=True,
                    discover=discover,
                    steps=total_steps,
                )
                if case_id:
                    console.print(f"[yellow]case saved as failure[/yellow] [dim]{case_id}[/dim]")
            return 1

        if attempt > max_retries:
            console.print(f"[yellow]лимит попыток ({max_retries})[/yellow]")
            if memory_enabled and binary:
                push_user_case(
                    binary=binary,
                    task=original_prompt,
                    tool_trace=merged_trace,
                    task_statuses=res.task_statuses,
                    outcome="failed",
                    user_feedback=feedback,
                    user_confirmed=True,
                    discover=discover,
                    steps=total_steps,
                )
            return 1

        prompt = build_retry_prompt(original_prompt, feedback, res)
        console.print(Panel(feedback, title="Пробуем ещё раз", border_style="cyan"))

    return 1 if last_res and not last_res.ok else 0
