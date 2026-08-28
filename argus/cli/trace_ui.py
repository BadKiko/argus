from __future__ import annotations

"""Rich agent trace: rounded-box investigation graph."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from argus.cli.trace_graph import InvestigationGraph

_TOOL_STYLE = {
    "argus_slice": "cyan",
    "argus_find": "blue",
    "argus_patch": "magenta",
    "argus_unlock_apply": "green",
    "argus_discover": "yellow",
    "argus_lift": "white",
    "argus_ai": "bright_blue",
    "argus_solve": "bright_green",
}


def _short_path(p: Any) -> str:
    if not p:
        return ""
    return Path(str(p)).name


def _addr(args: Dict[str, Any], payload: Optional[Dict[str, Any]] = None) -> str:
    for src in (args, payload or {}):
        for k in ("addr", "entry", "branch", "patch_addr"):
            v = src.get(k)
            if v:
                return str(v)
    return ""


def describe_tool_call(name: str, args: Dict[str, Any]) -> str:
    mod = _short_path(args.get("binary") or args.get("module") or "")
    if name == "argus_slice":
        q = args.get("query") or ""
        return f'gate scan' + (f' "{q}"' if q else "")
    if name == "argus_find":
        return f'find "{args.get("query") or "?"}"'
    if name == "argus_patch":
        kind = args.get("kind") or "patch"
        at = _addr(args)
        return f"{kind}" + (f" {at}" if at else "")
    if name == "argus_unlock_apply":
        return "unlock apply"
    if name == "argus_discover":
        return "discover DLL/SO"
    if name == "argus_lift":
        return f"lift {args.get('entry') or args.get('function') or '?'}"
    if name == "argus_ai":
        return "ask AI"
    if name == "argus_solve":
        return "solve password"
    return name.replace("argus_", "")


def describe_tool_result(name: str, args: Dict[str, Any], payload: Dict[str, Any]) -> str:
    ok = payload.get("ok")
    if name == "argus_slice":
        plan = payload.get("unlock_plan") or (payload.get("evidence") or {}).get("unlock_plan") or []
        return f"plan={len(plan)}"
    if name == "argus_find":
        hits = (payload.get("evidence") or {}).get("hits") or payload.get("hits") or []
        return f"{len(hits)} hits" if hits else "no hits"
    if name == "argus_patch":
        if payload.get("patched_path"):
            return _short_path(payload["patched_path"])
        return "ok" if ok else "fail"
    if name == "argus_discover":
        linked = payload.get("linked") or (payload.get("evidence") or {}).get("linked") or []
        return f"{len(linked)} linked" if linked else "scan"
    if name == "argus_unlock_apply":
        v = (payload.get("verify") or {}).get("ok")
        return "verified" if v else "verify fail"
    if ok is True:
        return "ok"
    if ok is False:
        return "fail"
    return ""


def _fan_out_modules(name: str, payload: Dict[str, Any]) -> Optional[List[str]]:
    if name == "argus_discover":
        linked = payload.get("linked") or (payload.get("evidence") or {}).get("linked") or []
        names = [_short_path(m.get("path")) for m in linked if isinstance(m, dict) and m.get("path")]
        return names if len(names) > 1 else None
    if name == "argus_slice":
        mods = payload.get("modules") or (payload.get("evidence") or {}).get("modules") or []
        names = [_short_path(m) for m in mods if m]
        if len(names) > 1:
            return names[:4]
        per = payload.get("per_module") or []
        if len(per) > 1:
            return [_short_path(p.get("module") or p.get("path")) for p in per[:4] if isinstance(p, dict)]
    return None


@dataclass
class AgentTraceUI:
    console: Console
    _graph: InvestigationGraph = field(default_factory=InvestigationGraph)
    _live: Optional[Live] = None
    _step: int = 0
    _max_steps: int = 0
    _model: str = ""

    def note(self, msg: str, *, style: str = "dim") -> None:
        self._refresh(status=f"[{style}]{msg}[/{style}]")

    def step_begin(self, step: int, max_steps: int, model: str) -> None:
        self._step = step
        self._max_steps = max_steps
        self._model = model
        if self._live is None:
            self._live = Live(
                self._panel(),
                console=self.console,
                refresh_per_second=4,
                transient=False,
            )
            self._live.start()
        else:
            self._refresh()

    def _step_title(self) -> str:
        if self._max_steps and self._max_steps > 0:
            return f"step {self._step}/{self._max_steps}  ·  {self._model}"
        return f"step {self._step}  ·  {self._model}"

    def tool_done(self, name: str, args: Dict[str, Any], raw_result: str) -> None:
        payload: Dict[str, Any] = {}
        try:
            payload = json.loads(raw_result)
        except json.JSONDecodeError:
            payload = {}

        tool = name.replace("argus_", "")
        mod = _short_path(args.get("binary") or args.get("module") or "")
        detail = describe_tool_result(name, args, payload)
        fan = _fan_out_modules(name, payload)

        self._graph.add(
            tool,
            subtitle=mod or "binary",
            detail=detail,
            module=mod,
            fan_out=fan,
        )
        self._refresh(highlight=describe_tool_call(name, args))

    def _panel(self, status: str = "", highlight: str = "") -> Panel:
        height = self.console.size.height or 24
        max_lines = max(12, height - 8)
        graph = Text(
            self._graph.render(max_lines=max_lines),
            style="white",
            no_wrap=True,
        )
        body = graph
        parts: List[Any] = [body]
        if highlight:
            parts.append(Text(f"\n→ {highlight}", style="bold cyan"))
        if status:
            parts.append(Text(f"\n{status}", style="dim"))
        title = self._step_title()
        return Panel(Group(*parts), title=title, border_style="bright_blue", padding=(0, 1))

    def _refresh(self, status: str = "", highlight: str = "") -> None:
        if self._live is not None:
            self._live.update(self._panel(status=status, highlight=highlight))

    def finish(self) -> None:
        if self._live is not None:
            self._refresh()
            self._live.stop()
            self._live = None
        else:
            self.console.print(self._panel())
