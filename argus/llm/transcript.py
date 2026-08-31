from __future__ import annotations

"""JSONL transcript of agent ↔ LLM traffic (requests, responses, tool I/O)."""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, TextIO

_PREVIEW = 8000
_DISABLED = frozenset({"0", "false", "no", "off", "none"})
_TMP_LINK = Path(tempfile.gettempdir()) / "argus.jsonl"


def _home_dir() -> Path:
    h = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    return Path(h) if h else Path.home()


def default_log_path() -> Path:
    return _home_dir() / ".cache" / "argus" / "current.jsonl"


def default_archive_path() -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return _home_dir() / ".cache" / "argus" / "sessions" / f"{ts}.jsonl"


def tail_log_hint() -> str:
    """Path users can `tail -f` (symlink when possible)."""
    current = default_log_path()
    try:
        if _TMP_LINK.is_symlink() and _TMP_LINK.resolve() == current.resolve():
            return str(_TMP_LINK)
    except OSError:
        pass
    return str(current)


def _link_tmp_log(current: Path) -> None:
    try:
        current.parent.mkdir(parents=True, exist_ok=True)
        _TMP_LINK.unlink(missing_ok=True)
        _TMP_LINK.symlink_to(current)
    except OSError:
        pass


def resolve_transcript(
    explicit: Optional[str] = None,
    *,
    enabled: bool = True,
) -> Optional["AgentTranscript"]:
    """
    Session logging (on by default):
      - ~/.cache/argus/current.jsonl  (truncated each run)
      - ~/.cache/argus/sessions/<timestamp>.jsonl  (archive)
      - /tmp/argus.jsonl → symlink to current (for tail -f)

    Disable: --no-transcript or ARGUS_AGENT_TRANSCRIPT=0
    Custom path: --transcript PATH or ARGUS_AGENT_TRANSCRIPT=/path
    Stderr mirror: ARGUS_AGENT_TRANSCRIPT=stderr
    """
    raw = (explicit if explicit is not None else os.environ.get("ARGUS_AGENT_TRANSCRIPT") or "").strip()
    if not enabled or raw.lower() in _DISABLED:
        return None
    if raw.lower() in ("1", "true", "yes", "stderr"):
        return AgentTranscript(mirror_stderr=True)
    if raw in ("stdout", "-"):
        return AgentTranscript(mirror_stdout=True)
    if raw:
        return AgentTranscript(path=Path(raw).expanduser(), truncate=True)
    current = default_log_path()
    archive = default_archive_path()
    _link_tmp_log(current)
    return AgentTranscript(path=current, archive_path=archive, truncate=True)


class AgentTranscript:
    def __init__(
        self,
        *,
        path: Optional[Path] = None,
        archive_path: Optional[Path] = None,
        truncate: bool = False,
        mirror_stderr: bool = False,
        mirror_stdout: bool = False,
    ) -> None:
        self.path = path
        self.archive_path = archive_path
        self.mirror_stderr = mirror_stderr
        self.mirror_stdout = mirror_stdout
        self._fh: Optional[TextIO] = None
        self._archive_fh: Optional[TextIO] = None
        mode = "w" if truncate else "a"
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open(mode, encoding="utf-8")
        if archive_path is not None:
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            self._archive_fh = archive_path.open("w", encoding="utf-8")

    def close(self) -> None:
        for fh in (self._fh, self._archive_fh):
            if fh is not None:
                fh.close()
        self._fh = None
        self._archive_fh = None

    def _write_line(self, line: str) -> None:
        for fh in (self._fh, self._archive_fh):
            if fh is not None:
                fh.write(line + "\n")
                fh.flush()

    def _emit(self, record: Dict[str, Any]) -> None:
        record.setdefault("ts", datetime.now(timezone.utc).isoformat())
        line = json.dumps(record, ensure_ascii=False, default=str)
        self._write_line(line)
        if self.mirror_stderr:
            print(f"[transcript] {line}", file=sys.stderr, flush=True)
        elif self.mirror_stdout:
            print(f"[transcript] {line}", flush=True)

    def session_start(self, **fields: Any) -> None:
        paths: Dict[str, str] = {}
        if self.path is not None:
            paths["current"] = str(self.path)
        if self.archive_path is not None:
            paths["archive"] = str(self.archive_path)
        if paths:
            fields = {**fields, "log_paths": paths, "tail": tail_log_hint()}
        self._emit({"event": "session_start", **fields})

    def session_end(self, **fields: Any) -> None:
        self._emit({"event": "session_end", **fields})

    def note(self, kind: str, **fields: Any) -> None:
        self._emit({"event": "note", "kind": kind, **fields})

    def initial_prompt(self, text: str) -> None:
        self._emit({"event": "initial_prompt", "text": text})

    def step_begin(self, step: int, **fields: Any) -> None:
        self._emit({"event": "step_begin", "step": step, **fields})

    def user_message(self, step: int, text: str, *, kind: str = "hint") -> None:
        self._emit({"event": "user_message", "step": step, "kind": kind, "text": text})

    def model_response(
        self,
        step: int,
        *,
        text: str = "",
        tool_calls: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self._emit(
            {
                "event": "model_response",
                "step": step,
                "text": text,
                "tool_calls": tool_calls or [],
            }
        )

    def tool_begin(self, step: int, name: str, args: Dict[str, Any], **fields: Any) -> None:
        self._emit({"event": "tool_begin", "step": step, "tool": name, "args": args, **fields})

    def tool_result(
        self,
        step: int,
        name: str,
        args: Dict[str, Any],
        result: str,
        *,
        injected_binary: Optional[str] = None,
    ) -> None:
        preview = result if len(result) <= _PREVIEW else result[:_PREVIEW] + "…"
        rec: Dict[str, Any] = {
            "event": "tool_result",
            "step": step,
            "tool": name,
            "args": args,
            "result_preview": preview,
            "result_len": len(result),
        }
        try:
            from argus.llm.tool_result import digest_tool_result

            digest = digest_tool_result(result)
            if digest:
                rec["evidence_digest"] = digest
        except Exception:
            pass
        if injected_binary is not None:
            rec["injected_binary"] = injected_binary
        self._emit(rec)
