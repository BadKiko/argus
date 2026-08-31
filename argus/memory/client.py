"""HTTP client for Argus memory backend."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

# Shared community case memory (opt-out: ARGUS_MEMORY=0)
DEFAULT_MEMORY_URL = "https://argus.cloud.badkiko.ru"

_MEMORY_NOTICE_SHOWN = False


def memory_url() -> Optional[str]:
    explicit = (os.environ.get("ARGUS_MEMORY_URL") or "").strip().rstrip("/")
    if explicit:
        return explicit
    if os.environ.get("ARGUS_MEMORY", "1").strip().lower() in ("0", "false", "no", "off"):
        return None
    return DEFAULT_MEMORY_URL


def memory_using_shared_default() -> bool:
    return not (os.environ.get("ARGUS_MEMORY_URL") or "").strip()


def memory_enabled() -> bool:
    if os.environ.get("ARGUS_MEMORY", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    return bool(memory_url())


def memory_privacy_notice() -> str:
    url = memory_url() or DEFAULT_MEMORY_URL
    shared = " (shared community DB)" if memory_using_shared_default() else ""
    return (
        f"[argus memory] Remote experience DB{shared}: {url}\n"
        "  Sends after agent runs: binary SHA256 + basename, arch/format, task text, "
        "tool strategies, outcome — never the raw binary.\n"
        "  Reads similar past cases as hints for the agent (not ground truth).\n"
        "  Opt out: ARGUS_MEMORY=0  |  own server: ARGUS_MEMORY_URL=https://..."
    )


def maybe_warn_memory_usage(*, force: bool = False) -> None:
    """Print privacy notice once per process when memory is active."""
    global _MEMORY_NOTICE_SHOWN
    if _MEMORY_NOTICE_SHOWN and not force:
        return
    if not memory_enabled():
        return
    _MEMORY_NOTICE_SHOWN = True
    print(memory_privacy_notice(), file=sys.stderr, flush=True)
    if httpx is None:
        print(
            "[argus memory] httpx not installed — memory disabled. "
            "pip install -e '.[memory]'",
            file=sys.stderr,
            flush=True,
        )


class MemoryClient:
    def __init__(self, base_url: Optional[str] = None, *, timeout: float = 30.0) -> None:
        self.base_url = (base_url or memory_url() or "").rstrip("/")
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.base_url) and httpx is not None

    def push_case(self, report: Dict[str, Any]) -> Optional[str]:
        if not self.available:
            return None
        assert httpx is not None
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/v1/cases", json=report)
                resp.raise_for_status()
                data = resp.json()
            return data.get("case_id")
        except Exception:
            return None

    def search_hints(
        self,
        query_text: str,
        *,
        k: int = 5,
        filters: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        assert httpx is not None
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    f"{self.base_url}/v1/search",
                    json={"query_text": query_text, "k": k, "filters": filters or {}},
                )
                resp.raise_for_status()
                data = resp.json()
            return list(data.get("hints") or [])
        except Exception:
            return []

    def stats(self) -> Dict[str, Any]:
        if not self.available:
            return {}
        assert httpx is not None
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(f"{self.base_url}/v1/stats")
                resp.raise_for_status()
                return resp.json()
        except Exception:
            return {}


def store_session_case(
    binary: str,
    task: str,
    tool_trace: List[Dict[str, Any]],
    task_statuses: List[Dict[str, Any]],
    *,
    discover: Optional[dict] = None,
    steps: int = 0,
    outcome_override: Optional[str] = None,
    user_feedback: str = "",
    user_confirmed: bool = False,
    runtime_launch: Optional[Dict[str, Any]] = None,
    planner: str = "llm",
) -> Optional[str]:
    if not memory_enabled():
        return None
    maybe_warn_memory_usage()
    from argus.memory.case import build_case_report

    report = build_case_report(
        binary,
        task,
        tool_trace,
        task_statuses,
        discover=discover,
        steps=steps,
        outcome_override=outcome_override,
        user_feedback=user_feedback,
        user_confirmed=user_confirmed,
        runtime_launch=runtime_launch,
        planner=planner,
    )
    if not report:
        return None
    return MemoryClient().push_case(report)
