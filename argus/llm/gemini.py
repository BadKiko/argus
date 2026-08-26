from __future__ import annotations

"""Native Google AI Studio / Gemini generateContent client (+ function calling)."""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from argus.llm.tools import ARGUS_TOOLS


DEFAULT_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEMINI_MODEL = "gemini-3.6-flash"
# Free-tier 429s often ask ~20s; wait a full minute so the next request usually succeeds.
RATE_LIMIT_WAIT_SEC = 60.0


def _retry_after_seconds(err_body: str, default: float = RATE_LIMIT_WAIT_SEC) -> float:
    """Parse Gemini 'Please retry in Ns' / RetryInfo; never wait less than default for 429."""
    m = re.search(r"retry in\s+([\d.]+)\s*s", err_body, re.I)
    if m:
        return max(default, float(m.group(1)))
    m = re.search(r'"retryDelay"\s*:\s*"(\d+)s"', err_body)
    if m:
        return max(default, float(m.group(1)))
    return default


@dataclass
class GeminiConfig:
    api_key: str
    model: str = DEFAULT_GEMINI_MODEL
    base_url: str = DEFAULT_GEMINI_BASE
    timeout: float = 60.0

    @classmethod
    def from_env(
        cls,
        key: Optional[str] = None,
        model: Optional[str] = None,
        url: Optional[str] = None,
    ) -> "GeminiConfig":
        api_key = (
            key
            if key is not None
            else (
                os.environ.get("ARGUS_GEMINI_API_KEY")
                or os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GOOGLE_API_KEY")
                or os.environ.get("ARGUS_OPENAI_API_KEY")
                or os.environ.get("OPENAI_API_KEY")
                or ""
            )
        )
        if not api_key:
            raise ValueError(
                "Gemini API key required: --key or ARGUS_GEMINI_API_KEY / GEMINI_API_KEY "
                "(from https://aistudio.google.com/apikey)"
            )
        base = (
            url
            or os.environ.get("ARGUS_GEMINI_BASE_URL")
            or DEFAULT_GEMINI_BASE
        ).rstrip("/")
        # If user passed openai-compat URL by mistake, strip to v1beta root
        if base.endswith("/openai"):
            base = base[: -len("/openai")]
        return cls(
            api_key=api_key,
            model=model
            or os.environ.get("ARGUS_GEMINI_MODEL")
            or os.environ.get("ARGUS_OPENAI_MODEL")
            or DEFAULT_GEMINI_MODEL,
            base_url=base,
        )


def openai_tools_to_gemini(tools: List[dict]) -> List[dict]:
    decls = []
    for t in tools:
        fn = t.get("function") or {}
        params = fn.get("parameters") or {"type": "object", "properties": {}}
        # Gemini wants uppercase Type sometimes but lowercase object works in v1beta
        decls.append(
            {
                "name": fn.get("name"),
                "description": fn.get("description") or "",
                "parameters": params,
            }
        )
    return [{"functionDeclarations": decls}]


class GeminiClient:
    """AI Studio generateContent with tools."""

    def __init__(self, config: GeminiConfig):
        self.config = config

    def _endpoint(self) -> str:
        model = self.config.model
        # allow models/gemini-... or bare gemini-...
        if model.startswith("models/"):
            model = model[len("models/") :]
        q = urllib.parse.urlencode({"key": self.config.api_key})
        return f"{self.config.base_url}/models/{model}:generateContent?{q}"

    def generate(
        self,
        contents: List[Dict[str, Any]],
        system: Optional[str] = None,
        tools: Optional[List[dict]] = None,
        temperature: float = 0.2,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        if tools is not None:
            body["tools"] = openai_tools_to_gemini(tools)

        data = json.dumps(body).encode("utf-8")
        url = self._endpoint()
        headers = {"Content-Type": "application/json", "User-Agent": "argus-re/0.2"}
        last_err: Optional[Exception] = None
        max_attempts = 4  # allow a couple of full 60s 429 waits
        for attempt in range(1, max_attempts + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except TimeoutError as e:
                last_err = e
                if attempt >= max_attempts:
                    raise RuntimeError(
                        f"Gemini timed out after {self.config.timeout}s for model={self.config.model}. "
                        f"Try --model gemini-3.6-flash (3.7-flash often hangs)."
                    ) from e
                time.sleep(1.5 * attempt)
            except urllib.error.HTTPError as e:
                err = e.read().decode("utf-8", errors="replace")
                if e.code == 429 and attempt < max_attempts:
                    wait = _retry_after_seconds(err, RATE_LIMIT_WAIT_SEC)
                    print(
                        f"[gemini] HTTP 429 rate limit — waiting {wait:.0f}s "
                        f"(attempt {attempt}/{max_attempts}) …",
                        flush=True,
                    )
                    time.sleep(wait)
                    last_err = e
                    continue
                if e.code in (500, 502, 503, 504) and attempt < max_attempts:
                    time.sleep(1.5 * attempt)
                    last_err = e
                    continue
                raise RuntimeError(f"Gemini HTTP {e.code}: {err[:800]}") from e
            except urllib.error.URLError as e:
                last_err = e
                reason = str(e.reason) if getattr(e, "reason", None) else str(e)
                transient = any(
                    x in reason.lower()
                    for x in (
                        "timed out",
                        "timeout",
                        "unexpected_eof",
                        "eof occurred",
                        "connection reset",
                        "broken pipe",
                        "temporarily unavailable",
                        "ssl",
                    )
                )
                if "timed out" in reason.lower() or "timeout" in reason.lower():
                    if attempt >= max_attempts:
                        raise RuntimeError(
                            f"Gemini timed out after {self.config.timeout}s for model={self.config.model}. "
                            f"Try --model gemini-3.6-flash."
                        ) from e
                elif not transient or attempt >= max_attempts:
                    raise RuntimeError(f"Gemini connection failed: {e}") from e
                time.sleep(1.5 * attempt)
                continue
            except OSError as e:
                # some SSL errors surface as OSError
                last_err = e
                if attempt >= max_attempts:
                    raise RuntimeError(f"Gemini connection failed: {e}") from e
                time.sleep(1.5 * attempt)
                continue
        raise RuntimeError(f"Gemini connection failed after retries: {last_err}")

    def parse_response(self, response: Dict[str, Any]) -> Tuple[Optional[str], List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Returns (text, function_calls, model_content_dict).
        function_calls: [{name, args dict}]
        model_content_dict: full content to append to history
        """
        cands = response.get("candidates") or []
        if not cands:
            # blocked / empty
            pf = response.get("promptFeedback")
            raise RuntimeError(f"Gemini empty candidates: {pf or response}")
        content = cands[0].get("content") or {"role": "model", "parts": []}
        parts = content.get("parts") or []
        texts: List[str] = []
        calls: List[Dict[str, Any]] = []
        for p in parts:
            if "text" in p and p["text"]:
                texts.append(p["text"])
            fc = p.get("functionCall")
            if fc:
                args = fc.get("args") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                calls.append({"name": fc.get("name") or "", "args": args})
        text = "\n".join(texts).strip() or None
        return text, calls, content
