from __future__ import annotations

"""OpenAI-compatible Chat Completions client (url + optional key + model)."""

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class LLMConfig:
    base_url: str = "https://api.openai.com/v1"
    api_key: Optional[str] = None
    model: str = "gpt-4o-mini"
    timeout: float = 120.0

    @classmethod
    def from_env(
        cls,
        url: Optional[str] = None,
        key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> "LLMConfig":
        return cls(
            base_url=(url or os.environ.get("ARGUS_OPENAI_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/"),
            api_key=key
            if key is not None
            else (os.environ.get("ARGUS_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY") or None),
            model=model or os.environ.get("ARGUS_OPENAI_MODEL") or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini",
        )


class OpenAICompatClient:
    """Minimal chat.completions client — works with OpenAI, OpenRouter, Ollama, vLLM, LM Studio."""

    def __init__(self, config: LLMConfig):
        self.config = config

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.2,
    ) -> Dict[str, Any]:
        url = f"{self.config.base_url}/chat/completions"
        body: Dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice

        data = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "argus-re/0.2",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM HTTP {e.code}: {err_body[:800]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"LLM connection failed ({self.config.base_url}): {e}") from e

    def message_content(self, response: Dict[str, Any]) -> tuple[Optional[str], List[Dict[str, Any]]]:
        """Return (assistant_text, tool_calls)."""
        choices = response.get("choices") or []
        if not choices:
            return None, []
        msg = choices[0].get("message") or {}
        content = msg.get("content")
        tool_calls = msg.get("tool_calls") or []
        return content, tool_calls
