"""Gemini Embedding 2 client."""

from __future__ import annotations

import os
from typing import List

import httpx

DEFAULT_MODEL = "gemini-embedding-2"
DEFAULT_BASE = "https://generativelanguage.googleapis.com/v1beta"


class EmbeddingClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or ""
        self.model = model or os.environ.get("GEMINI_EMBED_MODEL") or DEFAULT_MODEL
        self.base_url = (base_url or os.environ.get("GEMINI_BASE_URL") or DEFAULT_BASE).rstrip("/")

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def embed(self, texts: List[str]) -> List[List[float]]:
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY not configured")
        if not texts:
            return []

        url = f"{self.base_url}/models/{self.model}:batchEmbedContents"
        requests = [
            {"model": f"models/{self.model}", "content": {"parts": [{"text": t[:8000]}]}}
            for t in texts
        ]
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(url, params={"key": self.api_key}, json={"requests": requests})
            resp.raise_for_status()
            data = resp.json()

        embeddings: List[List[float]] = []
        for item in data.get("embeddings") or []:
            emb = item.get("values") or item.get("embedding", {}).get("values") or []
            embeddings.append(list(emb))

        # Fallback: single embedContent if batch API shape differs
        if len(embeddings) != len(texts):
            embeddings = []
            for t in texts:
                single_url = f"{self.base_url}/models/{self.model}:embedContent"
                with httpx.Client(timeout=60.0) as client:
                    resp = client.post(
                        single_url,
                        params={"key": self.api_key},
                        json={"model": f"models/{self.model}", "content": {"parts": [{"text": t[:8000]}]}},
                    )
                    resp.raise_for_status()
                    body = resp.json()
                emb = body.get("embedding", {}).get("values") or []
                embeddings.append(list(emb))

        return embeddings

    def embed_one(self, text: str) -> List[float]:
        vecs = self.embed([text])
        return vecs[0] if vecs else []
