"""Chroma vector store for case memory."""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import chromadb

from app.document import case_document, hint_summary
from app.embed import EmbeddingClient
from app.models import CaseReport, HintItem, StatsResponse

DEDUP_WINDOW_SEC = 300


class CaseStore:
    def __init__(
        self,
        *,
        chroma_host: str | None = None,
        chroma_port: int | None = None,
        collection_name: str | None = None,
        embedder: EmbeddingClient | None = None,
    ) -> None:
        host = chroma_host or os.environ.get("CHROMA_HOST", "localhost")
        port = int(chroma_port or os.environ.get("CHROMA_PORT", "8000"))
        self.collection_name = collection_name or os.environ.get("CHROMA_COLLECTION", "argus_cases")
        self.embedder = embedder or EmbeddingClient()
        self._client = chromadb.HttpClient(host=host, port=port)
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self._recent_dedup: Dict[str, float] = {}

    def _task_hash(self, report: CaseReport) -> str:
        raw = f"{report.binary_hash}:{report.task.strip().lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _case_id(self, report: CaseReport) -> str:
        th = self._task_hash(report)
        dedup_key = f"{report.binary_hash}:{th}"
        now = time.time()
        if dedup_key in self._recent_dedup and now - self._recent_dedup[dedup_key] < DEDUP_WINDOW_SEC:
            return f"{report.binary_hash[7:23]}:{th}"
        self._recent_dedup[dedup_key] = now
        ts = int(now)
        return f"{report.binary_hash[7:23]}:{th}:{ts}"

    def upsert_case(self, report: CaseReport, embedding: List[float]) -> str:
        case_id = self._case_id(report)
        doc = case_document(report)
        meta: Dict[str, Any] = {
            "binary_hash": report.binary_hash,
            "binary_name": report.binary_name,
            "format": report.format,
            "arch": report.arch,
            "protection": report.protection,
            "task": report.task[:500],
            "outcome": report.outcome.value,
            "verification_level": report.verification_level.value,
            "summary": hint_summary(report),
            "strategies_json": json.dumps([s.model_dump() for s in report.strategies]),
            "cost_steps": report.cost.steps,
            "cost_tool_calls": report.cost.tool_calls,
            "failure_modes_json": json.dumps(report.failure_modes),
            "client_version": report.client_version,
        }
        self._collection.upsert(
            ids=[case_id],
            embeddings=[embedding],
            documents=[doc],
            metadatas=[meta],
        )
        return case_id

    def search(
        self,
        query_embedding: List[float],
        *,
        k: int = 5,
        filters: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[str, float, Dict[str, Any]]]:
        where: Optional[Dict[str, Any]] = None
        if filters:
            clauses = [{key: val} for key, val in filters.items() if val]
            if len(clauses) == 1:
                where = clauses[0]
            elif len(clauses) > 1:
                where = {"$and": clauses}

        result = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=min(k * 3, 30),
            where=where,
            include=["metadatas", "distances"],
        )
        ids = (result.get("ids") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        out: List[Tuple[str, float, Dict[str, Any]]] = []
        for cid, dist, meta in zip(ids, dists, metas):
            if meta is None:
                continue
            # Chroma cosine distance: 0=identical; convert to similarity
            sim = max(0.0, 1.0 - float(dist))
            out.append((cid, sim, meta))
        return out

    def stats(self) -> StatsResponse:
        total = self._collection.count()
        if total == 0:
            return StatsResponse()

        # Sample up to 500 for stats (avoid full scan on huge collections)
        sample = self._collection.get(limit=min(total, 500), include=["metadatas"])
        metas = sample.get("metadatas") or []
        success = failed = incomplete = 0
        by_format: Dict[str, int] = {}
        for m in metas:
            if not m:
                continue
            outcome = m.get("outcome", "")
            if outcome == "success":
                success += 1
            elif outcome == "failed":
                failed += 1
            else:
                incomplete += 1
            fmt = m.get("format", "unknown")
            by_format[fmt] = by_format.get(fmt, 0) + 1

        n = len(metas) or 1
        return StatsResponse(
            total=total,
            success=success,
            failed=failed,
            incomplete=incomplete,
            success_rate=round(success / n, 3),
            by_format=by_format,
        )
