"""Argus memory backend — FastAPI app."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.document import query_document
from app.embed import EmbeddingClient
from app.models import (
    CaseIngestResponse,
    CaseReport,
    SearchRequest,
    SearchResponse,
    StatsResponse,
)
from app.search import rank_hints
from app.store import CaseStore
from app.validate import validate_case_report

limiter = Limiter(key_func=get_remote_address, default_limits=[os.environ.get("RATE_LIMIT", "30/minute")])

_store_instance: CaseStore | None = None
_embedder: EmbeddingClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _store_instance, _embedder
    _embedder = EmbeddingClient()
    _store_instance = CaseStore(embedder=_embedder)
    yield


app = FastAPI(title="Argus Memory", version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def get_store() -> CaseStore:
    if _store_instance is None:
        raise HTTPException(status_code=503, detail="store not ready")
    return _store_instance


def get_embedder() -> EmbeddingClient:
    if _embedder is None or not _embedder.available:
        raise HTTPException(status_code=503, detail="GEMINI_API_KEY not configured")
    return _embedder


@app.get("/v1/health")
@limiter.limit("60/minute")
async def health(request: Request) -> dict:
    return {
        "ok": True,
        "embedder": _embedder is not None and _embedder.available,
        "store": _store_instance is not None,
    }


@app.post("/v1/cases", response_model=CaseIngestResponse)
@limiter.limit("30/minute")
async def ingest_case(request: Request, report: CaseReport) -> CaseIngestResponse:
    validate_case_report(report)
    from app.document import case_document

    embedder = get_embedder()
    store = get_store()
    vec = embedder.embed_one(case_document(report))
    if not vec:
        raise HTTPException(status_code=502, detail="embedding failed")
    case_id = store.upsert_case(report, vec)
    return CaseIngestResponse(ok=True, case_id=case_id)


@app.post("/v1/search", response_model=SearchResponse)
@limiter.limit("60/minute")
async def search_cases(request: Request, body: SearchRequest) -> SearchResponse:
    embedder = get_embedder()
    store = get_store()
    vec = embedder.embed_one(body.query_text)
    if not vec:
        raise HTTPException(status_code=502, detail="embedding failed")
    raw = store.search(vec, k=body.k, filters=body.filters or None)
    hints = rank_hints(raw, k=body.k)
    return SearchResponse(ok=True, hints=hints)


@app.get("/v1/stats", response_model=StatsResponse)
@limiter.limit("30/minute")
async def stats(request: Request) -> StatsResponse:
    return get_store().stats()
