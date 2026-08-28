"""Pydantic models for case ingest and search."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class VerificationLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    BYTES_VERIFIED = "BYTES_VERIFIED"
    EXECUTION_VERIFIED = "EXECUTION_VERIFIED"
    BEHAVIOR_VERIFIED = "BEHAVIOR_VERIFIED"
    FORMALLY_VERIFIED = "FORMALLY_VERIFIED"


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class StrategyStep(BaseModel):
    tool: str
    ok: Optional[bool] = None
    summary: Optional[str] = None
    verify_kind: Optional[str] = None


class CaseCost(BaseModel):
    steps: int = 0
    tool_calls: int = 0


class CaseReport(BaseModel):
    binary_hash: str
    binary_name: str = "unknown"
    format: str
    arch: str
    protection: str = "unknown"
    features: Dict[str, Any] = Field(default_factory=dict)
    task: str
    task_kinds: List[str] = Field(default_factory=list)
    strategies: List[StrategyStep]
    outcome: Outcome
    plan_sourced: Optional[bool] = None
    verification_level: VerificationLevel = VerificationLevel.UNKNOWN
    failure_modes: List[str] = Field(default_factory=list)
    cost: CaseCost = Field(default_factory=CaseCost)
    modules_patched: List[str] = Field(default_factory=list)
    client_version: str = "0.0.0"

    @field_validator("binary_hash")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("sha256:") or len(v) != 71:
            raise ValueError("binary_hash must be sha256:<64 hex chars>")
        hexpart = v[7:]
        if len(hexpart) != 64 or not all(c in "0123456789abcdef" for c in hexpart.lower()):
            raise ValueError("invalid sha256 hex")
        return v.lower()


class CaseIngestResponse(BaseModel):
    ok: bool = True
    case_id: str


class SearchRequest(BaseModel):
    query_text: str = Field(min_length=8, max_length=4000)
    k: int = Field(default=5, ge=1, le=20)
    filters: Dict[str, str] = Field(default_factory=dict)


class HintItem(BaseModel):
    score: float
    outcome: str
    summary: str
    strategies: List[Dict[str, Any]] = Field(default_factory=list)
    verification_level: str = "UNKNOWN"
    case_id: Optional[str] = None


class SearchResponse(BaseModel):
    ok: bool = True
    hints: List[HintItem] = Field(default_factory=list)


class StatsResponse(BaseModel):
    ok: bool = True
    total: int = 0
    success: int = 0
    failed: int = 0
    incomplete: int = 0
    success_rate: float = 0.0
    by_format: Dict[str, int] = Field(default_factory=dict)
