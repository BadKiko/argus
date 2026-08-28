"""Rank and format search results."""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Tuple

from app.models import HintItem


def _outcome_weight(outcome: str) -> float:
    if outcome == "success":
        return 1.0
    if outcome == "failed":
        return 0.55
    return 0.65


def _verification_weight(level: str) -> float:
    if level == "FORMALLY_VERIFIED":
        return 1.2
    if level == "BEHAVIOR_VERIFIED":
        return 1.1
    if level == "EXECUTION_VERIFIED":
        return 1.0
    return 0.5


def rank_hints(
    raw: List[Tuple[str, float, Dict[str, Any]]],
    *,
    k: int = 5,
) -> List[HintItem]:
    scored: List[Tuple[float, HintItem]] = []
    for case_id, similarity, meta in raw:
        outcome = meta.get("outcome", "incomplete")
        vlevel = meta.get("verification_level", "UNKNOWN")
        steps = int(meta.get("cost_steps") or 1)
        cost_div = math.log1p(max(steps, 1))
        rank = (
            similarity
            * _outcome_weight(outcome)
            * _verification_weight(vlevel)
            / cost_div
        )
        strategies: List[Dict[str, Any]] = []
        try:
            strategies = json.loads(meta.get("strategies_json") or "[]")
        except json.JSONDecodeError:
            pass
        item = HintItem(
            score=round(rank, 3),
            outcome=outcome,
            summary=meta.get("summary") or "",
            strategies=strategies,
            verification_level=vlevel,
            case_id=case_id,
        )
        scored.append((rank, item))

    scored.sort(key=lambda t: -t[0])
    seen: set[str] = set()
    out: List[HintItem] = []
    for _, item in scored:
        key = f"{item.summary}:{item.outcome}"
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= k:
            break
    return out
