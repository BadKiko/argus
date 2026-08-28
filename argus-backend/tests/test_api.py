"""Backend tests for Argus memory API."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Set env before app import
os.environ.setdefault("GEMINI_API_KEY", "test-key")


@pytest.fixture
def mock_embedder():
    with patch("app.main.get_embedder") as m:
        emb = MagicMock()
        emb.available = True
        emb.embed_one.return_value = [0.1] * 8
        m.return_value = emb
        yield emb


@pytest.fixture
def mock_store():
    with patch("app.main.get_store") as m:
        store = MagicMock()
        store.upsert_case.return_value = "abc123:dead:1700000000"
        store.search.return_value = [
            (
                "case1",
                0.9,
                {
                    "outcome": "success",
                    "verification_level": "EXECUTION_VERIFIED",
                    "summary": "slice+apply_plan",
                    "strategies_json": '[{"tool": "argus_slice", "ok": true}]',
                    "cost_steps": 5,
                },
            )
        ]
        store.stats.return_value = __import__("app.models", fromlist=["StatsResponse"]).StatsResponse(
            ok=True,
            total=1,
            success=1,
            failed=0,
            incomplete=0,
            success_rate=1.0,
            by_format={"elf": 1},
        )
        m.return_value = store
        yield store


@pytest.fixture
def client(mock_embedder, mock_store):
    from app.main import app

    return TestClient(app)


VALID_CASE = {
    "binary_hash": "sha256:" + "a" * 64,
    "binary_name": "test_bin",
    "format": "elf",
    "arch": "x86_64",
    "protection": "stripped",
    "features": {"needle_score": 5},
    "task": "remove license check",
    "task_kinds": ["gate_transform"],
    "strategies": [{"tool": "argus_slice", "ok": True}],
    "outcome": "success",
    "verification_level": "EXECUTION_VERIFIED",
    "failure_modes": [],
    "cost": {"steps": 4, "tool_calls": 6},
    "modules_patched": [],
    "client_version": "0.2.0",
}


def test_health(client):
    r = client.get("/v1/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_ingest_valid_case(client, mock_store):
    r = client.post("/v1/cases", json=VALID_CASE)
    assert r.status_code == 200
    assert r.json()["ok"] is True
    mock_store.upsert_case.assert_called_once()


def test_reject_invalid_hash(client):
    bad = dict(VALID_CASE)
    bad["binary_hash"] = "not-a-hash"
    r = client.post("/v1/cases", json=bad)
    assert r.status_code == 422


def test_reject_no_argus_tools(client):
    bad = dict(VALID_CASE)
    bad["strategies"] = [{"tool": "random_spam", "ok": True}]
    r = client.post("/v1/cases", json=bad)
    assert r.status_code == 422


def test_reject_absolute_path(client):
    bad = dict(VALID_CASE)
    bad["task"] = "patch /home/user/secret binary"
    r = client.post("/v1/cases", json=bad)
    assert r.status_code == 422


def test_search(client, mock_store):
    r = client.post(
        "/v1/search",
        json={"query_text": "format=elf arch=x86_64 protection=stripped task=gate_transform", "k": 3},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert len(data["hints"]) >= 1


def test_stats(client):
    r = client.get("/v1/stats")
    assert r.status_code == 200
