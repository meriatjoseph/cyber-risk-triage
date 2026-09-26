"""POST /refresh is gated by the REFRESH_TOKEN env var (disabled when unset)."""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import main


@pytest.fixture
def client(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "build_top_risk_report", lambda: calls.append(1) or [])
    c = TestClient(main.app)  # not used as a context manager, so the startup build doesn't run
    c.calls = calls
    return c


def test_refresh_disabled_when_token_unset(client, monkeypatch):
    monkeypatch.delenv("REFRESH_TOKEN", raising=False)
    r = client.post("/refresh", headers={"X-Refresh-Token": "anything"})
    assert r.status_code == 403
    assert client.calls == []


def test_refresh_rejects_missing_or_wrong_token(client, monkeypatch):
    monkeypatch.setenv("REFRESH_TOKEN", "s3cret")
    assert client.post("/refresh").status_code == 403
    assert client.post("/refresh", headers={"X-Refresh-Token": "wrong"}).status_code == 403
    assert client.calls == []


def test_refresh_runs_with_correct_token(client, monkeypatch):
    monkeypatch.setenv("REFRESH_TOKEN", "s3cret")
    r = client.post("/refresh", headers={"X-Refresh-Token": "s3cret"})
    assert r.status_code == 200
    assert client.calls == [1]


def test_health_is_open(client):
    assert client.get("/health").json() == {"status": "ok"}
