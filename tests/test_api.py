from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api import state


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Explicit SQLite file so the test never depends on an external database.
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setattr(state, "_db", None)

    from src.api.server import app

    with TestClient(app) as test_client:
        yield test_client


def test_create_and_search_ioc(client):
    created = client.post(
        "/api/v1/iocs",
        json={"type": "ip", "value": "203.0.113.9", "tags": ["c2"], "severity": 8},
    )
    assert created.status_code == 201, created.text
    ioc_id = created.json()["id"]

    assert client.get(f"/api/v1/iocs/{ioc_id}").json()["value"] == "203.0.113.9"
    results = client.get("/api/v1/search", params={"q": "203.0.113"}).json()
    assert [i["id"] for i in results["iocs"]] == [ioc_id]
    assert client.get("/api/v1/stats").json()["total_iocs"] == 1


def test_create_threat(client):
    response = client.post(
        "/api/v1/threats", json={"name": "Test campaign", "tags": ["c2"]}
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "new"
