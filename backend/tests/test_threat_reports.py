import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base, get_db
from app.models.threat_report import ThreatReport
from app.routers.threat_reports import router


@pytest.fixture
def community_client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()
    app = FastAPI()
    app.include_router(router)
    app.state.client_host = "203.0.113.10"

    @app.middleware("http")
    async def set_test_client(request, call_next):
        request.scope["client"] = (app.state.client_host, 12345)
        return await call_next(request)

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(settings, "COMMUNITY_WRITES_ENABLED", True)
    monkeypatch.setattr(settings, "COMMUNITY_ABUSE_KEY", "a" * 32)
    with TestClient(app) as client:
        yield client, app, db
    db.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def report_payload():
    return {
        "target_url": "https://phishing.example.test/login",
        "report_type": "PHISHING",
        "severity": "HIGH",
        "description": "A test report describing a suspicious login page.",
    }


def test_repeated_upvote_from_same_network_is_not_counted(community_client):
    client, _, db = community_client
    report_response = client.post("/api/threat-reports", json=report_payload())
    report_id = report_response.json()["id"]

    first_vote = client.post(f"/api/threat-reports/{report_id}/upvote")
    repeated_vote = client.post(f"/api/threat-reports/{report_id}/upvote")

    assert first_vote.status_code == 200
    assert first_vote.json()["upvotes"] == 1
    assert repeated_vote.status_code == 409
    assert db.query(ThreatReport).filter_by(id=report_id).one().upvotes == 1


def test_report_creation_is_limited_per_network(community_client):
    client, _, _ = community_client

    responses = [
        client.post("/api/threat-reports", json=report_payload())
        for _ in range(6)
    ]

    assert [response.status_code for response in responses] == [
        200, 200, 200, 200, 200, 429
    ]


def test_upvotes_are_limited_per_network(community_client):
    client, _, _ = community_client
    report_response = client.post("/api/threat-reports", json=report_payload())
    report_id = report_response.json()["id"]

    responses = [
        client.post(f"/api/threat-reports/{report_id}/upvote")
        for _ in range(21)
    ]

    assert responses[0].status_code == 200
    assert all(response.status_code == 409 for response in responses[1:20])
    assert responses[20].status_code == 429


def test_community_writes_fail_closed_when_disabled(community_client, monkeypatch):
    client, _, _ = community_client
    monkeypatch.setattr(settings, "COMMUNITY_WRITES_ENABLED", False)

    response = client.post("/api/threat-reports", json=report_payload())

    assert response.status_code == 503
    assert "disabled" in response.json()["detail"].lower()
