import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.seed_data import seed_sample_data
from app.models.threat_report import ScamMessageAnalysis
from app.models.investigation import Investigation
from app.config import settings

# Ensure tables and seed data exist for test suite
Base.metadata.create_all(bind=engine)
db = SessionLocal()
seed_sample_data(db)
db.close()

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "TrustLens AI" in data["service"]
    assert data["access_control_required"] is False


def test_cors_allows_configured_origin_only():
    allowed = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    rejected = client.options(
        "/api/health",
        headers={
            "Origin": "http://attacker.test",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert rejected.headers.get("access-control-allow-origin") != "*"


def test_data_api_requires_configured_bearer_token(monkeypatch):
    token = "unit-test-shared-access-token-with-more-than-32-characters"
    monkeypatch.setattr(settings, "APP_ACCESS_TOKEN", token)

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/investigations").status_code == 401
    assert client.get("/api/investigations").headers["www-authenticate"] == "Bearer"

    authorized = client.get("/api/investigations", headers={"Authorization": f"Bearer {token}"})
    assert authorized.status_code == 200
    investigation_id = authorized.json()[0]["id"]
    assert client.get(f"/api/investigations/{investigation_id}").status_code == 401
    assert client.get(
        f"/api/investigations/{investigation_id}",
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 200
    assert client.get("/api/session", headers={"Authorization": f"Bearer {token}"}).json() == {
        "authenticated": True
    }


def test_security_response_headers_are_set():
    response = client.get("/api/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"


def test_tls_and_security_assessments_do_not_create_investigations():
    db = SessionLocal()
    try:
        before = db.query(Investigation).count()
    finally:
        db.close()

    tls = client.post("/api/analyze-tls", json={"url": "https://paypal-security-update.example.com"})
    assessment = client.post("/api/analyze-security", json={"url": "https://paypal-security-update.example.com"})

    assert tls.status_code == 200
    assert tls.json()["is_valid"] is True
    assert assessment.status_code == 200
    assert assessment.json()["https_available"] is True

    db = SessionLocal()
    try:
        assert db.query(Investigation).count() == before
    finally:
        db.close()


def test_dashboard_stats():
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_investigations" in data
    assert "threat_distribution" in data

def test_investigate_synthetic_url():
    response = client.post("/api/investigations", json={"url": "https://paypal-security-update.example.com/login"})
    assert response.status_code == 200
    data = response.json()
    assert data["hostname"] == "paypal-security-update.example.com"
    assert data["overall_risk"] in ("HIGH RISK", "SUSPICIOUS", "CONFIRMED MALICIOUS")
    assert data["overall_risk"] != "CONFIRMED MALICIOUS"
    assert len(data["findings"]) > 0

def test_analyze_message_endpoint():
    message = "Send OTP 123456 now: https://example.test/verify?token=secret"
    response = client.post("/api/analyze-message", json={
        "message_text": message
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ("HIGH RISK", "SUSPICIOUS")
    assert len(data["indicators"]) > 0
    db = SessionLocal()
    try:
        stored = db.query(ScamMessageAnalysis).filter_by(id=data["id"]).one()
        assert stored.input_preview == "[Message content withheld for privacy]"
        assert all(i["evidence_snippet"] == "[redacted]" for i in stored.indicators)
        assert "secret" not in stored.input_preview
    finally:
        db.close()

def test_registry_endpoints():
    response = client.get("/api/registry")
    assert response.status_code == 200
    entries = response.json()
    assert isinstance(entries, list)
    if len(entries) > 0:
        rep_id = entries[0]["report_id"]
        verif_res = client.get(f"/api/registry/verify/{rep_id}")
        assert verif_res.status_code == 200
        assert verif_res.json()["is_registered"] is True
        assert verif_res.json()["status"] == "VERIFIED_AUTHENTIC"
