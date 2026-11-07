import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.seed_data import seed_sample_data

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
    assert len(data["findings"]) > 0

def test_analyze_message_endpoint():
    response = client.post("/api/analyze-message", json={
        "message_text": "Your account is locked. Send your OTP code right away or face permanent suspension."
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ("HIGH RISK", "SUSPICIOUS")
    assert len(data["indicators"]) > 0

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
