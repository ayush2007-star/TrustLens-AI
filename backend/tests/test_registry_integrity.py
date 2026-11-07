import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.models.threat_report import ThreatReport
from app.services.registry_service import (
    register_threat_report_on_chain,
    verify_report_integrity,
    create_canonical_payload,
    compute_sha256
)

@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_registry_registration_and_verification(test_db):
    # 1. Create a threat report
    report = ThreatReport(
        target_url="https://phishing-portal.example.com",
        domain="example.com",
        report_type="PHISHING",
        severity="HIGH",
        description="Fake credentials stealer",
        reporter_alias="Tester_1"
    )
    test_db.add(report)
    test_db.commit()

    # 2. Register on chain
    entry = register_threat_report_on_chain(test_db, report.id)
    assert entry.block_index == 0
    assert len(entry.chained_hash) == 64
    assert len(entry.data_hash) == 64

    # 3. Verify integrity
    verif = verify_report_integrity(test_db, report.id)
    assert verif["is_registered"] is True
    assert verif["is_tampered"] is False
    assert verif["status"] == "VERIFIED_AUTHENTIC"

def test_registry_tamper_detection(test_db):
    report = ThreatReport(
        target_url="https://phishing-portal.example.com",
        domain="example.com",
        report_type="PHISHING",
        severity="HIGH",
        description="Original authentic description",
        reporter_alias="Tester_2"
    )
    test_db.add(report)
    test_db.commit()

    entry = register_threat_report_on_chain(test_db, report.id)

    # Maliciously modify report in DB without updating registry
    report.description = "MALICIOUSLY TAMPERED CONTENT"
    test_db.commit()

    verif = verify_report_integrity(test_db, report.id)
    assert verif["is_tampered"] is True
    assert verif["status"] == "TAMPER_DETECTED"
