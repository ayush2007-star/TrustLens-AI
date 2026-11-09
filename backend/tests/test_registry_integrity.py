import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.models.threat_report import ThreatReport
from app.services.registry_service import (
    register_threat_report_on_chain,
    verify_report_integrity,
    create_canonical_payload,
    compute_sha256,
    count_verified_registry_blocks
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
    assert count_verified_registry_blocks(test_db) == 1

    # Maliciously modify report in DB without updating registry
    report.description = "MALICIOUSLY TAMPERED CONTENT"
    test_db.commit()
    assert count_verified_registry_blocks(test_db) == 0

    verif = verify_report_integrity(test_db, report.id)
    assert verif["is_tampered"] is True
    assert verif["status"] == "TAMPER_DETECTED"


def test_registry_detects_canonical_payload_and_genesis_tampering(test_db):
    report = ThreatReport(
        target_url="https://registry-test.example.com",
        domain="example.com",
        report_type="PHISHING",
        severity="HIGH",
        description="A report used to test chain verification.",
        reporter_alias="Tester_3"
    )
    test_db.add(report)
    test_db.commit()
    entry = register_threat_report_on_chain(test_db, report.id)

    entry.canonical_payload = "{}"
    entry.previous_hash = "f" * 64
    test_db.commit()

    verification = verify_report_integrity(test_db, report.id)
    assert verification["is_tampered"] is True
    assert verification["status"] == "TAMPER_DETECTED"


def test_registry_detects_tampering_in_another_report_payload(test_db):
    first = ThreatReport(
        target_url="https://safe.example.com",
        domain="example.com",
        report_type="PHISHING",
        severity="HIGH",
        description="Original safe report",
        reporter_alias="Alice"
    )
    second = ThreatReport(
        target_url="https://target.example.com",
        domain="example.com",
        report_type="MALWARE",
        severity="CRITICAL",
        description="Check this report",
        reporter_alias="Bob"
    )
    test_db.add_all([first, second])
    test_db.commit()

    register_threat_report_on_chain(test_db, first.id)
    register_threat_report_on_chain(test_db, second.id)

    first_entry = test_db.query(type(first).__mro__[0]).filter_by(id=first.id).first()
    # Use the first report object as a known good chain anchor; rewrite the canonical payload of the first block
    # to ensure verification of a later report catches remote mutation in the same chain.
    from app.models.registry import ThreatRegistryEntry
    entry = test_db.query(ThreatRegistryEntry).filter(ThreatRegistryEntry.report_id == first.id).first()
    entry.canonical_payload = '{"tampered": true}'
    test_db.commit()

    verification = verify_report_integrity(test_db, second.id)
    assert verification["is_tampered"] is True
    assert verification["status"] == "TAMPER_DETECTED"
