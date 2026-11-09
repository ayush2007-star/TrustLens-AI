from app.config import settings
from app.services.risk_engine import calculate_risk_classification
from app.services.threat_intel_adapters import query_threat_intelligence


def test_synthetic_matches_are_not_reported_as_confirmed_provider_results():
    matches = query_threat_intelligence(
        "https://paypal-security-update.example.com/login",
        "paypal-security-update.example.com",
    )
    assert matches
    assert all(match["details"].get("synthetic_simulation") for match in matches)
    assert all(not match["is_available"] for match in matches)

    risk, *_ = calculate_risk_classification(
        findings=[],
        threat_intel_matches=matches,
        tls_report={},
        domain_info={"a_records": ["93.184.215.14"]},
        redirect_info={},
    )
    assert risk != "CONFIRMED MALICIOUS"


def test_unimplemented_feeds_do_not_claim_no_record(monkeypatch):
    monkeypatch.setattr(settings, "URLHAUS_API_ENABLED", False)

    matches = query_threat_intelligence("https://real-site.test/login", "real-site.test")
    by_name = {match["source"]: match for match in matches}
    assert by_name["URLhaus (abuse.ch)"]["verdict"] == "DISABLED"
    assert by_name["PhishTank"]["verdict"] == "UNAVAILABLE"
    assert by_name["OpenPhish Community Feed"]["verdict"] == "UNAVAILABLE"
    assert not by_name["PhishTank"]["is_available"]
    assert not by_name["OpenPhish Community Feed"]["is_available"]


def test_unreachable_target_with_unavailable_feeds_is_inconclusive():
    risk, score, *_ = calculate_risk_classification(
        findings=[],
        threat_intel_matches=[
            {"is_available": False, "is_match": False, "verdict": "UNAVAILABLE"}
        ],
        tls_report={"is_valid": False, "status_text": "Connection Error"},
        domain_info={"a_records": [], "aaaa_records": []},
        redirect_info={},
    )
    assert risk == "INCONCLUSIVE"
    assert score == 10


def test_heuristic_evidence_is_scored_even_without_network_diagnostics():
    risk, score, *_ = calculate_risk_classification(
        findings=[{"severity": "CRITICAL"}],
        threat_intel_matches=[{"is_available": False}],
        tls_report={"is_valid": False, "status_text": "Connection Error"},
        domain_info={"a_records": [], "aaaa_records": []},
        redirect_info={},
    )
    assert risk == "HIGH RISK"
    assert score == 40


def test_only_live_urlhaus_match_can_confirm_malicious():
    common = {
        "is_available": True,
        "is_match": True,
        "verdict": "MALICIOUS",
    }
    inputs = {
        "findings": [],
        "tls_report": {"is_valid": True, "subject": {"commonName": "safe.test"}},
        "domain_info": {"a_records": ["8.8.8.8"]},
        "redirect_info": {},
    }

    risk, *_ = calculate_risk_classification(
        threat_intel_matches=[{**common, "source": "VirusTotal API"}],
        **inputs,
    )
    assert risk != "CONFIRMED MALICIOUS"

    risk, *_ = calculate_risk_classification(
        threat_intel_matches=[
            {
                **common,
                "source": "URLhaus (abuse.ch)",
                "details": {"urlhaus_reference": "https://urlhaus.example/report"},
            }
        ],
        **inputs,
    )
    assert risk == "CONFIRMED MALICIOUS"
