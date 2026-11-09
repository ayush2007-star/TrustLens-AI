from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.models.investigation import (
    Investigation,
    DomainInformation,
    URLFinding,
    TLSReport,
    SecurityAssessment,
    ThreatIntelMatch
)
from app.models.threat_report import ThreatReport, ScamMessageAnalysis
from app.services.registry_service import register_threat_report_on_chain

def seed_sample_data(db: Session):
    """
    Seeds initial benchmark investigations, threat reports, and scam messages.
    All seeded cases are clearly labeled synthetic demo data.
    """
    if db.query(Investigation).first():
        return # Already seeded

    now = datetime.now(timezone.utc)

    # ----------------------------------------------------
    # Case 1: Synthetic benign baseline
    # ----------------------------------------------------
    inv_baseline = Investigation(
        target_url="https://example.com",
        normalized_url="https://example.com/",
        hostname="example.com",
        domain="example.com",
        ip_address="93.184.215.14",
        overall_risk="LOW RISK",
        risk_score=8,
        confidence="HIGH",
        summary="SYNTHETIC BENCHMARK: Benign baseline fixture; not a live assessment of a real organization.",
        analysis_limitations=["Synthetic demonstration data; no live network assessment was performed."],
        is_synthetic_demo=True,
        status="COMPLETED",
        created_at=now - timedelta(hours=6)
    )
    db.add(inv_baseline)
    db.flush()

    db.add(DomainInformation(
        investigation_id=inv_baseline.id,
        domain="example.com",
        registrar="RESERVED - Internet Assigned Numbers Authority",
        creation_date="1992-01-01",
        expiration_date="Reserved example domain",
        age_days=9400,
        nameservers=["a.iana-servers.net", "b.iana-servers.net"],
        a_records=["93.184.215.14"],
        suspicious_dns_flags=["SYNTHETIC_BENCHMARK: Reserved example domain"]
    ))
    db.add(TLSReport(
        investigation_id=inv_baseline.id,
        is_valid=True,
        status_text="Valid for inspected hostname (Synthetic Benchmark)",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=60),
        days_remaining=60,
        subject={"commonName": "example.com", "organization": "Synthetic benchmark"},
        issuer={"commonName": "Synthetic test data"},
        san_list=["example.com", "*.example.com"],
        signature_algorithm="sha256WithRSAEncryption",
        key_type="RSA",
        key_size=2048,
        tls_version="TLSv1.3 (Synthetic Benchmark)",
        hostname_match=True
    ))
    db.add(SecurityAssessment(
        investigation_id=inv_baseline.id,
        https_available=True,
        http_status=200,
        security_headers={"synthetic_demo": True},
        robots_txt_status="Present (HTTP 200)",
        security_txt_status="Present (Synthetic Benchmark)"
    ))

    # ----------------------------------------------------
    # Case 2: Synthetic Suspicious - PayPal Brand Impersonation
    # ----------------------------------------------------
    inv_paypal = Investigation(
        target_url="https://paypal-security-update.example.com/login?token=urgent",
        normalized_url="https://paypal-security-update.example.com/login?token=urgent",
        hostname="paypal-security-update.example.com",
        domain="example.com",
        ip_address="93.184.215.14",
        overall_risk="HIGH RISK",
        risk_score=85,
        confidence="HIGH",
        summary="SYNTHETIC BENCHMARK: High-severity brand impersonation targeting PAYPAL on an unassociated domain with credential-harvesting tokens.",
        analysis_limitations=["Demonstration benchmark using RFC 2606 reserved example.com domain."],
        is_synthetic_demo=True,
        status="COMPLETED",
        created_at=now - timedelta(hours=3)
    )
    db.add(inv_paypal)
    db.flush()

    db.add(URLFinding(
        investigation_id=inv_paypal.id,
        category="TYPOSQUAT",
        finding_title="Brand Impersonation Detected: 'PAYPAL'",
        severity="HIGH",
        evidence="The brand 'paypal' is present in host 'paypal-security-update.example.com', but base domain is 'example.com'.",
        impact="High likelihood of credential harvesting deceiving users expecting official PayPal authentication.",
        remediation="Never enter PayPal credentials outside official 'paypal.com'."
    ))
    db.add(URLFinding(
        investigation_id=inv_paypal.id,
        category="HEURISTIC",
        finding_title="Sensitive Action Keywords: login, security, update",
        severity="MEDIUM",
        evidence="URL contains multiple sensitive authentication parameters: ['login', 'security', 'update'].",
        impact="Clustered urgency tokens are strongly correlated with credential theft pages.",
        remediation="Check official account portal directly."
    ))
    db.add(DomainInformation(
        investigation_id=inv_paypal.id,
        domain="example.com",
        registrar="IANA Reserved Benchmark",
        creation_date="1992-01-01",
        expiration_date="2030-01-01",
        nameservers=["a.iana-servers.net"],
        a_records=["93.184.215.14"],
        suspicious_dns_flags=["SYNTHETIC_BENCHMARK: Reserved test domain"]
    ))
    db.add(TLSReport(
        investigation_id=inv_paypal.id,
        is_valid=False,
        status_text="Hostname mismatch (Synthetic Benchmark)",
        not_before=now - timedelta(days=100),
        not_after=now + timedelta(days=200),
        days_remaining=200,
        subject={"commonName": "example.com"},
        issuer={"commonName": "DigiCert Global Root G2"},
        san_list=["example.com", "www.example.com"],
        hostname_match=False
    ))
    db.add(ThreatIntelMatch(
        investigation_id=inv_paypal.id,
        source="TrustLens Phishing Heuristic Engine",
        is_available=False,
        is_match=True,
        verdict="SIMULATED_MALICIOUS",
        confidence="HIGH",
        details={"synthetic_simulation": True, "category": "Credential Harvesting Kit", "target": "PayPal"}
    ))

    # ----------------------------------------------------
    # Case 3: Synthetic Malicious - Direct IP & Non-Standard Port
    # ----------------------------------------------------
    inv_ip = Investigation(
        target_url="http://198.51.100.42:8080/banking/verification",
        normalized_url="http://198.51.100.42:8080/banking/verification",
        hostname="198.51.100.42",
        domain="198.51.100.42",
        ip_address="198.51.100.42",
        overall_risk="HIGH RISK",
        risk_score=90,
        confidence="HIGH",
        summary="SYNTHETIC BENCHMARK: Critical anomaly: Raw IP hosting, plaintext HTTP without TLS, non-standard port 8080, and banking verification keywords.",
        analysis_limitations=["Demonstration benchmark using RFC 5737 TEST-NET-2 IP."],
        is_synthetic_demo=True,
        status="COMPLETED",
        created_at=now - timedelta(hours=1)
    )
    db.add(inv_ip)
    db.flush()

    db.add(URLFinding(
        investigation_id=inv_ip.id,
        category="HEURISTIC",
        finding_title="Raw IP Address Used in Host Segment",
        severity="HIGH",
        evidence="Host '198.51.100.42' lacks registered domain reputation.",
        impact="Commonly used by disposable command-and-control and phishing panels.",
        remediation="Do not submit credentials to raw IP hosts."
    ))
    db.add(URLFinding(
        investigation_id=inv_ip.id,
        category="HEURISTIC",
        finding_title="Non-Standard Service Port: :8080",
        severity="MEDIUM",
        evidence="Web traffic runs over non-standard port 8080 without encryption.",
        impact="Bypasses typical port 80/443 monitoring.",
        remediation="Restrict corporate egress to verified ports."
    ))

    # ----------------------------------------------------
    # Community Threat Reports & Chained Trust Registry
    # ----------------------------------------------------
    rep1 = ThreatReport(
        target_url="https://secure-chase-online.example.org/verify",
        domain="example.org",
        report_type="PHISHING",
        severity="CRITICAL",
        description="SYNTHETIC BENCHMARK: Example phishing report targeting a fictionalized Chase-lookalike URL.",
        evidence_reference="SYNTHETIC BENCHMARK DATA; no source evidence attached.",
        reporter_alias="RedTeam_Analyst_99",
        verification_status="Pending",
        upvotes=0,
        tags=["chase", "banking", "sms-smishing"]
    )
    db.add(rep1)
    db.flush()
    # Register the synthetic benchmark report in the local hash ledger.
    register_threat_report_on_chain(db, rep1.id)

    rep2 = ThreatReport(
        target_url="https://dhl-express-tracking.example.net/customs-fee",
        domain="example.net",
        report_type="IMPERSONATION",
        severity="HIGH",
        description="SYNTHETIC BENCHMARK: Example delivery-fee lure; not a verified real-world report.",
        evidence_reference="SYNTHETIC BENCHMARK DATA; no source evidence attached.",
        reporter_alias="CyberShield_Watch",
        verification_status="Under Review",
        upvotes=4,
        tags=["dhl", "advance-fee", "delivery"]
    )
    db.add(rep2)
    db.flush()
    # Register the synthetic benchmark report in the local hash ledger.
    register_threat_report_on_chain(db, rep2.id)

    # ----------------------------------------------------
    # Sample Scam Message Analyses
    # ----------------------------------------------------
    msg1 = ScamMessageAnalysis(
        input_preview="[Message content withheld for privacy]",
        analyzed_via="deterministic",
        risk_level="HIGH RISK",
        risk_score=95,
        confidence="HIGH",
        urgency_detected=True,
        credential_request=True,
        payment_request=False,
        impersonation_target="Impersonation of banking/security fraud staff",
        indicators=[
            {
                "category": "CREDENTIAL_HARVESTING",
                "title": "Solicitation of One-Time Password / Security Code",
                "severity": "CRITICAL",
                "evidence_snippet": "[redacted]",
                "reasoning": "Legitimate banks NEVER ask customers to disclose OTPs via SMS or phone."
            },
            {
                "category": "URGENCY",
                "title": "Threat of punitive service termination",
                "severity": "HIGH",
                "evidence_snippet": "[redacted]",
                "reasoning": "Fabricates panic to bypass logical verification."
            }
        ],
        explanation="Classic smishing (SMS phishing) attack combining urgent account lockout threats with direct OTP harvesting.",
        recommended_precautions=[
            "Never disclose One-Time Passwords (OTPs) to anyone.",
            "Contact your bank directly via the phone number on the back of your card."
        ],
        limitations=["Analysis based on deterministic security rules."]
    )
    db.add(msg1)

    db.commit()
