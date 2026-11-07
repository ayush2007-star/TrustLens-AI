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
    Includes both benign real-world cases and clearly-labeled SYNTHETIC DEMO cases.
    """
    if db.query(Investigation).first():
        return # Already seeded

    now = datetime.now(timezone.utc)

    # ----------------------------------------------------
    # Case 1: Benign - Wikipedia (Real World)
    # ----------------------------------------------------
    inv_wiki = Investigation(
        target_url="https://en.wikipedia.org",
        normalized_url="https://en.wikipedia.org/",
        hostname="en.wikipedia.org",
        domain="wikipedia.org",
        ip_address="208.80.154.224",
        overall_risk="LOW RISK",
        risk_score=8,
        confidence="HIGH",
        summary="Legitimate institutional encyclopedia. Strong TLS configuration and valid domain registration.",
        analysis_limitations=["Passive observation only."],
        is_synthetic_demo=False,
        status="COMPLETED",
        created_at=now - timedelta(hours=6)
    )
    db.add(inv_wiki)
    db.flush()

    db.add(DomainInformation(
        investigation_id=inv_wiki.id,
        domain="wikipedia.org",
        registrar="MarkMonitor Inc.",
        creation_date="2001-01-13",
        expiration_date="2030-01-13",
        age_days=9400,
        nameservers=["ns0.wikimedia.org", "ns1.wikimedia.org"],
        a_records=["208.80.154.224"],
        aaaa_records=["2620:0:861:ed1a::1"],
        mx_records=["10 mx1001.wikimedia.org"],
        suspicious_dns_flags=[]
    ))
    db.add(TLSReport(
        investigation_id=inv_wiki.id,
        is_valid=True,
        status_text="Valid for inspected hostname",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=60),
        days_remaining=60,
        subject={"commonName": "*.wikipedia.org", "organization": "Wikimedia Foundation, Inc."},
        issuer={"commonName": "Let's Encrypt Authority X3", "organization": "Let's Encrypt"},
        san_list=["*.wikipedia.org", "wikipedia.org"],
        signature_algorithm="sha256WithRSAEncryption",
        key_type="RSA",
        key_size=2048,
        tls_version="TLSv1.3",
        hostname_match=True
    ))
    db.add(SecurityAssessment(
        investigation_id=inv_wiki.id,
        https_available=True,
        http_status=200,
        security_headers={
            "strict_transport_security": "max-age=31536000; includeSubDomains; preload",
            "content_security_policy": "default-src 'self'",
            "x_frame_options": "SAMEORIGIN",
            "x_content_type_options": "nosniff"
        },
        robots_txt_status="Present (HTTP 200)",
        security_txt_status="Present (HTTP 200 / RFC 9116)"
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
        is_available=True,
        is_match=True,
        verdict="MALICIOUS",
        confidence="HIGH",
        details={"category": "Credential Harvesting Kit", "target": "PayPal"}
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
        description="Phishing kit targeting Chase Bank users via SMS smishing campaign. Fake KYC verification prompt.",
        evidence_reference="SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        reporter_alias="RedTeam_Analyst_99",
        verification_status="Supported by Evidence",
        upvotes=7,
        tags=["chase", "banking", "sms-smishing"]
    )
    db.add(rep1)
    db.flush()
    # Register rep1 in immutable ledger!
    register_threat_report_on_chain(db, rep1.id)

    rep2 = ThreatReport(
        target_url="https://dhl-express-tracking.example.net/customs-fee",
        domain="example.net",
        report_type="IMPERSONATION",
        severity="HIGH",
        description="Fake parcel customs clearance fee demanding $2.50 via prepaid card or untraceable crypto wallet.",
        evidence_reference="Reported via SMS gateway lure #88219",
        reporter_alias="CyberShield_Watch",
        verification_status="Under Review",
        upvotes=4,
        tags=["dhl", "advance-fee", "delivery"]
    )
    db.add(rep2)
    db.flush()
    # Register rep2 in immutable ledger!
    register_threat_report_on_chain(db, rep2.id)

    # ----------------------------------------------------
    # Sample Scam Message Analyses
    # ----------------------------------------------------
    msg1 = ScamMessageAnalysis(
        input_preview="URGENT: Your Chase banking account has been locked. Reply with your 6-digit OTP immediately...",
        analyzed_via="deterministic",
        risk_level="HIGH RISK",
        risk_score=95,
        confidence="HIGH",
        urgency_detected=True,
        credential_request=True,
        payment_request=False,
        impersonation_target="Chase Bank",
        indicators=[
            {
                "category": "CREDENTIAL_HARVESTING",
                "title": "Solicitation of One-Time Password / Security Code",
                "severity": "CRITICAL",
                "evidence_snippet": "OTP",
                "reasoning": "Legitimate banks NEVER ask customers to disclose OTPs via SMS or phone."
            },
            {
                "category": "URGENCY",
                "title": "Threat of punitive service termination",
                "severity": "HIGH",
                "evidence_snippet": "locked",
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
