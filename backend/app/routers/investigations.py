from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.investigation import (
    Investigation,
    DomainInformation,
    URLFinding,
    TLSReport,
    SecurityAssessment,
    ThreatIntelMatch
)
from app.schemas.investigation import (
    InvestigationRequest,
    InvestigationResponse,
    InvestigationSummary,
    TLSReportSchema,
    SecurityAssessmentSchema
)
from app.services.url_normalizer import normalize_url, analyze_url_heuristics
from app.services.domain_intel import inspect_dns_records, inspect_whois_data
from app.services.redirect_tracer import trace_redirects_safely
from app.services.tls_inspector import inspect_tls_certificate
from app.services.security_headers import assess_website_security
from app.services.threat_intel_adapters import query_threat_intelligence
from app.services.risk_engine import calculate_risk_classification
from app.services.demo_data import is_synthetic_demo_host

router = APIRouter(prefix="/api", tags=["Investigations"])

def _normalize_request_url(url: str):
    try:
        return normalize_url(url.strip())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"URL Normalization Failed: {str(exc)}") from exc


@router.post("/analyze-tls", response_model=TLSReportSchema)
def analyze_tls(payload: InvestigationRequest):
    parsed_url = _normalize_request_url(payload.url)
    if parsed_url["scheme"] != "https":
        return {
            "is_valid": False,
            "status_text": "Not inspected: target uses HTTP",
            "hostname_match": False,
            "connection_errors": [],
            "limitation_notes": "TLS is not available for an HTTP target.",
        }
    return inspect_tls_certificate(parsed_url["hostname"], port=parsed_url["port"] or 443)


@router.post("/analyze-security", response_model=SecurityAssessmentSchema)
def analyze_security(payload: InvestigationRequest):
    parsed_url = _normalize_request_url(payload.url)
    return assess_website_security(parsed_url["normalized_url"])


@router.post("/investigations", response_model=InvestigationResponse)
@router.post("/analyze-url", response_model=InvestigationResponse)
def run_investigation(payload: InvestigationRequest, db: Session = Depends(get_db)):
    """
    Executes a comprehensive, multi-stage website threat and digital trust investigation:
    1. URL normalization & deceptive pattern heuristics
    2. Real DNS & WHOIS domain intelligence
    3. Safe redirect analysis with SSRF safeguards
    4. TLS certificate inspection and digital trust evaluation
    5. Passive website security header assessment
    6. Threat intelligence provider lookup
    7. Explainable risk classification
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    parsed_norm = _normalize_request_url(raw_url)

    normalized_url = parsed_norm["normalized_url"]
    hostname = parsed_norm["hostname"]
    base_domain = parsed_norm["base_domain"]

    # Check synthetic demo tag
    is_synthetic = is_synthetic_demo_host(hostname)

    # Step A: Heuristic findings
    url_findings_raw = analyze_url_heuristics(parsed_norm)

    # Step B: Domain Intel (DNS & WHOIS)
    dns_data = inspect_dns_records(hostname)
    whois_data = inspect_whois_data(base_domain)
    
    ip_addr = dns_data["a_records"][0] if dns_data["a_records"] else (
        dns_data["aaaa_records"][0] if dns_data["aaaa_records"] else None
    )

    # Step C: Redirect Analysis
    redirect_data = trace_redirects_safely(normalized_url)

    # Step D: TLS Certificate Inspection
    if parsed_norm["scheme"] == "https":
        tls_raw = inspect_tls_certificate(hostname, port=parsed_norm["port"] or 443)
    else:
        tls_raw = {
            "is_valid": False,
            "status_text": "Not inspected: target uses HTTP",
            "hostname_match": False,
            "connection_errors": [],
            "limitation_notes": "TLS is not available for an HTTP target.",
        }

    # Step E: Passive Security Assessment
    sec_raw = assess_website_security(normalized_url)

    # Step F: Threat Intelligence Feeds
    threat_intel_raw = query_threat_intelligence(normalized_url, hostname)

    # Step G: Risk Classification Engine
    overall_risk, score, confidence, summary, limitations = calculate_risk_classification(
        findings=url_findings_raw,
        threat_intel_matches=threat_intel_raw,
        tls_report=tls_raw,
        domain_info={**whois_data, **dns_data},
        redirect_info=redirect_data
    )

    # Save to Database
    inv = Investigation(
        target_url=raw_url,
        normalized_url=normalized_url,
        hostname=hostname,
        domain=base_domain,
        ip_address=ip_addr,
        overall_risk=overall_risk,
        risk_score=score,
        confidence=confidence,
        summary=summary,
        analysis_limitations=limitations,
        is_synthetic_demo=is_synthetic,
        status="COMPLETED"
    )
    db.add(inv)
    db.flush() # populate inv.id

    # Add Domain Info
    domain_obj = DomainInformation(
        investigation_id=inv.id,
        domain=base_domain,
        registrar=whois_data.get("registrar"),
        creation_date=whois_data.get("creation_date"),
        expiration_date=whois_data.get("expiration_date"),
        age_days=whois_data.get("age_days"),
        nameservers=dns_data.get("nameservers", []),
        a_records=dns_data.get("a_records", []),
        aaaa_records=dns_data.get("aaaa_records", []),
        mx_records=dns_data.get("mx_records", []),
        txt_records=dns_data.get("txt_records", []),
        suspicious_dns_flags=dns_data.get("suspicious_dns_flags", []),
        raw_details={"redirect_trace": redirect_data}
    )
    db.add(domain_obj)

    # Add URL Findings
    for f in url_findings_raw:
        db.add(URLFinding(
            investigation_id=inv.id,
            category=f.get("category", "HEURISTIC"),
            finding_title=f.get("finding_title", "Finding"),
            severity=f.get("severity", "INFO"),
            evidence=f.get("evidence", ""),
            impact=f.get("impact"),
            remediation=f.get("remediation")
        ))

    # Add TLS Report
    tls_obj = TLSReport(
        investigation_id=inv.id,
        is_valid=tls_raw.get("is_valid", False),
        status_text=tls_raw.get("status_text", "Unknown"),
        not_before=tls_raw.get("not_before"),
        not_after=tls_raw.get("not_after"),
        days_remaining=tls_raw.get("days_remaining"),
        subject=tls_raw.get("subject", {}),
        issuer=tls_raw.get("issuer", {}),
        san_list=tls_raw.get("san_list", []),
        signature_algorithm=tls_raw.get("signature_algorithm"),
        key_type=tls_raw.get("key_type"),
        key_size=tls_raw.get("key_size"),
        tls_version=tls_raw.get("tls_version"),
        hostname_match=tls_raw.get("hostname_match", False),
        connection_errors=tls_raw.get("connection_errors", []),
        chain_info=tls_raw.get("chain_info", []),
        limitation_notes=tls_raw.get("limitation_notes")
    )
    db.add(tls_obj)

    # Add Security Assessment
    sec_obj = SecurityAssessment(
        investigation_id=inv.id,
        https_available=sec_raw.get("https_available", False),
        http_status=sec_raw.get("http_status"),
        security_headers=sec_raw.get("security_headers", {}),
        cookies=sec_raw.get("cookies", []),
        robots_txt_status=sec_raw.get("robots_txt_status", "Not checked"),
        security_txt_status=sec_raw.get("security_txt_status", "Not checked"),
        passive_findings=sec_raw.get("passive_findings", []),
        limitations=sec_raw.get("limitations", [])
    )
    db.add(sec_obj)

    # Add Threat Intel Matches
    for ti in threat_intel_raw:
        db.add(ThreatIntelMatch(
            investigation_id=inv.id,
            source=ti.get("source", "Threat Feed"),
            is_available=ti.get("is_available", True),
            is_match=ti.get("is_match", False),
            verdict=ti.get("verdict", "UNKNOWN"),
            confidence=ti.get("confidence", "MEDIUM"),
            details=ti.get("details", {})
        ))

    db.commit()
    db.refresh(inv)
    return inv


@router.get("/investigations", response_model=List[InvestigationSummary])
def list_investigations(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    risk: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Investigation)
    if risk:
        query = query.filter(Investigation.overall_risk == risk)
    if search:
        query = query.filter(Investigation.target_url.contains(search) | Investigation.hostname.contains(search))
    
    return query.order_by(Investigation.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
def get_investigation_detail(investigation_id: str, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
    return inv


@router.get("/investigations/{investigation_id}/tls", response_model=TLSReportSchema)
def get_investigation_tls(investigation_id: str, db: Session = Depends(get_db)):
    tls = db.query(TLSReport).filter(TLSReport.investigation_id == investigation_id).first()
    if not tls:
        raise HTTPException(status_code=404, detail="TLS report for this investigation not found.")
    return tls


@router.get("/investigations/{investigation_id}/security", response_model=SecurityAssessmentSchema)
def get_investigation_security(investigation_id: str, db: Session = Depends(get_db)):
    sec = db.query(SecurityAssessment).filter(SecurityAssessment.investigation_id == investigation_id).first()
    if not sec:
        raise HTTPException(status_code=404, detail="Security assessment for this investigation not found.")
    return sec
