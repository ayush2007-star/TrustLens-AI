from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class InvestigationRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain to investigate", min_length=3, max_length=2048)

class URLFindingSchema(BaseModel):
    category: str
    finding_title: str
    severity: str
    evidence: str
    impact: Optional[str] = None
    remediation: Optional[str] = None

class DomainInfoSchema(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    age_days: Optional[int] = None
    nameservers: List[str] = []
    a_records: List[str] = []
    aaaa_records: List[str] = []
    mx_records: List[str] = []
    txt_records: List[str] = []
    suspicious_dns_flags: List[str] = []
    raw_details: Dict[str, Any] = {}

class TLSReportSchema(BaseModel):
    is_valid: bool
    status_text: str
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    subject: Dict[str, Any] = {}
    issuer: Dict[str, Any] = {}
    san_list: List[str] = []
    signature_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    tls_version: Optional[str] = None
    hostname_match: bool
    connection_errors: List[str] = []
    chain_info: List[Dict[str, Any]] = []
    limitation_notes: Optional[str] = None

class SecurityAssessmentSchema(BaseModel):
    https_available: bool
    http_status: Optional[int] = None
    security_headers: Dict[str, Any] = {}
    cookies: List[Dict[str, Any]] = []
    robots_txt_status: str
    security_txt_status: str
    passive_findings: List[Dict[str, Any]] = []
    limitations: List[str] = []

class ThreatIntelMatchSchema(BaseModel):
    source: str
    is_available: bool
    is_match: bool
    verdict: str
    confidence: str
    details: Dict[str, Any] = {}
    checked_at: Optional[datetime] = None

class InvestigationResponse(BaseModel):
    id: str
    target_url: str
    normalized_url: str
    hostname: str
    domain: str
    ip_address: Optional[str] = None
    overall_risk: str
    risk_score: int
    confidence: str
    summary: str
    analysis_limitations: List[str] = []
    is_synthetic_demo: bool = False
    status: str
    created_at: datetime
    
    domain_info: Optional[DomainInfoSchema] = None
    findings: List[URLFindingSchema] = []
    tls_report: Optional[TLSReportSchema] = None
    security_assessment: Optional[SecurityAssessmentSchema] = None
    threat_intel_matches: List[ThreatIntelMatchSchema] = []

    model_config = ConfigDict(from_attributes=True)

class InvestigationSummary(BaseModel):
    id: str
    target_url: str
    hostname: str
    domain: str
    overall_risk: str
    risk_score: int
    confidence: str
    summary: str
    is_synthetic_demo: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
