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
    nameservers: List[str] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    aaaa_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    suspicious_dns_flags: List[str] = Field(default_factory=list)
    raw_details: Dict[str, Any] = Field(default_factory=dict)

class TLSReportSchema(BaseModel):
    is_valid: bool
    status_text: str
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    subject: Dict[str, Any] = Field(default_factory=dict)
    issuer: Dict[str, Any] = Field(default_factory=dict)
    san_list: List[str] = Field(default_factory=list)
    signature_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    tls_version: Optional[str] = None
    hostname_match: bool
    connection_errors: List[str] = Field(default_factory=list)
    chain_info: List[Dict[str, Any]] = Field(default_factory=list)
    limitation_notes: Optional[str] = None

class SecurityAssessmentSchema(BaseModel):
    https_available: bool
    http_status: Optional[int] = None
    security_headers: Dict[str, Any] = Field(default_factory=dict)
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    robots_txt_status: str
    security_txt_status: str
    passive_findings: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

class ThreatIntelMatchSchema(BaseModel):
    source: str
    is_available: bool
    is_match: bool
    verdict: str
    confidence: str
    details: Dict[str, Any] = Field(default_factory=dict)
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
    analysis_limitations: List[str] = Field(default_factory=list)
    is_synthetic_demo: bool = False
    status: str
    created_at: datetime
    
    domain_info: Optional[DomainInfoSchema] = None
    findings: List[URLFindingSchema] = Field(default_factory=list)
    tls_report: Optional[TLSReportSchema] = None
    security_assessment: Optional[SecurityAssessmentSchema] = None
    threat_intel_matches: List[ThreatIntelMatchSchema] = Field(default_factory=list)

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
