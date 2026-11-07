import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    target_url = Column(Text, nullable=False, index=True)
    normalized_url = Column(Text, nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True) # IPv4 or IPv6
    
    # Overall risk classification
    # LOW RISK, SUSPICIOUS, HIGH RISK, CONFIRMED MALICIOUS, INCONCLUSIVE
    overall_risk = Column(String(50), nullable=False, default="INCONCLUSIVE", index=True)
    risk_score = Column(Integer, nullable=False, default=0) # 0 - 100
    confidence = Column(String(20), nullable=False, default="MEDIUM") # LOW, MEDIUM, HIGH
    summary = Column(Text, nullable=False)
    analysis_limitations = Column(JSON, nullable=True, default=list)
    
    is_synthetic_demo = Column(Boolean, default=False)
    status = Column(String(30), default="COMPLETED") # PROCESSING, COMPLETED, FAILED
    
    created_at = Column(DateTime, default=utc_now, index=True)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    domain_info = relationship("DomainInformation", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    findings = relationship("URLFinding", back_populates="investigation", cascade="all, delete-orphan")
    tls_report = relationship("TLSReport", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    security_assessment = relationship("SecurityAssessment", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    threat_intel_matches = relationship("ThreatIntelMatch", back_populates="investigation", cascade="all, delete-orphan")


class DomainInformation(Base):
    __tablename__ = "domain_information"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    domain = Column(String(255), nullable=False)
    registrar = Column(String(255), nullable=True)
    creation_date = Column(String(100), nullable=True)
    expiration_date = Column(String(100), nullable=True)
    age_days = Column(Integer, nullable=True)
    
    nameservers = Column(JSON, default=list)
    a_records = Column(JSON, default=list)
    aaaa_records = Column(JSON, default=list)
    mx_records = Column(JSON, default=list)
    txt_records = Column(JSON, default=list)
    suspicious_dns_flags = Column(JSON, default=list)
    raw_details = Column(JSON, default=dict)
    
    investigation = relationship("Investigation", back_populates="domain_info")


class URLFinding(Base):
    __tablename__ = "url_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    category = Column(String(50), nullable=False) # HEURISTIC, TYPOSQUAT, REDIRECT, DNS, CONTENT, HEADER
    finding_title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    evidence = Column(Text, nullable=False)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    
    investigation = relationship("Investigation", back_populates="findings")


class TLSReport(Base):
    __tablename__ = "tls_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    is_valid = Column(Boolean, default=False)
    status_text = Column(String(100), nullable=False) # Valid, Expired, Hostname Mismatch, Untrusted Issuer, etc.
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    days_remaining = Column(Integer, nullable=True)
    
    subject = Column(JSON, default=dict)
    issuer = Column(JSON, default=dict)
    san_list = Column(JSON, default=list)
    
    signature_algorithm = Column(String(100), nullable=True)
    key_type = Column(String(50), nullable=True)
    key_size = Column(Integer, nullable=True)
    tls_version = Column(String(50), nullable=True)
    hostname_match = Column(Boolean, default=False)
    
    connection_errors = Column(JSON, default=list)
    chain_info = Column(JSON, default=list)
    limitation_notes = Column(Text, nullable=True)
    
    investigation = relationship("Investigation", back_populates="tls_report")


class SecurityAssessment(Base):
    __tablename__ = "security_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    https_available = Column(Boolean, default=False)
    http_status = Column(Integer, nullable=True)
    
    # Headers evaluation
    security_headers = Column(JSON, default=dict) # csp, hsts, x_content_type, x_frame, referrer, permissions
    cookies = Column(JSON, default=list)
    robots_txt_status = Column(String(50), default="Not checked")
    security_txt_status = Column(String(50), default="Not checked")
    passive_findings = Column(JSON, default=list)
    limitations = Column(JSON, default=list)
    
    investigation = relationship("Investigation", back_populates="security_assessment")


class ThreatIntelMatch(Base):
    __tablename__ = "threat_intelligence_matches"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    source = Column(String(50), nullable=False) # URLhaus, PhishTank, OpenPhish, VirusTotal, TrustLens Heuristics
    is_available = Column(Boolean, default=True)
    is_match = Column(Boolean, default=False)
    verdict = Column(String(50), nullable=False) # MALICIOUS, CLEAN, UNKNOWN, UNAVAILABLE
    confidence = Column(String(20), default="MEDIUM")
    details = Column(JSON, default=dict)
    checked_at = Column(DateTime, default=utc_now)
    
    investigation = relationship("Investigation", back_populates="threat_intel_matches")
