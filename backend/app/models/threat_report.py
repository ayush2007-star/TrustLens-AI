import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime, JSON
from app.database import Base

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    target_url = Column(Text, nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    report_type = Column(String(50), nullable=False) # PHISHING, IMPERSONATION, MALWARE, SCAM_MESSAGE, FAKE_PORTAL, OTHER
    severity = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    evidence_reference = Column(Text, nullable=True) # Hashes, screenshots ref, DNS details, etc.
    reporter_alias = Column(String(100), default="Anonymous Researcher")
    
    # Verification status: Pending, Under Review, Supported by Evidence, Disputed, Rejected
    verification_status = Column(String(50), default="Pending", index=True)
    upvotes = Column(Integer, default=0)
    
    # Hash of this report when registered
    fingerprint = Column(String(64), nullable=True, index=True)
    registered_in_registry = Column(Boolean, default=False)
    registry_index = Column(Integer, nullable=True)
    
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=utc_now, index=True)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class ThreatRelationship(Base):
    __tablename__ = "threat_relationships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_type = Column(String(50), nullable=False) # DOMAIN, IP, NAMESERVER, REDIRECT, BRAND
    source_value = Column(String(255), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)
    target_value = Column(String(255), nullable=False, index=True)
    relation_type = Column(String(50), nullable=False) # SHARED_IP, SHARED_NS, TYPOSQUAT_TARGET, REDIRECT_TARGET, SAME_CAMPAIGN
    evidence = Column(Text, nullable=False)
    confidence = Column(String(20), default="MEDIUM")
    created_at = Column(DateTime, default=utc_now)


class ScamMessageAnalysis(Base):
    __tablename__ = "scam_message_analyses"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    input_preview = Column(String(255), nullable=False)
    analyzed_via = Column(String(50), default="deterministic") # deterministic, gemini, openai
    risk_level = Column(String(20), nullable=False) # LOW RISK, SUSPICIOUS, HIGH RISK, CONFIRMED MALICIOUS
    risk_score = Column(Integer, default=0) # 0-100
    confidence = Column(String(20), default="HIGH")
    
    urgency_detected = Column(Boolean, default=False)
    credential_request = Column(Boolean, default=False)
    payment_request = Column(Boolean, default=False)
    impersonation_target = Column(String(100), nullable=True)
    
    indicators = Column(JSON, default=list) # List of detected indicators with quote & rationale
    explanation = Column(Text, nullable=False)
    recommended_precautions = Column(JSON, default=list)
    limitations = Column(JSON, default=list)
    
    created_at = Column(DateTime, default=utc_now, index=True)
