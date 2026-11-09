from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class ThreatReportCreate(BaseModel):
    target_url: str = Field(..., min_length=3, max_length=2048)
    report_type: str = Field(..., description="PHISHING, IMPERSONATION, MALWARE, SCAM_MESSAGE, FAKE_PORTAL, OTHER")
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    description: str = Field(..., min_length=10, max_length=5000)
    evidence_reference: Optional[str] = Field(None, max_length=2000)
    reporter_alias: Optional[str] = Field("Anonymous Researcher", max_length=100)
    tags: List[str] = Field(default_factory=list)

class ThreatReportResponse(BaseModel):
    id: str
    target_url: str
    domain: str
    report_type: str
    severity: str
    description: str
    evidence_reference: Optional[str] = None
    reporter_alias: str
    verification_status: str
    upvotes: int
    fingerprint: Optional[str] = None
    registered_in_registry: bool
    registry_index: Optional[int] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ThreatRelationshipSchema(BaseModel):
    id: str
    source_type: str
    source_value: str
    target_type: str
    target_value: str
    relation_type: str
    evidence: str
    confidence: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
