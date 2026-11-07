from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class RegisterReportRequest(BaseModel):
    report_id: str = Field(..., description="ID of the threat report to register")

class RegistryEntryResponse(BaseModel):
    id: str
    block_index: int
    report_id: str
    data_hash: str
    previous_hash: str
    chained_hash: str
    canonical_payload: str
    registered_at: datetime
    reporter_alias: str
    target_domain: str
    report_type: str

    model_config = ConfigDict(from_attributes=True)

class RegistryVerificationResponse(BaseModel):
    report_id: str
    is_registered: bool
    is_tampered: bool
    status: str # VERIFIED_AUTHENTIC, TAMPER_DETECTED, NOT_REGISTERED
    block_index: Optional[int] = None
    stored_data_hash: Optional[str] = None
    computed_data_hash: Optional[str] = None
    stored_chained_hash: Optional[str] = None
    computed_chained_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    registered_at: Optional[datetime] = None
    details: str
