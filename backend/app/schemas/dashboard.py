from typing import List, Dict, Any
from pydantic import BaseModel
from app.schemas.investigation import InvestigationSummary
from app.schemas.threat_report import ThreatReportResponse

class DashboardStatsResponse(BaseModel):
    total_investigations: int
    high_risk_investigations: int
    confirmed_malicious_reports: int
    suspicious_reports: int
    
    # Distribution charts data
    threat_distribution: List[Dict[str, Any]]
    risk_distribution: List[Dict[str, Any]]
    
    recent_investigations: List[InvestigationSummary]
    recent_reports: List[ThreatReportResponse]
    verified_registry_blocks: int
