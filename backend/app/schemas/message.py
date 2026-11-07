from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class MessageAnalysisRequest(BaseModel):
    message_text: str = Field(..., description="Message text (SMS, email, WhatsApp, etc.) to analyze", min_length=5, max_length=10000)

class DetectedIndicator(BaseModel):
    category: str # URGENCY, CREDENTIAL_HARVESTING, SUSPICIOUS_PAYMENT, IMPERSONATION, MALICIOUS_LINK, REMOTE_ACCESS, FAKE_REWARD
    title: str
    severity: str # LOW, MEDIUM, HIGH, CRITICAL
    evidence_snippet: str
    reasoning: str

class MessageAnalysisResponse(BaseModel):
    id: str
    risk_level: str # LOW RISK, SUSPICIOUS, HIGH RISK, CONFIRMED MALICIOUS
    risk_score: int # 0-100
    confidence: str # LOW, MEDIUM, HIGH
    analyzed_via: str # deterministic, gemini, openai
    summary: str
    indicators: List[DetectedIndicator] = []
    explanation: str
    recommended_precautions: List[str] = []
    limitations: List[str] = []
    created_at: datetime
