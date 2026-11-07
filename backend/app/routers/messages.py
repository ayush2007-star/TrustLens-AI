from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.threat_report import ScamMessageAnalysis
from app.schemas.message import MessageAnalysisRequest, MessageAnalysisResponse
from app.services.message_analyzer import analyze_scam_message

router = APIRouter(prefix="/api", tags=["Scam Message Analysis"])

@router.post("/analyze-message", response_model=MessageAnalysisResponse)
def analyze_message_endpoint(payload: MessageAnalysisRequest, db: Session = Depends(get_db)):
    """
    Analyzes an incoming communication (SMS, email, WhatsApp, recruitment, payment demand)
    for psychological manipulation, urgency, credential harvesting, and social engineering patterns.
    """
    raw_text = payload.message_text.strip()
    if len(raw_text) < 5:
        raise HTTPException(status_code=400, detail="Message content too brief for threat analysis.")

    # Run analysis
    analysis_dict = analyze_scam_message(raw_text)

    # Persist record
    db_record = ScamMessageAnalysis(
        input_preview=raw_text[:100] + ("..." if len(raw_text) > 100 else ""),
        analyzed_via=analysis_dict["analyzed_via"],
        risk_level=analysis_dict["risk_level"],
        risk_score=analysis_dict["risk_score"],
        confidence=analysis_dict["confidence"],
        urgency_detected=any(i["category"] == "URGENCY" for i in analysis_dict["indicators"]),
        credential_request=any(i["category"] == "CREDENTIAL_HARVESTING" for i in analysis_dict["indicators"]),
        payment_request=any(i["category"] == "SUSPICIOUS_PAYMENT" for i in analysis_dict["indicators"]),
        impersonation_target=(
            next((i["evidence_snippet"] for i in analysis_dict["indicators"] if i["category"] == "IMPERSONATION"), None)
        ),
        indicators=analysis_dict["indicators"],
        explanation=analysis_dict["explanation"],
        recommended_precautions=analysis_dict["recommended_precautions"],
        limitations=analysis_dict["limitations"]
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    return {
        "id": db_record.id,
        "risk_level": analysis_dict["risk_level"],
        "risk_score": analysis_dict["risk_score"],
        "confidence": analysis_dict["confidence"],
        "analyzed_via": analysis_dict["analyzed_via"],
        "summary": analysis_dict["summary"],
        "indicators": analysis_dict["indicators"],
        "explanation": analysis_dict["explanation"],
        "recommended_precautions": analysis_dict["recommended_precautions"],
        "limitations": analysis_dict["limitations"],
        "created_at": db_record.created_at
    }
