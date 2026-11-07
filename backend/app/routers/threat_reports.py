import urllib.parse
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.threat_report import ThreatReport
from app.schemas.threat_report import ThreatReportCreate, ThreatReportResponse

router = APIRouter(prefix="/api/threat-reports", tags=["Threat Reports"])

@router.post("", response_model=ThreatReportResponse)
def create_threat_report(payload: ThreatReportCreate, db: Session = Depends(get_db)):
    """
    Submits a new collaborative threat intelligence report.
    Reports begin in 'Pending' status and require community or researcher corroboration.
    """
    raw_url = payload.target_url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    # Extract domain
    parsed = urllib.parse.urlsplit(raw_url if "://" in raw_url else f"https://{raw_url}")
    domain = parsed.hostname or raw_url.split('/')[0]

    report = ThreatReport(
        target_url=raw_url,
        domain=domain.lower(),
        report_type=payload.report_type.upper(),
        severity=payload.severity.upper(),
        description=payload.description.strip(),
        evidence_reference=payload.evidence_reference,
        reporter_alias=payload.reporter_alias or "Anonymous Researcher",
        verification_status="Pending",
        upvotes=0,
        registered_in_registry=False,
        tags=payload.tags
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("", response_model=List[ThreatReportResponse])
def list_threat_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = None,
    report_type: Optional[str] = None,
    domain: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ThreatReport)
    if status:
        query = query.filter(ThreatReport.verification_status == status)
    if report_type:
        query = query.filter(ThreatReport.report_type == report_type)
    if domain:
        query = query.filter(ThreatReport.domain.contains(domain.lower()))
    
    return query.order_by(ThreatReport.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/{report_id}", response_model=ThreatReportResponse)
def get_threat_report_detail(report_id: str, db: Session = Depends(get_db)):
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report record not found.")
    return report


@router.post("/{report_id}/upvote")
def upvote_threat_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report record not found.")
    
    report.upvotes += 1
    # If report gets 3 or more upvotes and has evidence, transition status
    if report.upvotes >= 3 and report.verification_status == "Pending":
        report.verification_status = "Under Review"
    db.commit()
    return {"id": report.id, "upvotes": report.upvotes, "status": report.verification_status}
