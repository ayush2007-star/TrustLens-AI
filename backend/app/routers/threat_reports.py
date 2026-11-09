import hashlib
import hmac
import ipaddress
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models.threat_report import CommunityAbuseEvent, ThreatReport, ThreatReportVote
from app.schemas.threat_report import ThreatReportCreate, ThreatReportResponse

router = APIRouter(prefix="/api/threat-reports", tags=["Threat Reports"])


def _record_community_write(request: Request, db: Session, action: str) -> str:
    if not settings.COMMUNITY_WRITES_ENABLED or len(settings.COMMUNITY_ABUSE_KEY) < 32:
        raise HTTPException(
            status_code=503,
            detail="Community writes are disabled until deployment abuse controls are configured.",
        )

    client_host = request.client.host if request.client else ""
    try:
        client_address = ipaddress.ip_address(client_host)
    except ValueError:
        raise HTTPException(
            status_code=503,
            detail="Community writes require a trusted client IP address.",
        ) from None
    if isinstance(client_address, ipaddress.IPv6Address) and client_address.ipv4_mapped:
        client_address = client_address.ipv4_mapped

    client_key = hmac.new(
        settings.COMMUNITY_ABUSE_KEY.encode(),
        client_address.packed,
        hashlib.sha256,
    ).hexdigest()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(hours=1)
    limit = 5 if action == "report" else 20
    db.query(CommunityAbuseEvent).filter(
        CommunityAbuseEvent.created_at < cutoff
    ).delete(synchronize_session=False)
    recent_writes = (
        db.query(CommunityAbuseEvent)
        .filter(
            CommunityAbuseEvent.client_key == client_key,
            CommunityAbuseEvent.action == action,
            CommunityAbuseEvent.created_at >= cutoff,
        )
        .count()
    )
    if recent_writes >= limit:
        raise HTTPException(status_code=429, detail="Community write rate limit exceeded.")

    db.add(CommunityAbuseEvent(client_key=client_key, action=action, created_at=now))
    db.commit()
    return client_key


@router.post("", response_model=ThreatReportResponse)
def create_threat_report(
    payload: ThreatReportCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Submits a new collaborative threat intelligence report.
    Reports begin in 'Pending' status and require community or researcher corroboration.
    """
    _record_community_write(request, db, "report")
    raw_url = payload.target_url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    parsed = urllib.parse.urlsplit(raw_url if "://" in raw_url else f"https://{raw_url}")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(
            status_code=400,
            detail="User credentials are not allowed in submitted URLs. Remove the username or password before reporting this target.",
        )

    # Extract domain
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
def upvote_threat_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report record not found.")

    client_key = _record_community_write(request, db, "upvote")
    db.add(ThreatReportVote(report_id=report.id, client_key=client_key))
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="This IP address has already upvoted this report.",
        ) from None

    db.query(ThreatReport).filter(ThreatReport.id == report.id).update(
        {ThreatReport.upvotes: ThreatReport.upvotes + 1},
        synchronize_session=False,
    )
    db.refresh(report)
    if report.upvotes >= 3 and report.verification_status == "Pending":
        report.verification_status = "Under Review"
    db.commit()
    return {"id": report.id, "upvotes": report.upvotes, "status": report.verification_status}
