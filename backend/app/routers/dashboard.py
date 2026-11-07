from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.investigation import Investigation, URLFinding
from app.models.threat_report import ThreatReport
from app.models.registry import ThreatRegistryEntry
from app.schemas.dashboard import DashboardStatsResponse
from app.schemas.investigation import InvestigationSummary
from app.schemas.threat_report import ThreatReportResponse

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_statistics(db: Session = Depends(get_db)):
    """
    Returns actual aggregated security intelligence metrics computed strictly
    from database records. Never fabricates numbers or synthetic placeholders.
    """
    total_inv = db.query(func.count(Investigation.id)).scalar() or 0
    high_risk_inv = db.query(func.count(Investigation.id)).filter(Investigation.overall_risk == "HIGH RISK").scalar() or 0
    confirmed_malicious = (
        db.query(func.count(Investigation.id)).filter(Investigation.overall_risk == "CONFIRMED MALICIOUS").scalar() or 0
    ) + (
        db.query(func.count(ThreatReport.id)).filter(ThreatReport.verification_status == "Supported by Evidence").scalar() or 0
    )
    
    suspicious_count = (
        db.query(func.count(Investigation.id)).filter(Investigation.overall_risk == "SUSPICIOUS").scalar() or 0
    ) + (
        db.query(func.count(ThreatReport.id)).filter(ThreatReport.verification_status.in_(["Pending", "Under Review"])).scalar() or 0
    )

    verified_blocks = db.query(func.count(ThreatRegistryEntry.id)).scalar() or 0

    # Risk Distribution
    risk_counts = db.query(
        Investigation.overall_risk,
        func.count(Investigation.id)
    ).group_by(Investigation.overall_risk).all()
    
    risk_distribution = [
        {"name": str(r[0]), "value": int(r[1])} for r in risk_counts
    ] if risk_counts else [
        {"name": "LOW RISK", "value": 0},
        {"name": "SUSPICIOUS", "value": 0},
        {"name": "HIGH RISK", "value": 0},
        {"name": "CONFIRMED MALICIOUS", "value": 0},
        {"name": "INCONCLUSIVE", "value": 0}
    ]

    # Threat Categories Distribution
    finding_categories = db.query(
        URLFinding.category,
        func.count(URLFinding.id)
    ).group_by(URLFinding.category).all()

    report_types = db.query(
        ThreatReport.report_type,
        func.count(ThreatReport.id)
    ).group_by(ThreatReport.report_type).all()

    threat_dict = {}
    for cat, cnt in finding_categories:
        threat_dict[str(cat)] = threat_dict.get(str(cat), 0) + int(cnt)
    for rtype, cnt in report_types:
        threat_dict[str(rtype)] = threat_dict.get(str(rtype), 0) + int(cnt)

    threat_distribution = [
        {"category": k, "count": v} for k, v in threat_dict.items()
    ] if threat_dict else [
        {"category": "Phishing / Brand Spoof", "count": 0},
        {"category": "Typosquatting", "count": 0},
        {"category": "Deceptive URL / IP", "count": 0},
        {"category": "TLS Anomaly", "count": 0}
    ]

    # Recent items
    recent_invs = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(6).all()
    recent_reps = db.query(ThreatReport).order_by(ThreatReport.created_at.desc()).limit(6).all()

    return {
        "total_investigations": total_inv,
        "high_risk_investigations": high_risk_inv,
        "confirmed_malicious_reports": confirmed_malicious,
        "suspicious_reports": suspicious_count,
        "threat_distribution": threat_distribution,
        "risk_distribution": risk_distribution,
        "recent_investigations": recent_invs,
        "recent_reports": recent_reps,
        "verified_registry_blocks": verified_blocks
    }
