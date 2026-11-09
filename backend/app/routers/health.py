from fastapi import APIRouter
from datetime import datetime, timezone
from app.config import settings

router = APIRouter(tags=["Health"])

@router.get("/api/health")
def get_health():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "tagline": settings.TAGLINE,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "access_control_required": bool(settings.APP_ACCESS_TOKEN),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "modules": {
            "url_normalizer": "operational",
            "tls_inspector": "operational",
            "passive_security_assessor": "operational",
            "threat_intelligence_adapters": "operational",
            "scam_message_analyzer": "operational",
            "tamper_evident_registry": "operational",
            "threat_correlation_engine": "operational"
        }
    }


@router.get("/api/session")
def get_session():
    return {"authenticated": True}
