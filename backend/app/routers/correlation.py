from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.correlation_service import build_threat_correlation_graph

router = APIRouter(prefix="/api", tags=["Threat Correlation"])

@router.get("/threat-relationships")
def get_threat_relationships(db: Session = Depends(get_db)):
    """
    Returns interconnected threat intelligence clusters across domains,
    shared IP infrastructure, nameservers, and brand typosquatting campaigns.
    """
    graph_data = build_threat_correlation_graph(db)
    return graph_data
