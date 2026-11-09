from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.registry import ThreatRegistryEntry
from app.schemas.registry import (
    RegisterReportRequest,
    RegistryEntryResponse,
    RegistryVerificationResponse
)
from app.services.registry_service import (
    register_threat_report_on_chain,
    verify_report_integrity
)

router = APIRouter(prefix="/api/registry", tags=["Digital Trust Registry"])

@router.get("", response_model=List[RegistryEntryResponse])
def get_registry_ledger(db: Session = Depends(get_db)):
    """
    Returns the current local, tamper-evident cryptographic hash ledger.
    Every entry contains its canonical data hash, previous block hash, and chained block hash.
    """
    entries = db.query(ThreatRegistryEntry).order_by(ThreatRegistryEntry.block_index.asc()).all()
    return entries


@router.post("/register", response_model=RegistryEntryResponse)
def register_threat_report(payload: RegisterReportRequest, db: Session = Depends(get_db)):
    """
    Registers a threat report in the local cryptographic hash chain.
    Computes deterministic SHA-256 fingerprint and cryptographically chains it to previous block.
    """
    try:
        entry = register_threat_report_on_chain(db, payload.report_id)
        return entry
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/verify/{report_id}", response_model=RegistryVerificationResponse)
def verify_registry_fingerprint(report_id: str, db: Session = Depends(get_db)):
    """
    Performs real-time cryptographic verification of a threat report.
    Re-hashes the canonical report and validates the stored local hash chain.
    Detects inconsistent report data or links in the stored hash chain.
    """
    result = verify_report_integrity(db, report_id)
    return result
