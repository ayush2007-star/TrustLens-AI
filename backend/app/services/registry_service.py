import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from app.models.registry import ThreatRegistryEntry
from app.models.threat_report import ThreatReport

GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def format_utc_iso(dt: Optional[datetime]) -> str:
    """Standardizes datetime to UTC RFC3339/ISO-8601 representation (second precision)."""
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def create_canonical_payload(report: ThreatReport) -> str:
    """
    Creates a deterministic, canonical JSON representation of the threat report
    excluding volatile database fields and ensuring no sensitive information is leaked.
    """
    payload = {
        "report_id": str(report.id),
        "target_url": str(report.target_url),
        "domain": str(report.domain),
        "report_type": str(report.report_type),
        "severity": str(report.severity),
        "description": str(report.description),
        "reporter_alias": str(report.reporter_alias or "Anonymous"),
        "created_at": format_utc_iso(report.created_at)
    }
    # Deterministic JSON with sorted keys and no whitespace variation
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))


def compute_sha256(content: str) -> str:
    """Computes SHA-256 hex digest of a string."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def _registry_chain_is_valid(db: Session) -> bool:
    entries = db.query(ThreatRegistryEntry).order_by(ThreatRegistryEntry.block_index.asc()).all()
    expected_previous_hash = GENESIS_PREV_HASH
    for expected_index, block in enumerate(entries):
        if block.block_index != expected_index:
            return False

        report = db.query(ThreatReport).filter(ThreatReport.id == block.report_id).first()
        if not report:
            return False

        canonical_payload = create_canonical_payload(report)
        if compute_sha256(canonical_payload) != block.data_hash:
            return False
        if canonical_payload != block.canonical_payload:
            return False

        chain_material = (
            f"{block.block_index}:{block.previous_hash}:{block.data_hash}:"
            f"{format_utc_iso(block.registered_at)}"
        )
        if block.previous_hash != expected_previous_hash:
            return False
        if compute_sha256(chain_material) != block.chained_hash:
            return False

        expected_previous_hash = block.chained_hash
    return True


def count_verified_registry_blocks(db: Session) -> int:
    entries = db.query(ThreatRegistryEntry).count()
    return entries if entries and _registry_chain_is_valid(db) else 0


def register_threat_report_on_chain(db: Session, report_id: str) -> ThreatRegistryEntry:
    """
    Registers a threat report in the local tamper-evident hash chain.
    The registry detects record changes but is not protected from full database rewrites.
    """
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).first()
    if not report:
        raise ValueError(f"Threat report with ID '{report_id}' does not exist.")

    # Check if already registered
    existing_entry = db.query(ThreatRegistryEntry).filter(ThreatRegistryEntry.report_id == report_id).first()
    if existing_entry:
        return existing_entry

    if not _registry_chain_is_valid(db):
        raise ValueError("Existing threat registry chain is invalid or has been tampered with. Registry append blocked.")

    # Get latest block to chain against
    latest_block = db.query(ThreatRegistryEntry).order_by(ThreatRegistryEntry.block_index.desc()).first()
    
    if latest_block:
        block_index = latest_block.block_index + 1
        previous_hash = latest_block.chained_hash
    else:
        block_index = 0
        previous_hash = GENESIS_PREV_HASH

    canonical_payload = create_canonical_payload(report)
    data_hash = compute_sha256(canonical_payload)
    
    now_utc = datetime.now(timezone.utc)
    timestamp_str = format_utc_iso(now_utc)
    
    # Chained hash links block index, previous block hash, data payload hash, and timestamp
    chain_material = f"{block_index}:{previous_hash}:{data_hash}:{timestamp_str}"
    chained_hash = compute_sha256(chain_material)

    entry = ThreatRegistryEntry(
        block_index=block_index,
        report_id=report.id,
        data_hash=data_hash,
        previous_hash=previous_hash,
        chained_hash=chained_hash,
        canonical_payload=canonical_payload,
        registered_at=now_utc,
        reporter_alias=report.reporter_alias,
        target_domain=report.domain,
        report_type=report.report_type
    )

    db.add(entry)
    
    # Update report record
    report.fingerprint = chained_hash
    report.registered_in_registry = True
    report.registry_index = block_index
    
    db.commit()
    db.refresh(entry)
    return entry


def verify_report_integrity(db: Session, report_id: str) -> Dict[str, Any]:
    """
    Verifies cryptographic integrity of a registered threat report.
    Checks whether the canonical payload matches the stored data_hash
    and whether the chained hash formula holds.
    """
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).first()
    if not report:
        return {
            "report_id": report_id,
            "is_registered": False,
            "is_tampered": False,
            "status": "NOT_FOUND",
            "details": f"No threat report found with ID '{report_id}'."
        }

    entry = db.query(ThreatRegistryEntry).filter(ThreatRegistryEntry.report_id == report_id).first()
    if not entry:
        return {
            "report_id": report_id,
            "is_registered": False,
            "is_tampered": False,
            "status": "NOT_REGISTERED",
            "details": "This threat report has not yet been committed to the cryptographic trust registry."
        }

    # 1. Recompute data hash from current report state in DB
    current_canonical = create_canonical_payload(report)
    computed_data_hash = compute_sha256(current_canonical)

    # 2. Check if canonical payload stored in registry matches current report payload
    is_data_tampered = (
        computed_data_hash != entry.data_hash
        or current_canonical != entry.canonical_payload
    )

    # 3. Recompute chained hash from block details
    timestamp_str = format_utc_iso(entry.registered_at)
    chain_material = f"{entry.block_index}:{entry.previous_hash}:{entry.data_hash}:{timestamp_str}"
    computed_chained_hash = compute_sha256(chain_material)
    is_chain_broken = (
        computed_chained_hash != entry.chained_hash
        or not _registry_chain_is_valid(db)
    )

    is_tampered = is_data_tampered or is_chain_broken

    if is_tampered:
        status = "TAMPER_DETECTED"
        details = (
            "CRYPTOGRAPHIC INTEGRITY VIOLATION DETECTED! "
            f"The report content has been altered since registration or the stored hash chain is broken. "
            f"Stored Hash: {entry.data_hash[:16]}..., Computed Hash: {computed_data_hash[:16]}..."
        )
    else:
        status = "VERIFIED_AUTHENTIC"
        details = (
            f"Cryptographic fingerprint verified. Report content precisely matches "
            f"stored registry entry #{entry.block_index}. The verified hash chain is intact."
        )

    return {
        "report_id": report_id,
        "is_registered": True,
        "is_tampered": is_tampered,
        "status": status,
        "block_index": entry.block_index,
        "stored_data_hash": entry.data_hash,
        "computed_data_hash": computed_data_hash,
        "stored_chained_hash": entry.chained_hash,
        "computed_chained_hash": computed_chained_hash,
        "previous_hash": entry.previous_hash,
        "registered_at": entry.registered_at,
        "details": details
    }
