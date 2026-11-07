import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime
from app.database import Base

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class ThreatRegistryEntry(Base):
    __tablename__ = "threat_registry"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    block_index = Column(Integer, unique=True, nullable=False, index=True)
    report_id = Column(String(36), nullable=False, index=True)
    
    # Cryptographic fields
    data_hash = Column(String(64), nullable=False) # SHA-256 of canonical report payload
    previous_hash = Column(String(64), nullable=False) # Chained hash of block (index - 1)
    chained_hash = Column(String(64), unique=True, nullable=False, index=True) # Current chained block hash
    
    canonical_payload = Column(Text, nullable=False) # Normalized JSON string without sensitive fields
    registered_at = Column(DateTime, default=utc_now, nullable=False)
    
    # Metadata
    reporter_alias = Column(String(100), default="Anonymous")
    target_domain = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)
