"""SQLAlchemy ORM models for threat intelligence and feedback storage."""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text
)

from app.database import Base


def utcnow() -> datetime:
    """Return current UTC timestamp with timezone."""
    return datetime.now(timezone.utc)


class ThreatURL(Base):
    """Cached URL threat intelligence record."""

    __tablename__ = "threat_urls"

    id = Column(Integer, primary_key=True, index=True)
    url_hash = Column(String(64), unique=True, index=True, nullable=False)
    canonical_url = Column(String(4096), nullable=False)
    hostname = Column(String(255), index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(32), nullable=False)
    attack_types = Column(JSON, default=list, nullable=False)
    findings = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class FeedbackRecord(Base):
    """User-submitted Safe / Threat labels for future ML model training."""

    __tablename__ = "feedback_records"

    id = Column(Integer, primary_key=True, index=True)
    target_hash = Column(String(64), index=True, nullable=False)
    target_type = Column(String(16), nullable=False)  # "URL" or "TEXT"
    is_safe = Column(Boolean, nullable=False)
    source = Column(String(64), default="extension", nullable=False)
    target_sample = Column(Text, nullable=False)  # Bounded sanitized sample
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ScanAuditLog(Base):
    """Privacy-preserving audit log storing cryptographic hashes and risk metrics only."""

    __tablename__ = "scan_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(16), nullable=False)  # "URL" or "EMAIL"
    content_hash = Column(String(64), index=True, nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(32), nullable=False)
    threat_vectors = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

