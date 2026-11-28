"""SQLAlchemy ORM models for threat intelligence and feedback storage."""

from datetime import datetime, timezone
from sqlalchemy import (
    BigInteger,
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
    skeleton_hash = Column(String(64), index=True, nullable=True)  # Canonical invariant skeleton hash
    target_type = Column(String(16), nullable=False)  # "URL" or "TEXT"
    is_safe = Column(Boolean, nullable=False)
    source = Column(String(64), default="extension", nullable=False)
    target_sample = Column(Text, nullable=False)  # Bounded sanitized sample
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ScanAuditLog(Base):
    """Privacy-preserving audit log storing cryptographic hashes and risk metrics only."""

    __tablename__ = "scan_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), index=True, nullable=True)
    user_index_id = Column(String(64), index=True, nullable=True)
    scan_type = Column(String(16), nullable=False)  # "URL" or "EMAIL"
    content_hash = Column(String(64), index=True, nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(32), nullable=False)
    threat_vectors = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class UrlClickLog(Base):
    """Persistent audit log storing user click actions on hyperlinks in emails."""

    __tablename__ = "url_clicks"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), index=True, nullable=True)
    user_index_id = Column(String(64), index=True, nullable=True)
    url = Column(String(4096), nullable=False)
    defanged_url = Column(String(4096), nullable=False)
    url_hash = Column(String(64), index=True, nullable=False)
    email_subject = Column(String(255), nullable=True)
    sender = Column(String(255), nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String(32), nullable=False, default="AUDITED")
    proceeded = Column(Boolean, nullable=False, default=True)
    source = Column(String(64), nullable=False, default="email_body_link")
    is_encrypted = Column(Boolean, nullable=False, default=False)
    encrypted_payload = Column(Text, nullable=True)
    clicked_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class CommunityThreatSignal(Base):
    """
    Consolidated crowd-sourced threat intelligence table.
    Enables O(1) primary-key point lookups for community feedback consensus
    without scanning individual feedback rows. Zero-PII: stores NO user data.
    """

    __tablename__ = "community_threat_signals"

    id = Column(Integer, primary_key=True, index=True)
    target_hash = Column(String(64), unique=True, index=True, nullable=False)
    target_type = Column(String(16), index=True, nullable=False)  # "EMAIL" or "URL"
    threat_count = Column(Integer, default=0, nullable=False)
    safe_count = Column(Integer, default=0, nullable=False)
    last_reported_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class ThreatLshSignature(Base):
    """
    Tier 2: Locality-Sensitive Hashing (LSH) and MinHash signatures for fuzzy near-duplicate matching.
    Provides O(1) indexed candidate bucket retrieval in PostgreSQL/SQLite across 8 bands (b0..b7).
    Zero-PII: stores NO text, NO names, NO emails, only mathematical integer bucket hashes.
    """

    __tablename__ = "threat_lsh_signatures"

    id = Column(Integer, primary_key=True, index=True)
    target_hash = Column(String(64), index=True, nullable=False)
    target_type = Column(String(16), index=True, nullable=False)  # "EMAIL" or "URL"

    # 16 LSH Band Buckets (signed 64-bit BigInteger) indexed for O(1) union scan
    b0 = Column(BigInteger, index=True, nullable=False)
    b1 = Column(BigInteger, index=True, nullable=False)
    b2 = Column(BigInteger, index=True, nullable=False)
    b3 = Column(BigInteger, index=True, nullable=False)
    b4 = Column(BigInteger, index=True, nullable=False)
    b5 = Column(BigInteger, index=True, nullable=False)
    b6 = Column(BigInteger, index=True, nullable=False)
    b7 = Column(BigInteger, index=True, nullable=False)
    b8 = Column(BigInteger, index=True, nullable=False)
    b9 = Column(BigInteger, index=True, nullable=False)
    b10 = Column(BigInteger, index=True, nullable=False)
    b11 = Column(BigInteger, index=True, nullable=False)
    b12 = Column(BigInteger, index=True, nullable=False)
    b13 = Column(BigInteger, index=True, nullable=False)
    b14 = Column(BigInteger, index=True, nullable=False)
    b15 = Column(BigInteger, index=True, nullable=False)

    # Serialized MinHash signature (32 integers) for exact in-memory Jaccard verification
    minhash_sig = Column(String(512), nullable=False)

    threat_count = Column(Integer, default=1, nullable=False)
    safe_count = Column(Integer, default=0, nullable=False)
    last_reported_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


