"""Database model for 15-day security digest dispatch logs."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text
)

from app.database import Base


def utcnow() -> datetime:
    """Return current UTC timestamp with timezone."""
    return datetime.now(timezone.utc)


class SecurityDigestLog(Base):
    """Audit log of 15-day security records dispatched to users."""

    __tablename__ = "security_digest_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), index=True, nullable=False)
    user_index_id = Column(String(64), index=True, nullable=True)
    period_start = Column(String(64), nullable=False)
    period_end = Column(String(64), nullable=False)
    total_emails = Column(Integer, default=0, nullable=False)
    threat_count = Column(Integer, default=0, nullable=False)
    click_count = Column(Integer, default=0, nullable=False)
    dispatch_status = Column(String(32), default="sent", nullable=False)  # "sent", "simulated", "failed"
    delivery_note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

