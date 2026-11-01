"""SQLAlchemy ORM model for user accounts and authentication."""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String
)

from app.database import Base


def utcnow() -> datetime:
    """Return current UTC timestamp with timezone."""
    return datetime.now(timezone.utc)


class User(Base):
    """User account entity for extension and cloud intelligence authentication."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class TermsConsent(Base):
    """Audit record capturing user consent to Terms & Conditions and Privacy Policy."""

    __tablename__ = "terms_consents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    email = Column(String(255), index=True, nullable=False)
    ip_address = Column(String(64), nullable=False)
    mac_address = Column(String(128), nullable=True)
    terms_version = Column(String(32), nullable=False, default="1.0.0")
    user_agent = Column(String(512), nullable=True)
    agreed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

