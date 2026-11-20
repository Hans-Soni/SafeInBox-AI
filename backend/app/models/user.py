"""SQLAlchemy ORM model for user accounts and authentication."""

from datetime import datetime, timezone
import hashlib
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String
)

from app.database import Base


def utcnow() -> datetime:
    """Return current UTC timestamp with timezone."""
    return datetime.now(timezone.utc)


def generate_user_index_id(email: str) -> str:
    """
    Generate a deterministic, unique, professional index ID for an email account.
    Format: SAFE-IDX-<12_HEX_DIGITS> (e.g. SAFE-IDX-4F9A7C12D83E)
    """
    clean = (email or "").strip().lower()
    digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()[:12].upper()
    return f"SAFE-IDX-{digest}"


class User(Base):
    """User account entity for extension and cloud intelligence authentication."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    index_id = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    password_changed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    password_history = Column(JSON, default=list, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class TermsConsent(Base):
    """Audit record capturing user consent to Terms & Conditions and Privacy Policy."""

    __tablename__ = "terms_consents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    user_index_id = Column(String(64), index=True, nullable=True)
    email = Column(String(255), index=True, nullable=False)
    ip_address = Column(String(64), nullable=False)
    mac_address = Column(String(128), nullable=True)
    terms_version = Column(String(32), nullable=False, default="1.0.0")
    user_agent = Column(String(512), nullable=True)
    agreed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class EmailOTPVerification(Base):
    """Temporary pending registration and email OTP verification record."""

    __tablename__ = "email_otp_verifications"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    otp_hash = Column(String(255), nullable=False)
    salt = Column(String(64), nullable=False)
    pending_data = Column(JSON, nullable=False)
    attempts_left = Column(Integer, default=3, nullable=False)
    resend_available_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

