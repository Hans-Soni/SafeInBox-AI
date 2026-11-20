"""Pydantic schemas for 15-day security and threat audit digest."""

import re
from typing import List, Optional, Any
from pydantic import BaseModel, Field, field_validator

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class UrlClickItem(BaseModel):
    """Audited URL click item from within an email or webmail session."""
    url: str
    defanged: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "AUDITED"
    timestamp: Optional[Any] = None
    proceeded: bool = True
    email_subject: Optional[str] = None
    sender: Optional[str] = None
    source: Optional[str] = None


class EmailRecordItem(BaseModel):
    """Individual email security audit entry."""
    id: Optional[str] = None
    sender: str = Field(..., description="Sender display name or email address")
    receiver: str = Field(..., description="Receiver email address")
    subject: str = Field(..., description="Email subject line")
    timestamp: Optional[Any] = None
    date_iso: Optional[str] = None
    time_slab: Optional[str] = None
    composite_risk: float = Field(..., ge=0, le=100)
    risk_level: str = Field(..., description="SAFE, LOW, MEDIUM, HIGH, or CRITICAL")
    text_threat_score: Optional[float] = 0.0
    url_threat_score: Optional[float] = 0.0
    threat_vectors: List[str] = Field(default_factory=list)
    clicked_urls: List[UrlClickItem] = Field(default_factory=list)


class DigestSendRequest(BaseModel):
    """Payload to dispatch 15-day security record to specific user email."""
    user_email: str = Field(..., description="Target user email address")
    user_name: Optional[str] = "SafeInbox AI User"
    period_start: str = Field(..., description="Start of 15-day time-slab window")
    period_end: str = Field(..., description="End of 15-day time-slab window")
    records: List[EmailRecordItem] = Field(default_factory=list, description="All email threat reports in 15 days")
    url_clicks: List[UrlClickItem] = Field(default_factory=list, description="All webmail URL clicks in 15 days")

    @field_validator("user_email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        clean = value.strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        return clean


class DigestSendResponse(BaseModel):
    """Response returned upon digest dispatch."""
    success: bool
    message: str
    recipient: str
    period: str
    total_emails: int
    threats_detected: int
    total_clicks: int
    purged_records: int = 0
    dispatch_mode: str  # "apps_script", "smtp", or "simulated_preview"
    preview_html: Optional[str] = None


class DigestPurgeResponse(BaseModel):
    """Response returned upon 15-day history database purge."""
    success: bool
    message: str
    purged_audits: int
    purged_clicks: int
    purged_digests: int
    total_purged: int
    retention_days: int
    cutoff_iso: str


class DigestHistoryItem(BaseModel):
    """Historical digest log record."""
    id: int
    user_email: str
    period_start: str
    period_end: str
    total_emails: int
    threat_count: int
    click_count: int
    dispatch_status: str
    created_at: str
