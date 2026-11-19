"""Pydantic schemas for URL threat scanning and click tracking."""

from typing import Any
from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    """URL threat scan request payload."""
    url: str = Field(..., min_length=1, max_length=4096, description="URL to analyze")


class URLScanResponse(BaseModel):
    """Detailed URL scan analysis response matching extension threat engine contract."""
    inputUrl: str
    canonicalUrl: str
    hostname: str
    unicodeHostname: str
    matchedBrand: str | None = None
    riskScore: float
    riskLevel: str
    attackTypes: list[str]
    findings: list[dict[str, Any]]
    cached: bool = False
    latency_ms: float


class UrlClickCreate(BaseModel):
    """Payload for recording a user click action on an email hyperlink."""
    url: str = Field(..., min_length=1, max_length=4096, description="Destination URL")
    defanged_url: str | None = None
    email_subject: str | None = None
    sender: str | None = None
    risk_score: float = 0.0
    risk_level: str = "AUDITED"
    proceeded: bool = True
    source: str = "email_body_link"
    user_email: str | None = None


class UrlClickResponse(BaseModel):
    """Response confirming click event storage."""
    id: int
    url: str
    defanged_url: str
    risk_score: float
    risk_level: str
    proceeded: bool
    recorded: bool = True


class ScanAuditCreate(BaseModel):
    """Payload for recording a zero-PII scan audit log."""
    scan_type: str = Field(default="EMAIL", max_length=16)
    content_hash: str = Field(..., min_length=1, max_length=64)
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: str = Field(default="SAFE", max_length=32)
    threat_vectors: list[str] = Field(default_factory=list)


class ScanAuditResponse(BaseModel):
    """Response confirming scan audit storage."""
    id: int
    scan_type: str
    content_hash: str
    risk_score: int
    risk_level: str
    recorded: bool = True
