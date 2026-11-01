"""Pydantic schemas for Email threat scanning."""

from typing import Any
from pydantic import BaseModel, Field


class EmailEvidence(BaseModel):
    """Specific evidence item in email threat analysis."""
    rule_id: str
    severity: str
    evidence: str
    remediation: str
    threat_vector: str


class CompanyIntelligence(BaseModel):
    """Brand and domain intelligence result."""
    claimed_brand: str | None = None
    status: str
    sender_domain: str
    canonical_domains: list[str] = []


class EmailScanRequest(BaseModel):
    """Email threat scan request payload."""
    sender: str = Field(default="", max_length=512)
    receiver: str = Field(default="", max_length=512)
    cc: str = Field(default="", max_length=512)
    bcc: str = Field(default="", max_length=512)
    subject: str = Field(default="", max_length=1024)
    text: str = Field(default="", max_length=1_000_000)
    body: str = Field(default="", max_length=1_000_000)
    urls: list[str] = Field(default_factory=list, max_length=100)


class EmailScanResponse(BaseModel):
    """Email threat scan response matching extension threat engine contract."""
    target_type: str = "EMAIL"
    risk_level: str
    risk_score: int
    riskScore: float
    threat_vectors: list[str]
    summary: str
    recommended_action: str
    evidence: list[dict[str, Any]]
    company_intelligence: CompanyIntelligence
    extracted_urls_count: int
    urls_analyzed: list[dict[str, Any]] = []
    analysis_note: str = ""
    latency_ms: float

