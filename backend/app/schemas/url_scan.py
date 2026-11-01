"""Pydantic schemas for URL threat scanning."""

from typing import Any
from pydantic import BaseModel, Field


class URLFinding(BaseModel):
    """Specific threat indicator or heuristic finding."""
    signal: str
    attackType: str
    title: str
    detail: str
    penalty: float


class URLScanRequest(BaseModel):
    """URL scan request payload."""
    url: str = Field(..., min_length=1, max_length=4096, description="URL to analyze")


class URLScanResponse(BaseModel):
    """URL scan response matching extension threat engine contract."""
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

