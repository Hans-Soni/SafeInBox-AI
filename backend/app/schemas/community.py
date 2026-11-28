"""Pydantic schemas for Privacy-Preserving Community Threat Intelligence."""

from pydantic import BaseModel, Field


class CommunityIntelResponse(BaseModel):
    """Anonymous aggregate crowd intelligence metric for emails and URLs."""
    flagged: bool = Field(default=False, description="Whether aggregate community reports flag this as a threat")
    threat_count: int = Field(default=0, description="Total independent community threat reports")
    safe_count: int = Field(default=0, description="Total independent community safe reports")
    consensus: str = Field(default="NONE", description="Consensus verdict: THREAT, SAFE, or NONE")
    confidence: float = Field(default=0.0, description="Confidence ratio of consensus")
    match_type: str = Field(default="NONE", description="Match granularity: EXACT, FUZZY_LSH, or NONE")
    similarity: float | None = Field(default=None, description="Estimated Jaccard similarity for fuzzy matches")
    message: str | None = Field(default=None, description="User-facing anonymous explanation")
