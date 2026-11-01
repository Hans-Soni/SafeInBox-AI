"""Pydantic schemas for feedback and health check endpoints."""

from datetime import datetime
from pydantic import BaseModel, Field


class FeedbackRequest(BaseModel):
    """User-submitted assessment for URL or Email."""
    target: str = Field(..., min_length=1, max_length=20000)
    is_safe: bool
    target_type: str = Field(default="URL", pattern="^(URL|TEXT|EMAIL)$")
    source: str = Field(default="api", max_length=64)


class FeedbackResponse(BaseModel):
    """Response confirming feedback storage."""
    status: str = "recorded"
    target_hash: str
    target_type: str
    is_safe: bool
    recorded_at: datetime


class FeedbackItem(BaseModel):
    """Stored feedback assessment record."""
    id: int
    target_hash: str
    target_type: str
    is_safe: bool
    source: str
    target_sample: str
    created_at: datetime


class DatasetSplitResponse(BaseModel):
    """Strictly partitioned dataset splits for offline model training and evaluation."""
    target_type: str
    total_samples: int
    train_count: int
    val_count: int
    test_count: int
    zero_leakage_verified: bool
    train: list[FeedbackItem]
    val: list[FeedbackItem]
    test: list[FeedbackItem]


class HealthResponse(BaseModel):
    """System health check response."""
    status: str = "healthy"
    version: str
    environment: str
    database: str
    timestamp: datetime

