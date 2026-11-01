"""Feedback ingestion router for user-provided Safe / Threat assessments."""

from datetime import datetime, timezone
import hashlib
from typing import Literal
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import FeedbackRecord
from app.schemas.feedback import DatasetSplitResponse, FeedbackItem, FeedbackRequest, FeedbackResponse
from app.services.dataset_manager import assert_zero_leakage, split_dataset

router = APIRouter(prefix="/api/v1", tags=["Feedback"])


def sha256_hash(text: str) -> str:
    """Compute hex SHA-256 digest."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@router.post("/feedback", response_model=FeedbackResponse, status_code=status.HTTP_201_CREATED)
async def submit_feedback(
    payload: FeedbackRequest,
    db: AsyncSession = Depends(get_db)
) -> FeedbackResponse:
    """Store labeled user assessment for future model dataset training."""
    target_clean = payload.target.strip()
    target_hash = sha256_hash(target_clean)

    # Sanitize and truncate sample
    normalized_type = "TEXT" if payload.target_type == "EMAIL" else payload.target_type
    max_len = 20000 if normalized_type == "TEXT" else 4096
    bounded_sample = target_clean[:max_len]

    record = FeedbackRecord(
        target_hash=target_hash,
        target_type=normalized_type,
        is_safe=payload.is_safe,
        source=payload.source[:64],
        target_sample=bounded_sample
    )
    db.add(record)
    await db.commit()

    return FeedbackResponse(
        status="recorded",
        target_hash=target_hash,
        target_type=normalized_type,
        is_safe=payload.is_safe,
        recorded_at=datetime.now(timezone.utc)
    )


@router.get("/feedback", response_model=list[FeedbackItem], status_code=status.HTTP_200_OK)
async def list_feedback(
    target_type: Literal["URL", "TEXT"] | None = Query(
        None,
        description="Filter feedback strictly by URL vs TEXT storage to prevent dataset cross-contamination"
    ),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db)
) -> list[FeedbackItem]:
    """Retrieve feedback records strictly partitioned by target type (URL or TEXT)."""
    stmt = select(FeedbackRecord).order_by(FeedbackRecord.created_at.desc()).limit(limit)
    if target_type:
        stmt = stmt.where(FeedbackRecord.target_type == target_type)

    result = await db.execute(stmt)
    records = result.scalars().all()
    return [
        FeedbackItem(
            id=r.id,
            target_hash=r.target_hash,
            target_type=r.target_type,
            is_safe=r.is_safe,
            source=r.source,
            target_sample=r.target_sample,
            created_at=r.created_at
        )
        for r in records
    ]


@router.get("/feedback/export-split", response_model=DatasetSplitResponse, status_code=status.HTTP_200_OK)
async def export_dataset_split(
    target_type: Literal["URL", "TEXT"] = Query(
        "URL",
        description="Target dataset to partition ('URL' or 'TEXT')"
    ),
    train_ratio: float = Query(0.80, ge=0.5, le=0.9),
    val_ratio: float = Query(0.10, ge=0.05, le=0.3),
    test_ratio: float = Query(0.10, ge=0.05, le=0.3),
    db: AsyncSession = Depends(get_db)
) -> DatasetSplitResponse:
    """Export training, validation, and testing splits partitioned with mathematical zero-leakage guarantee."""
    stmt = select(FeedbackRecord).where(FeedbackRecord.target_type == target_type)
    result = await db.execute(stmt)
    records = result.scalars().all()

    items = [
        FeedbackItem(
            id=r.id,
            target_hash=r.target_hash,
            target_type=r.target_type,
            is_safe=r.is_safe,
            source=r.source,
            target_sample=r.target_sample,
            created_at=r.created_at
        )
        for r in records
    ]

    splits = split_dataset(
        items,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        hash_attr="target_hash"
    )

    zero_leakage = assert_zero_leakage(
        train=splits["train"],
        test=splits["test"],
        val=splits["val"],
        hash_attr="target_hash"
    )

    return DatasetSplitResponse(
        target_type=target_type,
        total_samples=len(items),
        train_count=len(splits["train"]),
        val_count=len(splits["val"]),
        test_count=len(splits["test"]),
        zero_leakage_verified=zero_leakage,
        train=splits["train"],
        val=splits["val"],
        test=splits["test"]
    )

