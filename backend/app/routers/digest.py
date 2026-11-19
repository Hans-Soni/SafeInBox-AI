"""API router for 15-day email security digest dispatch and preview."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.digest import SecurityDigestLog
from app.schemas.digest import (
    DigestSendRequest,
    DigestSendResponse,
    DigestHistoryItem
)
from app.services.digest_service import dispatch_15_day_digest, generate_digest_html

router = APIRouter(prefix="/api/v1/digest", tags=["Security Digest"])


@router.post("/send", response_model=DigestSendResponse, summary="Dispatch 15-day security record to user email")
async def send_15_day_digest(
    payload: DigestSendRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Format and email the 15-day security and threat record to the specific user.
    Contains:
    - Senders and receivers
    - Time-slab records
    - ML threat scores
    - All URL clicks within each email
    """
    if not payload.user_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid user email is required for 15-day digest delivery."
        )

    success, message, dispatch_mode, preview_html = await dispatch_15_day_digest(db, payload)

    total_threats = sum(
        1 for r in payload.records
        if r.composite_risk >= 35 or r.risk_level in ("HIGH", "CRITICAL", "MEDIUM")
    )
    total_clicks = sum(len(r.clicked_urls) for r in payload.records)

    return DigestSendResponse(
        success=success,
        message=message,
        recipient=payload.user_email,
        period=f"{payload.period_start} to {payload.period_end}",
        total_emails=len(payload.records),
        threats_detected=total_threats,
        total_clicks=total_clicks,
        dispatch_mode=dispatch_mode,
        preview_html=preview_html
    )


@router.post("/preview", summary="Generate HTML preview of 15-day security digest")
async def preview_15_day_digest(payload: DigestSendRequest):
    """Generate rendered HTML preview of the 15-day audit email for inspection."""
    html_content = generate_digest_html(
        user_email=payload.user_email,
        user_name=payload.user_name or "SafeInbox AI User",
        period_start=payload.period_start,
        period_end=payload.period_end,
        records=payload.records
    )
    return {
        "user_email": payload.user_email,
        "period": f"{payload.period_start} to {payload.period_end}",
        "total_emails": len(payload.records),
        "html": html_content
    }


@router.get("/history", response_model=List[DigestHistoryItem], summary="Get past digest logs for user")
async def get_digest_history(
    user_email: str,
    limit: int = 20,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve historical 15-day digest dispatch logs for a user email."""
    stmt = (
        select(SecurityDigestLog)
        .where(SecurityDigestLog.user_email == user_email.strip().lower())
        .order_by(SecurityDigestLog.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()

    return [
        DigestHistoryItem(
            id=log.id,
            user_email=log.user_email,
            period_start=log.period_start,
            period_end=log.period_end,
            total_emails=log.total_emails,
            threat_count=log.threat_count,
            click_count=log.click_count,
            dispatch_status=log.dispatch_status,
            created_at=log.created_at.isoformat()
        )
        for log in logs
    ]

