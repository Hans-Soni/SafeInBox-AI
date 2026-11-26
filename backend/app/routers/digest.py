"""API router for 15-day email security digest dispatch and preview."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.digest import SecurityDigestLog
from app.models.user import User, generate_user_index_id
from app.services.auth_service import get_current_user
from app.schemas.digest import (
    DigestSendRequest,
    DigestSendResponse,
    DigestHistoryItem,
    DigestPurgeResponse
)
from app.services.digest_service import (
    dispatch_15_day_digest,
    generate_digest_html,
    purge_expired_15day_history
)

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
    - ML threat scores and vectors
    - Complete 15-day URL click history
    - Automatically purges database records older than 15 days
    """
    if not payload.user_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid user email is required for 15-day digest delivery."
        )

    success, message, dispatch_mode, preview_html, purge_info = await dispatch_15_day_digest(db, payload)

    total_threats = sum(
        1 for r in payload.records
        if r.composite_risk >= 35 or r.risk_level in ("HIGH", "CRITICAL", "MEDIUM")
    )
    click_urls_set = set(c.url for c in payload.url_clicks)
    for r in payload.records:
        for c in r.clicked_urls:
            click_urls_set.add(c.url)
    total_clicks = max(len(click_urls_set), len(payload.url_clicks))
    resolved_idx = payload.user_index_id or generate_user_index_id(payload.user_email)

    return DigestSendResponse(
        success=success,
        message=message,
        recipient=payload.user_email,
        user_index_id=resolved_idx,
        period=f"{payload.period_start} to {payload.period_end}",
        total_emails=len(payload.records),
        threats_detected=total_threats,
        total_clicks=total_clicks,
        purged_records=purge_info.get("total_purged", 0),
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
        records=payload.records,
        url_clicks=payload.url_clicks
    )
    click_urls_set = set(c.url for c in payload.url_clicks)
    for r in payload.records:
        for c in r.clicked_urls:
            click_urls_set.add(c.url)
    total_clicks = max(len(click_urls_set), len(payload.url_clicks))

    return {
        "user_email": payload.user_email,
        "period": f"{payload.period_start} to {payload.period_end}",
        "total_emails": len(payload.records),
        "total_clicks": total_clicks,
        "html": html_content
    }


@router.post("/purge", response_model=DigestPurgeResponse, summary="Purge email history and URL clicks older than 15 days")
async def purge_expired_history(
    user_email: Optional[str] = None,
    days: int = 15,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Clear all email scan logs, URL clicks, and past digest logs older than 15 days
    from the database for the authenticated user to enforce the 15-day rolling retention limit.
    """
    target_email = current_user.email.strip().lower()
    if user_email and user_email.strip().lower() != target_email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot purge history of another user."
        )
    result = await purge_expired_15day_history(db, user_email=target_email, days=days)
    return DigestPurgeResponse(
        success=True,
        message=f"Purged {result['total_purged']} expired records older than {days} days from database.",
        **result
    )


@router.get("/history", response_model=List[DigestHistoryItem], summary="Get past digest logs for user")
async def get_digest_history(
    user_email: Optional[str] = None,
    user_index_id: Optional[str] = None,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve historical 15-day digest dispatch logs for the authenticated user."""
    target_email = current_user.email.strip().lower()
    target_index = (current_user.index_id or "").strip().upper()

    if user_email and user_email.strip().lower() != target_email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot access digest history of another user."
        )
    if user_index_id and user_index_id.strip().upper() != target_index:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot access digest history of another user index."
        )

    filters = [SecurityDigestLog.user_email == target_email]
    if target_index:
        filters.append(SecurityDigestLog.user_index_id == target_index)

    stmt = select(SecurityDigestLog).where(or_(*filters)).order_by(SecurityDigestLog.created_at.desc()).limit(limit)
    result = await db.execute(stmt)
    logs = result.scalars().all()

    return [
        DigestHistoryItem(
            id=log.id,
            user_email=log.user_email,
            user_index_id=log.user_index_id,
            period_start=log.period_start,
            period_end=log.period_end,
            total_emails=log.total_emails,
            threat_count=log.threat_count,
            click_count=log.click_count,
            dispatch_status=log.dispatch_status,
            is_encrypted=log.is_encrypted or False,
            encrypted_payload=log.encrypted_payload,
            created_at=log.created_at.isoformat()
        )
        for log in logs
    ]
