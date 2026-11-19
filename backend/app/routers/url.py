"""URL threat analysis and audit log router."""

import hashlib
import time
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import ThreatURL, ScanAuditLog, UrlClickLog
from app.schemas.url_scan import (
    URLScanRequest,
    URLScanResponse,
    UrlClickCreate,
    UrlClickResponse,
    ScanAuditCreate,
    ScanAuditResponse,
)
from app.services.url_analyzer import analyze_url

router = APIRouter(prefix="/api/v1/scan", tags=["URL Scanner & Audits"])


def sha256_hash(text: str) -> str:
    """Compute hex SHA-256 digest."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def defang_url(url: str) -> str:
    """Defang URL for safe persistence and display."""
    return url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


@router.post("/url", response_model=URLScanResponse, status_code=status.HTTP_200_OK)
async def scan_url(
    payload: URLScanRequest,
    db: AsyncSession = Depends(get_db)
) -> URLScanResponse:
    """Analyze a single URL for phishing, homographs, redirects, and injection markers."""
    t0 = time.perf_counter()

    try:
        result = analyze_url(payload.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc)
        ) from exc

    url_hash = sha256_hash(result["canonicalUrl"])

    # Check cache in DB
    cached_stmt = select(ThreatURL).where(ThreatURL.url_hash == url_hash)
    db_result = await db.execute(cached_stmt)
    cached_entry = db_result.scalars().first()

    if cached_entry:
        elapsed = (time.perf_counter() - t0) * 1000
        return URLScanResponse(
            inputUrl=result["inputUrl"],
            canonicalUrl=cached_entry.canonical_url,
            hostname=cached_entry.hostname,
            unicodeHostname=result["unicodeHostname"],
            matchedBrand=result["matchedBrand"],
            riskScore=cached_entry.risk_score,
            riskLevel=cached_entry.risk_level,
            attackTypes=cached_entry.attack_types,
            findings=cached_entry.findings,
            cached=True,
            latency_ms=round(elapsed, 2)
        )

    # Save to database cache
    new_entry = ThreatURL(
        url_hash=url_hash,
        canonical_url=result["canonicalUrl"][:4096],
        hostname=result["hostname"][:255],
        risk_score=result["riskScore"],
        risk_level=result["riskLevel"],
        attack_types=result["attackTypes"],
        findings=result["findings"]
    )
    db.add(new_entry)

    # Record privacy-preserving audit log
    audit_entry = ScanAuditLog(
        scan_type="URL",
        content_hash=url_hash,
        risk_score=int(result["riskScore"] * 100),
        risk_level=result["riskLevel"],
        threat_vectors=result["attackTypes"]
    )
    db.add(audit_entry)

    await db.commit()

    elapsed = (time.perf_counter() - t0) * 1000
    return URLScanResponse(
        inputUrl=result["inputUrl"],
        canonicalUrl=result["canonicalUrl"],
        hostname=result["hostname"],
        unicodeHostname=result["unicodeHostname"],
        matchedBrand=result["matchedBrand"],
        riskScore=result["riskScore"],
        riskLevel=result["riskLevel"],
        attackTypes=result["attackTypes"],
        findings=result["findings"],
        cached=False,
        latency_ms=round(elapsed, 2)
    )


@router.post("/click", response_model=UrlClickResponse, status_code=status.HTTP_201_CREATED)
async def record_click(
    payload: UrlClickCreate,
    db: AsyncSession = Depends(get_db)
) -> UrlClickResponse:
    """Record a user click on an email hyperlink in the persistent database."""
    url_hash = sha256_hash(payload.url)
    defanged = payload.defanged_url or defang_url(payload.url)

    click_entry = UrlClickLog(
        user_email=payload.user_email,
        url=payload.url[:4096],
        defanged_url=defanged[:4096],
        url_hash=url_hash,
        email_subject=(payload.email_subject or "")[:255] if payload.email_subject else None,
        sender=(payload.sender or "")[:255] if payload.sender else None,
        risk_score=float(payload.risk_score),
        risk_level=str(payload.risk_level),
        proceeded=bool(payload.proceeded),
        source=(payload.source or "email_body_link")[:64],
    )
    db.add(click_entry)
    await db.commit()
    await db.refresh(click_entry)

    return UrlClickResponse(
        id=click_entry.id,
        url=click_entry.url,
        defanged_url=click_entry.defanged_url,
        risk_score=click_entry.risk_score,
        risk_level=click_entry.risk_level,
        proceeded=click_entry.proceeded,
        recorded=True
    )


@router.get("/clicks", response_model=list[UrlClickResponse])
async def get_clicks(
    user_email: str | None = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
) -> list[UrlClickResponse]:
    """Retrieve recent recorded click events from the persistent database."""
    stmt = select(UrlClickLog)
    if user_email:
        stmt = stmt.where(UrlClickLog.user_email == user_email)
    stmt = stmt.order_by(UrlClickLog.clicked_at.desc()).limit(min(limit, 500))
    result = await db.execute(stmt)
    entries = result.scalars().all()
    return [
        UrlClickResponse(
            id=entry.id,
            url=entry.url,
            defanged_url=entry.defanged_url,
            risk_score=entry.risk_score,
            risk_level=entry.risk_level,
            proceeded=entry.proceeded,
            recorded=True
        )
        for entry in entries
    ]


@router.post("/audit", response_model=ScanAuditResponse, status_code=status.HTTP_201_CREATED)
async def record_audit(
    payload: ScanAuditCreate,
    db: AsyncSession = Depends(get_db)
) -> ScanAuditResponse:
    """Record a zero-PII scan audit log in the persistent database."""
    audit_entry = ScanAuditLog(
        scan_type=payload.scan_type.upper()[:16],
        content_hash=payload.content_hash[:64],
        risk_score=int(payload.risk_score),
        risk_level=str(payload.risk_level)[:32],
        threat_vectors=payload.threat_vectors
    )
    db.add(audit_entry)
    await db.commit()
    await db.refresh(audit_entry)

    return ScanAuditResponse(
        id=audit_entry.id,
        scan_type=audit_entry.scan_type,
        content_hash=audit_entry.content_hash,
        risk_score=audit_entry.risk_score,
        risk_level=audit_entry.risk_level,
        recorded=True
    )


@router.get("/audits", response_model=list[ScanAuditResponse])
async def get_audits(
    scan_type: str | None = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
) -> list[ScanAuditResponse]:
    """Retrieve recent scan audit logs from the persistent database."""
    stmt = select(ScanAuditLog)
    if scan_type:
        stmt = stmt.where(ScanAuditLog.scan_type == scan_type.upper())
    stmt = stmt.order_by(ScanAuditLog.created_at.desc()).limit(min(limit, 500))
    result = await db.execute(stmt)
    entries = result.scalars().all()
    return [
        ScanAuditResponse(
            id=entry.id,
            scan_type=entry.scan_type,
            content_hash=entry.content_hash,
            risk_score=entry.risk_score,
            risk_level=entry.risk_level,
            recorded=True
        )
        for entry in entries
    ]
