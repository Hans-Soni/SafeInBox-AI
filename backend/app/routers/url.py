"""URL threat analysis router."""

import hashlib
import time
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import ThreatURL, ScanAuditLog
from app.schemas.url_scan import URLScanRequest, URLScanResponse
from app.services.url_analyzer import analyze_url

router = APIRouter(prefix="/api/v1/scan", tags=["URL Scanner"])


def sha256_hash(text: str) -> str:
    """Compute hex SHA-256 digest."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
