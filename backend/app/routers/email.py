"""Email text threat analysis router."""

import hashlib
import json
import time
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import ScanAuditLog
from app.schemas.email_scan import EmailScanRequest, EmailScanResponse
from app.services.email_analyzer import analyze_email_text
from app.services.url_analyzer import analyze_url

router = APIRouter(prefix="/api/v1/scan", tags=["Email Scanner"])


def sha256_hash(data: dict) -> str:
    """Compute deterministic SHA-256 digest of email metadata."""
    canonical = json.dumps({
        "sender": data.get("sender", ""),
        "subject": data.get("subject", ""),
        "text": data.get("text", ""),
        "body": data.get("body", "")
    }, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@router.post("/email", response_model=EmailScanResponse, status_code=status.HTTP_200_OK)
async def scan_email(
    payload: EmailScanRequest,
    db: AsyncSession = Depends(get_db)
) -> EmailScanResponse:
    """Analyze email text, headers, and embedded link candidates for threats."""
    t0 = time.perf_counter()

    email_dict = payload.model_dump()
    result = analyze_email_text(email_dict)
    content_hash = sha256_hash(email_dict)

    # Optional URL scan for embedded URLs if provided
    urls_analyzed = []
    if payload.urls:
        for u in payload.urls[:20]:  # Limit to 20 candidate URLs
            try:
                u_res = analyze_url(u)
                urls_analyzed.append({
                    "url": u,
                    "risk_score": u_res["riskScore"],
                    "risk_level": u_res["riskLevel"],
                    "attack_types": u_res["attackTypes"],
                    "findings": u_res["findings"]
                })
            except Exception:
                urls_analyzed.append({
                    "url": u,
                    "risk_score": 0.0,
                    "risk_level": "UNKNOWN",
                    "error": "URL parsing failed"
                })

    # Record privacy-preserving audit log (no email body/subject stored)
    audit_entry = ScanAuditLog(
        scan_type="EMAIL",
        content_hash=content_hash,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        threat_vectors=result["threat_vectors"]
    )
    db.add(audit_entry)
    await db.commit()

    elapsed = (time.perf_counter() - t0) * 1000
    return EmailScanResponse(
        target_type=result["target_type"],
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        riskScore=result["riskScore"],
        threat_vectors=result["threat_vectors"],
        summary=result["summary"],
        recommended_action=result["recommended_action"],
        evidence=result["evidence"],
        company_intelligence=result["company_intelligence"],
        extracted_urls_count=len(payload.urls),
        urls_analyzed=urls_analyzed,
        analysis_note=result["analysis_note"],
        latency_ms=round(elapsed, 2)
    )

