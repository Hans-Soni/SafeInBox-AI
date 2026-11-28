"""Email text threat analysis router."""

import hashlib
import json
import time
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import ScanAuditLog
from app.schemas.email_scan import EmailScanRequest, EmailScanResponse
from app.services.community_service import get_community_intel
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

    # Query anonymous aggregate community crowd consensus in O(1) time
    email_text = payload.text or payload.body or ""
    community_intel = await get_community_intel(
        db=db,
        target=email_text,
        target_type="EMAIL",
        subject=payload.subject
    )

    if community_intel.flagged and community_intel.message:
        result["evidence"].append({
            "rule_id": "COMMUNITY_CROWD_THREAT",
            "severity": "CRITICAL" if community_intel.threat_count >= 3 else "HIGH",
            "evidence": community_intel.message,
            "remediation": "Multiple SafeInbox AI community members previously flagged this email template as phishing. Do not click links or respond.",
            "threat_vector": "COMMUNITY_REPORTED_THREAT"
        })
        if "COMMUNITY_REPORTED_THREAT" not in result["threat_vectors"]:
            result["threat_vectors"].append("COMMUNITY_REPORTED_THREAT")
        if result["risk_score"] < 60:
            result["risk_score"] = min(85, max(result["risk_score"] + 30, 65))
            result["riskScore"] = result["risk_score"] / 100.0
            if result["risk_level"] in ("SAFE", "LOW"):
                result["risk_level"] = "HIGH" if community_intel.threat_count >= 3 else "MEDIUM"

    # Optional URL scan for embedded URLs if provided
    urls_analyzed = []
    candidate_urls = [u for u in (payload.urls or []) if isinstance(u, str)]
    if candidate_urls:
        for u in candidate_urls[:20]:  # Limit to 20 candidate URLs
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

    # Quishing Defense: Analyze decoded QR codes if present
    qr_codes_analyzed = []
    candidate_qr = [q for q in (payload.qr_codes or []) if isinstance(q, str)]
    if candidate_qr:
        for qr_url in candidate_qr[:10]:
            try:
                qr_res = analyze_url(qr_url)
                qr_codes_analyzed.append({
                    "url": qr_url,
                    "risk_score": qr_res["riskScore"],
                    "risk_level": qr_res["riskLevel"],
                    "attack_types": qr_res["attackTypes"],
                    "findings": qr_res["findings"]
                })
                if qr_res["riskScore"] >= 0.4:
                    if "QUISHING_QR_CODE_THREAT" not in result["threat_vectors"]:
                        result["threat_vectors"].append("QUISHING_QR_CODE_THREAT")
                    result["evidence"].insert(0, {
                        "rule_id": "QUISHING_MALICIOUS_DESTINATION",
                        "severity": "CRITICAL" if qr_res["riskScore"] >= 0.8 else "HIGH",
                        "evidence": f"Embedded QR code leads to suspicious destination: {qr_url}",
                        "remediation": "Do not scan this QR code with mobile devices. The destination link was flagged as malicious.",
                        "threat_vector": "QUISHING_QR_CODE_THREAT"
                    })
                    result["risk_score"] = max(result["risk_score"], int(qr_res["riskScore"] * 100))
                    result["riskScore"] = result["risk_score"] / 100.0
                    if result["risk_level"] in ("SAFE", "LOW"):
                        result["risk_level"] = "HIGH"
            except Exception:
                qr_codes_analyzed.append({
                    "url": qr_url,
                    "risk_score": 0.0,
                    "risk_level": "UNKNOWN",
                    "error": "QR target analysis failed"
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
        extracted_urls_count=len(candidate_urls),
        urls_analyzed=urls_analyzed,
        qr_codes_analyzed=qr_codes_analyzed,
        analysis_note=result["analysis_note"],
        community_intel=community_intel,
        manipulation_radar=result.get("manipulation_radar"),
        latency_ms=round(elapsed, 2)
    )

