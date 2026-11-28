"""Test Suite for Feature 2: Inline QR Code Phishing Detection ('Quishing Defense')."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import init_db
from app.main import app


@pytest.mark.asyncio
async def test_email_scan_with_benign_qr_code():
    """Verify email scan with benign QR destination returns clean report."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "sender": "HR Portal <hr@verified-company.com>",
            "subject": "Benefits Enrollment QR Code",
            "body": "Please scan the QR code to review your updated health benefits.",
            "qr_codes": ["https://verified-company.com/benefits"]
        }

        resp = await client.post("/api/v1/scan/email", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert "qr_codes_analyzed" in data
        assert len(data["qr_codes_analyzed"]) == 1
        assert data["qr_codes_analyzed"][0]["url"] == "https://verified-company.com/benefits"
        assert "QUISHING_QR_CODE_THREAT" not in data["threat_vectors"]


@pytest.mark.asyncio
async def test_email_scan_with_malicious_quishing_qr_code():
    """Verify email scan with phishing QR destination flags QUISHING_QR_CODE_THREAT."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # A deceptive phishing QR destination (IP address + credential path)
        malicious_qr_target = "http://192.168.1.100/secure-microsoft-mfa/login.php?session=evil"

        payload = {
            "sender": "IT Support <support@secure-update-notice.xyz>",
            "subject": "URGENT: Microsoft 365 MFA Re-Authentication Required",
            "body": "Your MFA authentication token has expired. Scan the QR code below on your mobile authenticator.",
            "qr_codes": [malicious_qr_target]
        }

        resp = await client.post("/api/v1/scan/email", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        # Quishing Threat Assertions
        assert "QUISHING_QR_CODE_THREAT" in data["threat_vectors"]
        assert data["risk_score"] >= 65
        assert data["risk_level"] in ("HIGH", "CRITICAL")

        # Evidence checks
        evidence_rules = [e["rule_id"] for e in data["evidence"]]
        assert "QUISHING_MALICIOUS_DESTINATION" in evidence_rules

        # QR Codes analyzed structure
        assert len(data["qr_codes_analyzed"]) == 1
        qr_eval = data["qr_codes_analyzed"][0]
        assert qr_eval["url"] == malicious_qr_target
        assert qr_eval["risk_score"] > 0.0

        # Zero-PII assertions
        assert "user_id" not in data
        assert "email" not in data
