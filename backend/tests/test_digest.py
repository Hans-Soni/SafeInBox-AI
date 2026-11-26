"""Tests for 15-day email security digest generation and dispatch."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.digest_service import generate_digest_html
from app.schemas.digest import EmailRecordItem, UrlClickItem


def test_generate_digest_html_contains_all_fields():
    """Verify generated HTML digest includes senders, receivers, time-slabs, ML scores, and clicked URLs."""
    records = [
        EmailRecordItem(
            id="rec_1",
            sender="Security Dept <alerts@bank-verify.com>",
            receiver="target.user@company.com",
            subject="Urgent: Account Suspension Notice",
            timestamp=1730500000000,
            date_iso="2026-11-01T10:00:00Z",
            time_slab="2026-10-18 to 2026-11-02",
            composite_risk=85.0,
            risk_level="CRITICAL",
            text_threat_score=92.0,
            url_threat_score=78.0,
            threat_vectors=["ARTIFICIAL_URGENCY", "CREDENTIAL_HARVESTING"],
            clicked_urls=[
                UrlClickItem(
                    url="https://bank-verify.com/login.php",
                    defanged="hxxps://bank-verify[.]com/login.php",
                    risk_score=95.0,
                    risk_level="CRITICAL",
                    timestamp="2026-11-01 10:02:00"
                )
            ]
        ),
        EmailRecordItem(
            id="rec_2",
            sender="Alice Smith <alice@company.com>",
            receiver="target.user@company.com",
            subject="Project roadmap update",
            timestamp=1730510000000,
            date_iso="2026-11-01T12:00:00Z",
            time_slab="2026-10-18 to 2026-11-02",
            composite_risk=5.0,
            risk_level="SAFE",
            text_threat_score=2.0,
            url_threat_score=0.0,
            threat_vectors=[],
            clicked_urls=[]
        )
    ]

    html_out = generate_digest_html(
        user_email="target.user@company.com",
        user_name="Target User",
        period_start="2026-10-18",
        period_end="2026-11-02",
        records=records
    )

    # Check key components
    assert "target.user@company.com" in html_out
    assert "Target User" in html_out
    assert "2026-10-18" in html_out
    assert "2026-11-02" in html_out
    assert "alerts@bank-verify.com" in html_out
    assert "alice@company.com" in html_out
    assert "ML Score: 85/100 (CRITICAL)" in html_out
    assert "ML Score: 5/100 (SAFE)" in html_out
    assert "hxxps://bank-verify[.]com/login.php" in html_out
    assert "Risk: 95/100" in html_out
    assert "ARTIFICIAL_URGENCY" in html_out


@pytest.mark.asyncio
async def test_digest_send_and_preview_endpoints():
    """Verify POST /api/v1/digest/send and preview endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "user_email": "security.audit@safeinbox.ai",
            "user_name": "Audit Test User",
            "period_start": "2026-10-18",
            "period_end": "2026-11-02",
            "records": [
                {
                    "sender": "Payroll Dept <payroll@scam-payroll.org>",
                    "receiver": "security.audit@safeinbox.ai",
                    "subject": "Direct Deposit Verification Required",
                    "timestamp": 1730505000000,
                    "date_iso": "2026-11-01T11:00:00Z",
                    "composite_risk": 78.0,
                    "risk_level": "HIGH",
                    "text_threat_score": 80.0,
                    "url_threat_score": 75.0,
                    "threat_vectors": ["FINANCIAL_SCAM"],
                    "clicked_urls": [
                        {
                            "url": "http://scam-payroll.org/verify",
                            "defanged": "hxxp://scam-payroll[.]org/verify",
                            "risk_score": 85.0,
                            "risk_level": "HIGH"
                        }
                    ]
                }
            ]
        }

        # Test preview
        preview_res = await client.post("/api/v1/digest/preview", json=payload)
        assert preview_res.status_code == 200
        preview_data = preview_res.json()
        assert "html" in preview_data
        assert "security.audit@safeinbox.ai" in preview_data["html"]

        # Test send
        send_res = await client.post("/api/v1/digest/send", json=payload)
        assert send_res.status_code == 200
        send_data = send_res.json()
        assert send_data["success"] is True
        assert send_data["recipient"] == "security.audit@safeinbox.ai"
        assert send_data["total_emails"] == 1
        assert send_data["threats_detected"] == 1
        assert send_data["total_clicks"] == 1
        assert send_data["dispatch_mode"] in ("smtp", "simulated_preview", "apps_script")

        # Test unauthenticated history retrieval (MUST be rejected with 401)
        unauth_res = await client.get("/api/v1/digest/history?user_email=security.audit@safeinbox.ai")
        assert unauth_res.status_code == 401

        # Register authenticated user
        signup_res = await client.post("/api/v1/auth/signup", json={
            "email": "security.audit@safeinbox.ai",
            "password": "M7$xK9#vL2@qW4!",
            "full_name": "Digest Officer"
        })
        assert signup_res.status_code == 201, f"Signup failed: {signup_res.text}"
        auth_headers = {"Authorization": f"Bearer {signup_res.json()['access_token']}"}

        # Test authenticated history retrieval
        hist_res = await client.get("/api/v1/digest/history?user_email=security.audit@safeinbox.ai", headers=auth_headers)
        assert hist_res.status_code == 200
        hist_data = hist_res.json()
        assert len(hist_data) >= 1
        assert hist_data[0]["user_email"] == "security.audit@safeinbox.ai"

        # Test cross-user IDOR access (MUST be rejected with 403)
        idor_res = await client.get("/api/v1/digest/history?user_email=victim@safeinbox.ai", headers=auth_headers)
        assert idor_res.status_code == 403

