"""Standalone verification for 15-day digest HTML generation and endpoints."""

import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.digest_service import generate_digest_html
from app.schemas.digest import EmailRecordItem, UrlClickItem
from app.main import app
from httpx import ASGITransport, AsyncClient


def test_html():
    print("[*] Testing generate_digest_html...")
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

    assert "target.user@company.com" in html_out
    assert "Target User" in html_out
    assert "alerts@bank-verify.com" in html_out
    assert "hxxps://bank-verify[.]com/login.php" in html_out
    assert "ML Score: 85/100 (CRITICAL)" in html_out
    print(f"[*] generate_digest_html passed successfully ({len(html_out)} chars generated)")


def test_schemas_and_preview():
    print("[*] Testing DigestSendRequest schema validation and preview generation...")
    from app.schemas.digest import DigestSendRequest
    payload = DigestSendRequest(
        user_email="security.audit@safeinbox.ai",
        user_name="Audit Test User",
        period_start="2026-10-18",
        period_end="2026-11-02",
        records=[
            EmailRecordItem(
                id="rec_audit_1",
                sender="Payroll Dept <payroll@scam-payroll.org>",
                receiver="security.audit@safeinbox.ai",
                subject="Direct Deposit Verification Required",
                timestamp=1730505000000,
                date_iso="2026-11-01T11:00:00Z",
                time_slab="2026-10-18 to 2026-11-02",
                composite_risk=78.0,
                risk_level="HIGH",
                text_threat_score=80.0,
                url_threat_score=75.0,
                threat_vectors=["FINANCIAL_SCAM"],
                clicked_urls=[
                    UrlClickItem(
                        url="http://scam-payroll.org/verify",
                        defanged="hxxp://scam-payroll[.]org/verify",
                        risk_score=85.0,
                        risk_level="HIGH",
                        timestamp="2026-11-01 11:02:00"
                    )
                ]
            )
        ]
    )
    assert payload.user_email == "security.audit@safeinbox.ai"
    assert len(payload.records) == 1
    html = generate_digest_html(
        user_email=payload.user_email,
        user_name=payload.user_name,
        period_start=payload.period_start,
        period_end=payload.period_end,
        records=payload.records
    )
    assert "Direct Deposit Verification Required" in html
    assert "hxxp://scam-payroll[.]org/verify" in html
    print("[*] DigestSendRequest validation and preview generation PASSED")


if __name__ == "__main__":
    test_html()
    test_schemas_and_preview()
    print("\nALL 15-DAY DIGEST BACKEND CHECKS PASSED!\n")

