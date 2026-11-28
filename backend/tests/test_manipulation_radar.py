"""Test Psychological Coercion & Manipulation Radar engine and endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.services.email_analyzer import compute_manipulation_radar, analyze_email_text


def test_manipulation_radar_urgency_coercion():
    radar = compute_manipulation_radar(
        subject="URGENT: Immediate Account Suspension Notice",
        body_text="Your account will be terminated within 24 hours unless you act now. Final warning: do not delay.",
        sender_raw="Security Team <security@example.com>",
        threat_vectors={"ARTIFICIAL_URGENCY"}
    )
    assert radar["urgency_score"] >= 70
    assert radar["dominant_tactic"] == "URGENCY"
    assert radar["cognitive_load_level"] in ("HIGH", "SEVERE")
    assert any("Urgency Pressure" in t for t in radar["detected_tactics"])


def test_manipulation_radar_authority_intimidation():
    radar = compute_manipulation_radar(
        subject="Confidential Executive Directive from the CEO",
        body_text="By direct order of the Chief Executive Officer, this matter is strictly confidential. Legal action and police report will follow if leaked. Do not discuss with anyone.",
        sender_raw="CEO Office <exec@example.com>",
        threat_vectors={"BEHAVIORAL_MANIPULATION"}
    )
    assert radar["authority_score"] >= 65
    assert radar["dominant_tactic"] == "AUTHORITY"
    assert radar["cognitive_load_level"] in ("HIGH", "SEVERE")
    assert any("Authority Coercion" in t for t in radar["detected_tactics"])


def test_manipulation_radar_financial_lure():
    radar = compute_manipulation_radar(
        subject="Invoice Overdue: Unclaimed Refund Available",
        body_text="You have won a prize of $5,000. Invoice #1029 is overdue. Please process wire transfer and direct deposit to claim your reward.",
        sender_raw="Billing <billing@example.com>",
        threat_vectors={"FINANCIAL_SCAM"}
    )
    assert radar["financial_score"] >= 65
    assert radar["dominant_tactic"] == "FINANCIAL"
    assert any("Financial Hook" in t for t in radar["detected_tactics"])


def test_manipulation_radar_credential_harvest():
    radar = compute_manipulation_radar(
        subject="Security Verification: Confirm Password and 2FA Code",
        body_text="Please verify your login credentials, password, and security code immediately to avoid service interruption.",
        sender_raw="Support <support@example.com>",
        threat_vectors={"CREDENTIAL_HARVESTING"}
    )
    assert radar["credential_score"] >= 70
    assert radar["dominant_tactic"] == "CREDENTIAL"
    assert any("Credential Harvest" in t for t in radar["detected_tactics"])


def test_manipulation_radar_benign_email():
    radar = compute_manipulation_radar(
        subject="Quarterly Team Retrospective and Planning",
        body_text="Hi team, hope you are having a wonderful week. Here is the agenda for our retrospective meeting on Thursday.",
        sender_raw="Colleague <colleague@company.internal>",
        threat_vectors=set()
    )
    assert radar["urgency_score"] < 25
    assert radar["authority_score"] < 25
    assert radar["financial_score"] < 25
    assert radar["credential_score"] < 25
    assert radar["dominant_tactic"] == "NONE"
    assert radar["cognitive_load_level"] == "LOW"
    assert len(radar["detected_tactics"]) == 0


@pytest.mark.asyncio
async def test_api_scan_email_returns_manipulation_radar():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "sender": "CEO <ceo@spoofed-company.com>",
            "subject": "URGENT: Executive Wire Transfer Required Immediately",
            "body": "By order of the CEO, execute this wire transfer within 24 hours. Strictly confidential, do not discuss.",
            "text": "By order of the CEO, execute this wire transfer within 24 hours. Strictly confidential, do not discuss."
        }
        resp = await client.post("/api/v1/scan/email", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "manipulation_radar" in data
        radar = data["manipulation_radar"]
        assert radar is not None
        assert radar["urgency_score"] >= 50
        assert radar["authority_score"] >= 50
        assert radar["dominant_tactic"] in ("URGENCY", "AUTHORITY", "FINANCIAL")
        assert radar["cognitive_load_level"] in ("HIGH", "SEVERE")
        assert len(radar["detected_tactics"]) >= 1
