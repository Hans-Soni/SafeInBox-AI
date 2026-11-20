"""Zero-Knowledge Client-Side Encryption verification test suite."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models.threat import UrlClickLog
from app.models.digest import SecurityDigestLog


@pytest.mark.asyncio
async def test_zk_encrypted_click_recording_and_retrieval():
    """Verify that encrypted URL clicks preserve zero-knowledge payload in persistent storage."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        test_email = "zk_user@safeinbox.test"
        mock_encrypted_payload = "vN4bMockBase64AES256GCMPayloadWithRandomIVAndAuthTag=="

        click_data = {
            "url": "[ENCRYPTED]",
            "defanged_url": "[ENCRYPTED]",
            "email_subject": "[ENCRYPTED]",
            "sender": "[ENCRYPTED]",
            "risk_score": 15.0,
            "risk_level": "AUDITED",
            "proceeded": True,
            "source": "email_body_link",
            "user_email": test_email,
            "user_index_id": "IDX-ZKTEST-0001",
            "is_encrypted": True,
            "encrypted_payload": mock_encrypted_payload
        }

        # 1. Post encrypted click
        res = await client.post("/api/v1/scan/click", json=click_data)
        assert res.status_code in (200, 201), res.text
        data = res.json()
        assert data["is_encrypted"] is True
        assert data["encrypted_payload"] == mock_encrypted_payload
        assert data["url"] == "[ENCRYPTED]"

        # 2. Retrieve encrypted clicks
        res_list = await client.get("/api/v1/scan/clicks", params={"user_email": test_email})
        assert res_list.status_code == 200
        items = res_list.json()
        matching = [item for item in items if item["encrypted_payload"] == mock_encrypted_payload]
        assert len(matching) >= 1
        assert matching[0]["is_encrypted"] is True
        assert matching[0]["user_index_id"] == "IDX-ZKTEST-0001"


@pytest.mark.asyncio
async def test_zk_encrypted_digest_dispatch_and_history():
    """Verify that encrypted 15-day digest dispatch stores and returns encrypted audit logs."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        test_email = "zk_digest_user@safeinbox.test"
        mock_encrypted_digest = "vN4bDigestMockBase64AES256GCMPayload=="

        digest_payload = {
            "user_email": test_email,
            "user_index_id": "IDX-ZKTEST-DIGEST",
            "user_name": "ZK Tester",
            "period_start": "2026-11-01",
            "period_end": "2026-11-15",
            "records": [],
            "url_clicks": [],
            "is_encrypted": True,
            "encrypted_payload": mock_encrypted_digest
        }

        # 1. Send digest request
        res = await client.post("/api/v1/digest/send", json=digest_payload)
        assert res.status_code == 200, res.text
        send_resp = res.json()
        assert send_resp["success"] is True

        # 2. Retrieve digest history
        res_hist = await client.get("/api/v1/digest/history", params={"user_email": test_email})
        assert res_hist.status_code == 200, res_hist.text
        history_items = res_hist.json()
        matching = [h for h in history_items if h.get("encrypted_payload") == mock_encrypted_digest]
        assert len(matching) >= 1
        assert matching[0]["is_encrypted"] is True
        assert matching[0]["user_index_id"] == "IDX-ZKTEST-DIGEST"
