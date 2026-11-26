"""Security Verification: Guest Access Prevention and IDOR / Cross-User Isolation."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import init_db
from app.main import app


@pytest.mark.asyncio
async def test_unauthenticated_guests_blocked_from_all_data_endpoints():
    """Verify that unauthenticated guests are strictly blocked with 401 Unauthorized from all data and log endpoints."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. URL clicks
        res = await client.get("/api/v1/scan/clicks")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"

        # 2. Scan audits
        res = await client.get("/api/v1/scan/audits")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"

        # 3. Digest history
        res = await client.get("/api/v1/digest/history")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"

        # 4. Digest purge
        res = await client.post("/api/v1/digest/purge")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"

        # 5. Feedback records list
        res = await client.get("/api/v1/feedback")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"

        # 6. Feedback dataset export split
        res = await client.get("/api/v1/feedback/export-split")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"

        # 7. User profile by index ID
        res = await client.get("/api/v1/auth/user-by-index/SAFE-IDX-VICTIM1")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"

        # 8. User tracking summary
        res = await client.get("/api/v1/auth/track/victim@safeinbox.ai")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"


@pytest.mark.asyncio
async def test_idor_and_cross_user_isolation():
    """Verify that authenticated users cannot access, view, or purge another user's data (IDOR prevention)."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register User Alice
        alice_signup = await client.post("/api/v1/auth/signup", json={
            "email": "alice@safeinbox.ai",
            "password": "Xk9#mP2$vL8@qW4!",
            "full_name": "Alice Auditor"
        })
        assert alice_signup.status_code == 201, f"Alice signup failed: {alice_signup.text}"
        alice_data = alice_signup.json()
        alice_token = alice_data["access_token"]
        alice_index = alice_data["user"]["index_id"]
        alice_headers = {"Authorization": f"Bearer {alice_token}"}

        # Register User Bob
        bob_signup = await client.post("/api/v1/auth/signup", json={
            "email": "bob@safeinbox.ai",
            "password": "Zq7*jN4^wY1#tR9?",
            "full_name": "Bob Target"
        })
        assert bob_signup.status_code == 201, f"Bob signup failed: {bob_signup.text}"
        bob_data = bob_signup.json()
        bob_index = bob_data["user"]["index_id"]

        # Alice attempts to query Bob's data -> MUST return 403 Forbidden
        # 1. Clicks by Bob's email
        res = await client.get("/api/v1/scan/clicks", params={"user_email": "bob@safeinbox.ai"}, headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 2. Clicks by Bob's index_id
        res = await client.get("/api/v1/scan/clicks", params={"user_index_id": bob_index}, headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 3. Audits by Bob's email
        res = await client.get("/api/v1/scan/audits", params={"user_email": "bob@safeinbox.ai"}, headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 4. Audits by Bob's index_id
        res = await client.get("/api/v1/scan/audits", params={"user_index_id": bob_index}, headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 5. Digest history by Bob's email
        res = await client.get("/api/v1/digest/history", params={"user_email": "bob@safeinbox.ai"}, headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 6. Digest history by Bob's index_id
        res = await client.get("/api/v1/digest/history", params={"user_index_id": bob_index}, headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 7. Digest purge on Bob's records
        res = await client.post("/api/v1/digest/purge", params={"user_email": "bob@safeinbox.ai"}, headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 8. User profile by Bob's index_id
        res = await client.get(f"/api/v1/auth/user-by-index/{bob_index}", headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 9. User tracking summary by Bob's email
        res = await client.get("/api/v1/auth/track/bob@safeinbox.ai", headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # 10. User tracking summary by Bob's index_id
        res = await client.get(f"/api/v1/auth/track/{bob_index}", headers=alice_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"

        # Alice accesses HER OWN data -> MUST return 200 OK
        res = await client.get("/api/v1/scan/clicks", params={"user_email": "alice@safeinbox.ai"}, headers=alice_headers)
        assert res.status_code == 200

        res = await client.get("/api/v1/scan/clicks", params={"user_index_id": alice_index}, headers=alice_headers)
        assert res.status_code == 200

        res = await client.get("/api/v1/scan/audits", params={"user_email": "alice@safeinbox.ai"}, headers=alice_headers)
        assert res.status_code == 200

        res = await client.get("/api/v1/digest/history", params={"user_email": "alice@safeinbox.ai"}, headers=alice_headers)
        assert res.status_code == 200

        res = await client.post("/api/v1/digest/purge", params={"user_email": "alice@safeinbox.ai"}, headers=alice_headers)
        assert res.status_code == 200

        res = await client.get(f"/api/v1/auth/user-by-index/{alice_index}", headers=alice_headers)
        assert res.status_code == 200
        assert res.json()["email"] == "alice@safeinbox.ai"

        res = await client.get("/api/v1/auth/track/alice@safeinbox.ai", headers=alice_headers)
        assert res.status_code == 200
        assert res.json()["email"] == "alice@safeinbox.ai"

        res = await client.get(f"/api/v1/auth/track/{alice_index}", headers=alice_headers)
        assert res.status_code == 200
        assert res.json()["index_id"] == alice_index
