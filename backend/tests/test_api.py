"""End-to-end API integration tests for SafeInbox AI Backend."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models.threat import FeedbackRecord, ScanAuditLog, ThreatURL


@pytest.mark.asyncio
async def test_health_endpoints():
    """Verify health check endpoints return healthy status and database connection."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["database"] == "connected"

        res_v1 = await client.get("/api/v1/health")
        assert res_v1.status_code == 200
        assert res_v1.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_url_scan_benign_and_caching():
    """Verify benign URL scan, DB caching on subsequent request, and audit log."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        target = "https://en.wikipedia.org/wiki/Computer_security"

        # First request: not cached
        res1 = await client.post("/api/v1/scan/url", json={"url": target})
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["riskLevel"] == "SAFE"
        assert data1["riskScore"] == 0.0
        assert data1["cached"] is False

        # Second request: served from DB cache
        res2 = await client.post("/api/v1/scan/url", json={"url": target})
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["cached"] is True
        assert data2["canonicalUrl"] == data1["canonicalUrl"]

    # Verify record in database
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(ThreatURL).where(ThreatURL.canonical_url == target))
        entry = result.scalars().first()
        assert entry is not None
        assert entry.risk_level == "SAFE"


@pytest.mark.asyncio
async def test_url_scan_phishing_and_injections():
    """Verify homograph, typosquatting, and redirect detection."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Homograph attack
        homograph_res = await client.post("/api/v1/scan/url", json={"url": "https://\u0440\u0430ypal.com/signin"})
        assert homograph_res.status_code == 200
        data_h = homograph_res.json()
        assert "HOMOGRAPH_ATTACK" in data_h["attackTypes"]
        assert data_h["riskScore"] > 0.5

        # Typosquatting attack
        typo_res = await client.post("/api/v1/scan/url", json={"url": "https://paypa1-security.com/update"})
        assert typo_res.status_code == 200
        data_t = typo_res.json()
        assert "TYPOSQUATTING" in data_t["attackTypes"]

        # Open redirect
        redirect_res = await client.post(
            "/api/v1/scan/url",
            json={"url": "https://example.com/login?next=https%3A%2F%2Foutside.example"}
        )
        assert redirect_res.status_code == 200
        data_r = redirect_res.json()
        assert "OPEN_REDIRECT" in data_r["attackTypes"]


@pytest.mark.asyncio
async def test_url_scan_invalid_inputs():
    """Verify validation errors on non-HTTP or empty URLs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Non-HTTP URL
        res = await client.post("/api/v1/scan/url", json={"url": "javascript:alert(1)"})
        assert res.status_code == 422


@pytest.mark.asyncio
async def test_email_scan_spoofing_and_privacy():
    """Verify email spoofing detection and zero raw body retention in DB."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        secret_content = "Confidential secret token XYZ-998877"
        email_payload = {
            "sender": "PayPal Support <security@gmail.com>",
            "receiver": "user@example.test",
            "subject": "URGENT: Your account is suspended",
            "body": f"Please verify your credentials immediately. {secret_content}",
            "urls": ["https://paypal-verification.xyz/login"]
        }

        res = await client.post("/api/v1/scan/email", json=email_payload)
        assert res.status_code == 200
        data = res.json()
        assert data["risk_level"] == "CRITICAL"
        assert "SENDER_SPOOFING" in data["threat_vectors"]
        assert "ARTIFICIAL_URGENCY" in data["threat_vectors"]
        assert "CREDENTIAL_HARVESTING" in data["threat_vectors"]
        assert data["company_intelligence"]["status"] == "IMPERSONATION_MISMATCH"

    # Zero-leak check: audit log stores hash, NOT raw body or secret token!
    async with AsyncSessionLocal() as session:
        logs = (await session.execute(select(ScanAuditLog).where(ScanAuditLog.scan_type == "EMAIL"))).scalars().all()
        assert len(logs) >= 1
        for log in logs:
            assert secret_content not in str(log.__dict__)
            assert "Confidential secret" not in str(log.__dict__)


@pytest.mark.asyncio
async def test_feedback_ingestion():
    """Verify feedback recording for Safe/Threat training datasets."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # URL feedback
        res_url = await client.post("/api/v1/feedback", json={
            "target": "https://suspicious-sample.xyz/auth",
            "is_safe": False,
            "target_type": "URL",
            "source": "sidepanel"
        })
        assert res_url.status_code == 201
        data_u = res_url.json()
        assert data_u["status"] == "recorded"
        assert len(data_u["target_hash"]) == 64

        # Text feedback
        res_text = await client.post("/api/v1/feedback", json={
            "target": "Please verify your payment method within 24 hours.",
            "is_safe": False,
            "target_type": "TEXT",
            "source": "webmail_banner"
        })
        assert res_text.status_code == 201

    # Verify stored in DB
    async with AsyncSessionLocal() as session:
        records = (await session.execute(select(FeedbackRecord))).scalars().all()
        assert len(records) >= 2
        assert any(r.target_type == "URL" for r in records)
        assert any(r.target_type == "TEXT" for r in records)


@pytest.mark.asyncio
async def test_url_and_text_storage_separation_and_filtering():
    """Verify that URL feedback and Text feedback are stored and retrieved with strict separation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest 3 URL samples
        for i in range(3):
            await client.post("/api/v1/feedback", json={
                "target": f"https://sample-domain-{i}.com/login",
                "is_safe": False,
                "target_type": "URL",
                "source": "sidepanel"
            })

        # Ingest 3 Text samples
        for i in range(3):
            await client.post("/api/v1/feedback", json={
                "target": f"Urgent wire transfer request #{i} for financial audit.",
                "is_safe": False,
                "target_type": "TEXT",
                "source": "email_scanner"
            })

        # 1. Fetch URL dataset only - must NOT contain text samples
        res_url = await client.get("/api/v1/feedback?target_type=URL")
        assert res_url.status_code == 200
        url_items = res_url.json()
        assert len(url_items) == 3
        for item in url_items:
            assert item["target_type"] == "URL"
            assert item["target_sample"].startswith("https://")

        # 2. Fetch Text dataset only - must NOT contain URL samples
        res_text = await client.get("/api/v1/feedback?target_type=TEXT")
        assert res_text.status_code == 200
        text_items = res_text.json()
        assert len(text_items) == 3
        for item in text_items:
            assert item["target_type"] == "TEXT"
            assert "wire transfer" in item["target_sample"]


@pytest.mark.asyncio
async def test_training_and_testing_data_zero_leakage():
    """Verify that train, validation, and test datasets are partitioned with zero data leakage."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Insert 25 distinct URL feedback items
        for i in range(25):
            await client.post("/api/v1/feedback", json={
                "target": f"https://dataset-partition-check-{i}.org/portal",
                "is_safe": (i % 2 == 0),
                "target_type": "URL",
                "source": "automated_ingest"
            })

        # Request partitioned splits (80% train, 10% val, 10% test)
        res_split = await client.get("/api/v1/feedback/export-split?target_type=URL&train_ratio=0.8&val_ratio=0.1&test_ratio=0.1")
        assert res_split.status_code == 200
        data = res_split.json()

        assert data["target_type"] == "URL"
        assert data["total_samples"] == 25
        assert data["zero_leakage_verified"] is True

        train_hashes = {item["target_hash"] for item in data["train"]}
        val_hashes = {item["target_hash"] for item in data["val"]}
        test_hashes = {item["target_hash"] for item in data["test"]}

        # Strict disjointness assertions: ZERO overlap between train, val, and test!
        assert len(train_hashes.intersection(test_hashes)) == 0
        assert len(train_hashes.intersection(val_hashes)) == 0
        assert len(val_hashes.intersection(test_hashes)) == 0


@pytest.mark.asyncio
async def test_security_headers_present():
    """Verify that HSTS, CSP, and security defense-in-depth headers are attached."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://testserver") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        headers = res.headers
        assert "strict-transport-security" in headers
        assert "max-age=63072000" in headers["strict-transport-security"]
        assert "includesubdomains" in headers["strict-transport-security"].lower()
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in headers["content-security-policy"]
        assert headers["referrer-policy"] == "strict-origin-when-cross-origin"


@pytest.mark.asyncio
async def test_https_enforcement_and_insecure_http_blocking():
    """Verify that insecure non-HTTPS requests are rejected or redirected when HTTPS is enforced."""
    from app.config import settings

    original_force = settings.FORCE_HTTPS
    settings.FORCE_HTTPS = True
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://api.safeinbox.app") as client:
            # GET request over insecure HTTP: redirected to HTTPS via 308
            res_get = await client.get("/health", headers={"x-forwarded-proto": "http"})
            assert res_get.status_code == 308
            assert res_get.headers["location"].startswith("https://")

            # POST request with data over insecure HTTP: rejected with 403 Forbidden
            res_post = await client.post(
                "/api/v1/scan/url",
                json={"url": "https://example.com"},
                headers={"x-forwarded-proto": "http"}
            )
            assert res_post.status_code == 403
            assert "HTTPS required" in res_post.json()["detail"]
    finally:
        settings.FORCE_HTTPS = original_force
