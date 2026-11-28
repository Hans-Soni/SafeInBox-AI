"""Test Suite for Privacy-Preserving Community Threat Intelligence (CrowdShield Tier 1)."""

import time

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import init_db
from app.main import app
from app.services.canonical_skeleton import (
    compute_canonical_url,
    compute_canonical_url_hash,
    compute_text_skeleton,
    compute_text_skeleton_hash
)


def test_canonical_text_skeleton_mutation_resilience():
    """Verify that email text mutations (amounts, dates, names, tracking links) yield identical skeleton hashes."""
    email_a = (
        "Dear Alice,\n\n"
        "Your account is scheduled for immediate suspension on 2026-11-20. "
        "An overdue payment of $450.00 is required for invoice #INV-98214. "
        "Please confirm your credentials at https://secure-verify.com/portal?token=94821a&session=123 "
        "immediately or your data will be permanently terminated.\n\n"
        "Thank you,\nAccount Security Dept"
    )

    email_b = (
        "Dear Bob,\n\n"
        "Your account is scheduled for immediate suspension on 2026-12-05. "
        "An overdue payment of $1,250.50 is required for invoice #INV-33109. "
        "Please confirm your credentials at https://secure-verify.com/portal?token=bbb999&session=999 "
        "immediately or your data will be permanently terminated.\n\n"
        "Thank you,\nAccount Security Dept"
    )

    skeleton_a = compute_text_skeleton(email_a, "Immediate Account Suspension")
    skeleton_b = compute_text_skeleton(email_b, "Immediate Account Suspension")

    hash_a = compute_text_skeleton_hash(email_a, "Immediate Account Suspension")
    hash_b = compute_text_skeleton_hash(email_b, "Immediate Account Suspension")

    # Both skeletons must have masked tokens and match identically
    assert "[amount]" in skeleton_a.lower() or "[amount]" in skeleton_a
    assert "[url]" in skeleton_a.lower() or "[url]" in skeleton_a
    assert skeleton_a == skeleton_b
    assert hash_a == hash_b


def test_canonical_url_normalization():
    """Verify that tracking parameters and port differences collapse into the identical canonical URL hash."""
    url_1 = "https://phish-portal.example.org:443/login.php?token=xyz123&utm_source=newsletter&utm_medium=email"
    url_2 = "https://www.phish-portal.example.org/login.php?utm_medium=email&utm_source=newsletter&token=abc999"

    canonical_1 = compute_canonical_url(url_1)
    canonical_2 = compute_canonical_url(url_2)

    hash_1 = compute_canonical_url_hash(url_1)
    hash_2 = compute_canonical_url_hash(url_2)

    assert canonical_1 == canonical_2
    assert hash_1 == hash_2


@pytest.mark.asyncio
async def test_community_feedback_and_scan_intelligence_flow():
    """Verify that user feedback records crowd consensus and alerts subsequent scans with zero PII disclosure."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Step 1: User 1 flags an email phishing template
        phish_text_1 = (
            "Dear Customer, Your PayPal account #49102 has been locked on 2026-11-25. "
            "Click here to unlock: https://fake-paypal.com/verify?token=xyz "
            "Failure to pay the $50 fee will result in legal action."
        )

        res_fb1 = await client.post("/api/v1/feedback", json={
            "target": phish_text_1,
            "is_safe": False,
            "target_type": "TEXT",
            "source": "sidepanel_banner"
        })
        assert res_fb1.status_code == 201
        data_fb1 = res_fb1.json()
        assert data_fb1["community_intel"]["threat_count"] == 1
        assert data_fb1["community_intel"]["flagged"] is True

        # Step 2: User 2 flags a mutated version of the same campaign
        phish_text_2 = (
            "Dear Customer, Your PayPal account #88219 has been locked on 2026-12-02. "
            "Click here to unlock: https://fake-paypal.com/verify?token=abc "
            "Failure to pay the $150 fee will result in legal action."
        )

        res_fb2 = await client.post("/api/v1/feedback", json={
            "target": phish_text_2,
            "is_safe": False,
            "target_type": "TEXT",
            "source": "sidepanel_banner"
        })
        assert res_fb2.status_code == 201
        data_fb2 = res_fb2.json()
        assert data_fb2["community_intel"]["threat_count"] == 2

        # Step 3: User 3 scans a third variant of the template -> MUST receive community alert
        phish_text_3 = (
            "Dear Customer, Your PayPal account #99001 has been locked on 2026-12-10. "
            "Click here to unlock: https://fake-paypal.com/verify?token=def "
            "Failure to pay the $250 fee will result in legal action."
        )

        scan_res = await client.post("/api/v1/scan/email", json={
            "sender": "Service <alert@fake-service.xyz>",
            "subject": "Urgent Notice",
            "text": phish_text_3
        })
        assert scan_res.status_code == 200
        scan_data = scan_res.json()

        # Assert community intelligence is populated
        intel = scan_data["community_intel"]
        assert intel is not None
        assert intel["flagged"] is True
        assert intel["threat_count"] >= 2
        assert intel["consensus"] == "THREAT"
        assert "SafeInbox AI users reported this email template as a threat" in intel["message"]

        # Zero-PII assertions: verify no user identity leakage
        assert "user_email" not in intel
        assert "user_id" not in intel
        assert "index_id" not in intel
        assert "email" not in intel

        # Verify evidence list contains the community rule
        rule_ids = [e["rule_id"] for e in scan_data["evidence"]]
        assert "COMMUNITY_CROWD_THREAT" in rule_ids


@pytest.mark.asyncio
async def test_community_url_feedback_and_scan_flow():
    """Verify community threat intelligence on URLs with volatile parameter resilience."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reported_url = "https://credential-stealer.org/login.php?session=abc12345&utm_source=phish"

        # 1. Report URL as threat
        fb_res = await client.post("/api/v1/feedback", json={
            "target": reported_url,
            "is_safe": False,
            "target_type": "URL",
            "source": "webmail_banner"
        })
        assert fb_res.status_code == 201

        # 2. Scan same base URL with different session parameter
        victim_url = "https://credential-stealer.org/login.php?session=xyz98765"
        scan_res = await client.post("/api/v1/scan/url", json={"url": victim_url})
        assert scan_res.status_code == 200
        data = scan_res.json()

        intel = data.get("community_intel")
        assert intel is not None
        assert intel["flagged"] is True
        assert intel["threat_count"] == 1
        assert "link as a threat" in intel["message"]


@pytest.mark.asyncio
async def test_community_in_memory_cache_synchronization():
    """Verify high-speed in-memory cache hit rate and real-time synchronization on feedback update."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        test_url = "https://speed-test-malicious-domain.com/login?token=abc1"

        # 1. Report threat
        fb1 = await client.post("/api/v1/feedback", json={
            "target": test_url,
            "is_safe": False,
            "target_type": "URL",
            "source": "webmail_banner"
        })
        assert fb1.status_code == 201

        # 2. Scan 1 -> populates / reads from memory cache
        t0 = time.perf_counter()
        scan1 = await client.post("/api/v1/scan/url", json={"url": test_url})
        t1 = time.perf_counter()
        assert scan1.status_code == 200
        assert scan1.json()["community_intel"]["threat_count"] == 1

        # 3. Scan 2 -> hits in-memory cache directly with near-zero latency
        t2 = time.perf_counter()
        scan2 = await client.post("/api/v1/scan/url", json={"url": test_url})
        t3 = time.perf_counter()
        assert scan2.status_code == 200
        assert scan2.json()["community_intel"]["threat_count"] == 1
        # Memory cache hit should execute extremely fast
        assert (t3 - t2) <= (t1 - t0) + 0.1

        # 4. Immediate feedback 2 -> must immediately synchronize cache with count=2
        fb2 = await client.post("/api/v1/feedback", json={
            "target": test_url,
            "is_safe": False,
            "target_type": "URL",
            "source": "webmail_banner"
        })
        assert fb2.status_code == 201

        # 5. Scan 3 -> immediately sees synchronized threat_count=2
        scan3 = await client.post("/api/v1/scan/url", json={"url": test_url})
        assert scan3.status_code == 200
        assert scan3.json()["community_intel"]["threat_count"] == 2

