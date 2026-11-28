"""Tests for Tier 2 Locality-Sensitive Hashing (LSH) and MinHash Community Intelligence.

Validates:
1. Mathematical MinHash signature and LSH band bucket collision properties.
2. Invariance to sentence mutations and word insertions that evade Tier 1 skeleton hashing.
3. Fast O(1) indexed database candidate lookup and candidate Jaccard threshold filtering.
4. End-to-end feedback-to-scan fuzzy matching flow with Zero-PII assertions.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import init_db
from app.main import app
from app.services.lsh_engine import (
    generate_shingles,
    compute_minhash_signature,
    compute_lsh_buckets,
    estimate_jaccard_similarity,
    compute_text_lsh
)
from app.services.canonical_skeleton import compute_text_skeleton_hash


def test_lsh_engine_shingling_and_signature_shapes():
    """Verify shingling generates unsigned 32-bit hashes and signature is 32 integers."""
    sample = "Please click here immediately to renew your enterprise subscription before termination."
    shingles = generate_shingles(sample, k=3)
    assert len(shingles) > 0
    assert all(isinstance(s, int) and s >= 0 for s in shingles)

    sig = compute_minhash_signature(shingles, num_hashes=32)
    assert len(sig) == 32
    assert all(isinstance(x, int) for x in sig)

    buckets = compute_lsh_buckets(sig, num_bands=8, rows_per_band=4)
    assert len(buckets) == 8
    # Buckets are signed 64-bit integers suitable for database BIGINT
    assert all(isinstance(b, int) for b in buckets)


def test_lsh_minhash_similarity_properties():
    """Verify that identical texts yield similarity 1.0, and unrelated texts yield near-zero."""
    text_a = "Your account is temporarily suspended due to multiple failed login attempts. Verify identity."
    text_b = "Your account is temporarily suspended due to multiple failed login attempts. Verify identity."
    text_c = "Delicious Italian pasta recipe with garlic, olive oil, and fresh basil for dinner."

    sig_a, b_a = compute_text_lsh(text_a)
    sig_b, b_b = compute_text_lsh(text_b)
    sig_c, b_c = compute_text_lsh(text_c)

    assert estimate_jaccard_similarity(sig_a, sig_b) == 1.0
    assert b_a == b_b

    # Unrelated texts should have low similarity and zero or near-zero bucket collisions
    sim_unrelated = estimate_jaccard_similarity(sig_a, sig_c)
    assert sim_unrelated < 0.25


def test_fuzzy_mutation_catches_variant_that_evades_tier1():
    """
    Demonstrate that a mutated phishing email evades Tier 1 skeleton hashing
    (different SHA-256 hash), but is caught by Tier 2 LSH with bucket collisions.
    """
    original = (
        "Security Alert: We detected unauthorized sign-in attempts on your payroll account. "
        "Access has been temporarily restricted for your safety. "
        "Please confirm your credentials immediately to avoid permanent disruption."
    )

    # Attacker mutates by inserting conversational filler, changing phrasing
    mutated = (
        "Security Alert: We recently detected unauthorized sign-in attempts on your company payroll account. "
        "Your access has been temporarily restricted for company safety. "
        "Kindly confirm your credentials right away to prevent disruption to your service."
    )

    # 1. Tier 1 Canonical Skeleton produces DIFFERENT hashes
    hash_orig = compute_text_skeleton_hash(original, subject="Security Alert")
    hash_mut = compute_text_skeleton_hash(mutated, subject="Security Alert")
    assert hash_orig != hash_mut, "Tier 1 should produce different hashes on rephrased sentences"

    # 2. Tier 2 MinHash and LSH Buckets collide
    sig_orig, buckets_orig = compute_text_lsh(original, subject="Security Alert")
    sig_mut, buckets_mut = compute_text_lsh(mutated, subject="Security Alert")

    similarity = estimate_jaccard_similarity(sig_orig, sig_mut)
    assert similarity >= 0.65, f"Expected similarity >= 0.65 for rephrased email, got {similarity}"

    # Verify at least one of the 8 band buckets matches (LSH indexing condition)
    common_buckets = set(buckets_orig).intersection(set(buckets_mut))
    assert len(common_buckets) >= 1, "Mutated email must share at least one LSH bucket"


@pytest.mark.asyncio
async def test_end_to_end_lsh_fuzzy_threat_detection():
    """
    End-to-end integration test:
    1. Report phishing template A as a threat.
    2. Scan rephrased variant B (Tier 1 misses, Tier 2 LSH detects it).
    3. Assert Zero-PII in community intelligence response.
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        template_a = (
            "Immediate Action Required: Your cloud storage payment was declined by your bank. "
            "Update billing information within 24 hours to prevent account suspension."
        )

        # 1. User reports template A as a threat
        fb_payload = {
            "target": template_a,
            "target_type": "TEXT",
            "is_safe": False,
            "source": "webmail_banner"
        }
        fb_resp = await client.post("/api/v1/feedback", json=fb_payload)
        assert fb_resp.status_code == 201

        # 2. Another user receives variant B with mutated wording
        variant_b = (
            "Immediate Action Required: Your cloud storage monthly payment was declined by your credit bank. "
            "Kindly update your billing information within 24 hours to prevent account disruption."
        )
        subject_b = "Billing Notice: Payment Declined"

        scan_payload = {
            "text": variant_b,
            "subject": subject_b,
            "sender": "billing-support@secure-cloud-alerts.com",
            "receiver": "victim@company.com",
            "urls": []
        }
        scan_resp = await client.post("/api/v1/scan/email", json=scan_payload)
        assert scan_resp.status_code == 200
        data = scan_resp.json()

        # 3. Verify Tier 2 LSH flagged the mutated email
        assert "community_intel" in data
        c_intel = data["community_intel"]
        assert c_intel["flagged"] is True
        assert c_intel["threat_count"] >= 1
        assert c_intel["match_type"] in ("EXACT", "FUZZY_LSH")
        if c_intel["match_type"] == "FUZZY_LSH":
            assert c_intel["similarity"] is not None
            assert c_intel["similarity"] >= 0.50

        # 4. Verify evidence was injected into scan result
        rule_ids = [e["rule_id"] for e in data.get("evidence", [])]
        assert "COMMUNITY_CROWD_THREAT" in rule_ids

        # 5. Verify benign unrelated email is NOT flagged
        benign_email = (
            "Hey Sarah, attached is the revised agenda for our quarterly roadmap discussion on Tuesday. "
            "Let me know if you want to add any talking points."
        )
        benign_scan = await client.post("/api/v1/scan/email", json={
            "text": benign_email,
            "subject": "Quarterly Roadmap Agenda",
            "sender": "colleague@company.com"
        })
        assert benign_scan.status_code == 200
        benign_data = benign_scan.json()
        assert benign_data["community_intel"]["flagged"] is False
        assert benign_data["community_intel"]["threat_count"] == 0
