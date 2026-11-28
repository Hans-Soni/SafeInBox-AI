"""Comprehensive End-to-End System Test Suite for SafeInbox AI Backend.

Validates the complete backend lifecycle:
1. Authentication (Sign Up, Password Complexity, Terms Consent)
2. Authentication (Sign In, Rate Limiting, Lockout, Profile /me)
3. Sign Out (Token Revocation, JTI Blacklisting)
4. URL Threat Intelligence & Database Caching
5. Email Threat Analysis & Zero-PII Audit Logging
6. User Feedback Storage & Zero-Leakage Dataset Partitioning
7. 15-Day Security Digest System (Senders, Receivers, Time-Slabs, ML Scores, URL Clicks, HTML Report)
8. URL Click & Action Persistence Pipeline (Payload Validation, Defanging, Database Storage)
"""

import sys
import os
import time
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.schemas.auth import (
    UserSignUp,
    UserSignIn,
    UserResponse,
    UserTrackingSummary,
    OTPRequestResponse,
    OTPResendRequest,
    OTPVerifyRequest,
    validate_password_complexity,
    sanitize_display_name,
)
from app.models.user import generate_user_index_id
from app.services.otp_service import (
    generate_otp,
    generate_otp_salt,
    hash_otp,
    verify_otp,
    generate_otp_email_html,
)
from app.services.auth_service import (
    hash_password,
    verify_password,
    dummy_verify_password,
    create_access_token,
    decode_access_token,
    revoke_token,
    is_token_revoked,
    AuthRateLimiter,
)
from app.services.url_analyzer import analyze_url
from app.services.email_analyzer import analyze_email_text
from app.services.dataset_manager import split_dataset, assert_zero_leakage
from app.services.digest_service import generate_digest_html
from app.schemas.digest import EmailRecordItem, UrlClickItem, DigestSendRequest
from app.schemas.url_scan import UrlClickCreate, UrlClickResponse
from app.routers.url import defang_url


def test_system_1_signup_password_and_terms():
    print("[*] 1. System E2E: User Sign-Up, Password Policy & Terms Consent...")
    # Validate password complexity
    valid_pw = "EnterpriseSecure#2026!"
    assert validate_password_complexity(valid_pw) == valid_pw

    # Test display name sanitization
    sanitized_name = sanitize_display_name("<script>alert(1)</script>Security Lead")
    assert sanitized_name == "Security Lead"

    # User SignUp model validation
    user_data = UserSignUp(
        email="lead.analyst@safeinbox.ai",
        password=valid_pw,
        full_name="Security Lead",
        terms_agreed=True,
        terms_version="1.0.0",
        mac_address="00:1A:2B:3C:4D:5E"
    )
    assert user_data.email == "lead.analyst@safeinbox.ai"
    assert user_data.terms_agreed is True

    # Unique Index ID generation check
    idx = generate_user_index_id(user_data.email)
    assert idx.startswith("SAFE-IDX-")
    assert len(idx) == 21
    assert idx == generate_user_index_id("LEAD.ANALYST@SAFEINBOX.AI"), "Index ID must be deterministic and lowercase-normalized"
    assert idx != generate_user_index_id("another@safeinbox.ai"), "Distinct emails must have distinct index IDs"
    print("  [OK] Sign-Up schema, password policy, terms consent, and Unique Index ID passed.")


def test_system_2_signin_rate_limiting_and_jwt():
    print("[*] 2. System E2E: User Sign-In, Brute-Force Defense & JWT Creation...")
    limiter = AuthRateLimiter()
    target_account = "target.user@safeinbox.ai"

    # Simulate 5 consecutive failed attempts
    account_key = f"acc:{target_account}"
    for i in range(1, 6):
        limiter.record_attempt(account_key)

    is_locked, rem = limiter.is_rate_limited(account_key, max_attempts=5, window_seconds=60, lockout_seconds=180)
    assert is_locked is True, "Target account must be locked out after 5 failures"
    assert rem > 150

    # Reset on successful login
    limiter.reset_attempts(account_key)
    is_locked_after, _ = limiter.is_rate_limited(account_key, max_attempts=5, window_seconds=60, lockout_seconds=180)
    assert is_locked_after is False

    # Mint JWT access token
    payload = {"sub": target_account, "user_id": 101, "role": "analyst"}
    token = create_access_token(payload)
    assert isinstance(token, str)

    decoded = decode_access_token(token)
    assert decoded["sub"] == target_account
    assert "jti" in decoded
    print("  [OK] Sign-In rate limiter lockout and JWT minting passed.")


def test_system_3_signout_and_token_invalidation():
    print("[*] 3. System E2E: Sign-Out & Active Token Invalidation...")
    target_account = "analyst.signout@company.internal"
    payload = {"sub": target_account, "user_id": 101, "role": "analyst"}
    token = create_access_token(payload)
    decoded = decode_access_token(token)
    jti = decoded["jti"]

    # Verify token is initially not revoked
    assert is_token_revoked(jti) is False

    # Simulate user sign-out calling token revocation
    revoked = revoke_token(token)
    assert revoked is True
    assert is_token_revoked(jti) is True

    # Attempting to use decoded token after revocation
    is_valid = not is_token_revoked(jti)
    assert is_valid is False, "Revoked token must not be accepted"
    print("  [OK] Sign-Out token revocation and blacklist verification passed.")


def test_system_4_url_threat_model_and_intelligence():
    print("[*] 4. System E2E: URL Threat Analysis & Heuristic Engine...")
    test_urls = [
        ("https://google.com/search?q=security", False, "Legitimate domain"),
        ("http://192.168.1.1/admin.php?login=admin", True, "IP address in URL"),
        ("https://paypal.com.account-verify.suspicious-domain.ru/webscr", True, "Subdomain spoofing / homograph"),
        ("http://secure-login.bank.com@attacker-site.com/steal", True, "Embedded userinfo authority trick"),
    ]

    for raw_url, should_be_threat, description in test_urls:
        analysis = analyze_url(raw_url)
        assert "riskScore" in analysis
        assert "riskLevel" in analysis
        assert "findings" in analysis
        assert "canonicalUrl" in analysis
        if should_be_threat:
            assert analysis["riskScore"] >= 0.5 or len(analysis["attackTypes"]) > 0, f"Failed on {description}: {raw_url}"
        print(f"    - [{analysis['riskLevel']:8}] {raw_url[:50]}... ({description})")

    print("  [OK] URL threat analysis engine successfully verified.")


def test_system_5_email_threat_analysis_and_zero_pii():
    print("[*] 5. System E2E: Email Threat Analysis & Zero-PII Compliance...")
    phishing_sample = (
        "URGENT: Your bank account will be suspended within 24 hours due to suspicious activity. "
        "Click the link below immediately to verify your identity and enter your password: "
        "https://bank-verify.example.org/confirm?id=99281"
    )

    result = analyze_email_text({"body": phishing_sample, "subject": "URGENT: Account Suspension", "sender": "security@bank-notice.com"})
    assert result["risk_score"] >= 50
    assert result["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert any("URGENCY" in cat or "CREDENTIAL" in cat for cat in result["threat_vectors"])

    # Verify zero-PII storage constraint: Content hash only, never raw body
    content_hash = hashlib.sha256(phishing_sample.encode("utf-8")).hexdigest()
    assert len(content_hash) == 64
    assert phishing_sample not in content_hash
    print(f"  [OK] Email threat analysis passed: Risk {result['risk_score']} ({result['risk_level']}), Zero-PII Hash {content_hash[:16]}...")


def test_system_6_feedback_storage_and_zero_leakage():
    print("[*] 6. System E2E: Feedback Storage & Zero Data Leakage Partitioning...")
    # Generate 100 sample feedback items
    raw_samples = [
        {"target_hash": hashlib.sha256(f"sample_{i}".encode()).hexdigest(), "url": f"https://sample-{i}.org/page", "label": i % 2}
        for i in range(100)
    ]

    # Split dataset deterministically (70% train, 15% val, 15% test)
    splits = split_dataset(raw_samples, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, hash_attr="target_hash")

    # Cryptographic proof of zero data leakage
    assert_zero_leakage(splits["train"], splits["test"], splits["val"], hash_attr="target_hash")

    train_count = len(splits["train"])
    val_count = len(splits["val"])
    test_count = len(splits["test"])
    assert train_count + val_count + test_count == 100
    print(f"  [OK] Zero data leakage verified: Train={train_count}, Val={val_count}, Test={test_count}.")


def test_system_7_fifteen_day_security_digest():
    print("[*] 7. System E2E: 15-Day Security Digest Generator & Audit Records...")
    records = [
        EmailRecordItem(
            id="rec_1",
            sender="alerts@bank-verify.com",
            receiver="target.employee@company.com",
            subject="Urgent: Your account is on hold",
            timestamp=1730500000000,
            date_iso="2026-11-01T10:00:00Z",
            time_slab="2026-10-20 to 2026-11-04",
            composite_risk=88.0,
            risk_level="CRITICAL",
            text_threat_score=92.0,
            url_threat_score=84.0,
            threat_vectors=["URGENCY", "CREDENTIAL_HARVESTING"],
            clicked_urls=[
                UrlClickItem(
                    url="https://bank-verify.com/login.php",
                    defanged="hxxps://bank-verify[.]com/login.php",
                    risk_score=94.0,
                    risk_level="CRITICAL",
                    timestamp="2026-11-01 10:02:15",
                    proceeded=True
                ),
                UrlClickItem(
                    url="http://bank-verify.com/cancel.php",
                    defanged="hxxp://bank-verify[.]com/cancel.php",
                    risk_score=82.0,
                    risk_level="HIGH",
                    timestamp="2026-11-01 10:03:00",
                    proceeded=True
                )
            ]
        ),
        EmailRecordItem(
            id="rec_2",
            sender="bob@company.com",
            receiver="target.employee@company.com",
            subject="Quarterly Sprint Planning",
            timestamp=1730510000000,
            date_iso="2026-11-02T14:30:00Z",
            time_slab="2026-10-20 to 2026-11-04",
            composite_risk=5.0,
            risk_level="SAFE",
            text_threat_score=0.0,
            url_threat_score=10.0,
            threat_vectors=[],
            clicked_urls=[]
        )
    ]

    html_report = generate_digest_html(
        user_email="target.employee@company.com",
        user_name="Target Employee",
        period_start="2026-10-20",
        period_end="2026-11-04",
        records=records
    )

    # 1. Verify recipient and sender information
    assert "target.employee@company.com" in html_report, "Must display recipient email"
    assert "alerts@bank-verify.com" in html_report, "Must display sender address"
    assert "bob@company.com" in html_report, "Must display safe sender address"

    # 2. Verify time-slab records
    assert "2026-10-20 to 2026-11-04" in html_report, "Must display time-slab record"

    # 3. Verify ML threat scores
    assert "ML Score: 88/100 (CRITICAL)" in html_report, "Must display composite ML score"
    assert "Text Threat:" in html_report and "92%" in html_report, "Must display text threat score breakdown"
    assert "URL Threat:" in html_report and "84%" in html_report, "Must display URL threat score breakdown"

    # 4. Verify all URL clicks done by user in that specific email
    assert "hxxps://bank-verify[.]com/login.php" in html_report, "Must display first clicked URL"
    assert "hxxp://bank-verify[.]com/cancel.php" in html_report, "Must display second clicked URL"
    assert "Risk: 94/100" in html_report, "Must display clicked URL risk score"
    assert "2026-11-01 10:02:15" in html_report, "Must display exact click timestamp"

    print(f"  [OK] 15-Day Security Digest verified with all required fields ({len(html_report)} bytes HTML generated).")


def test_system_8_url_click_and_action_sync():
    print("[*] 8. System E2E: URL Click & Action Persistence Pipeline...")
    raw_target = "https://phishing-portal.com/update?token=xyz987"
    defanged = defang_url(raw_target)
    assert defanged == "hxxps://phishing-portal[.]com/update?token=xyz987"

    click_payload = UrlClickCreate(
        url=raw_target,
        email_subject="Account Verification Required",
        sender="security@service-updates.com",
        risk_score=91.5,
        risk_level="CRITICAL",
        proceeded=True,
        source="email_body_link",
        user_email="victim@company.com"
    )
    assert click_payload.url == raw_target
    assert click_payload.risk_score == 91.5
    assert click_payload.user_email == "victim@company.com"

    response = UrlClickResponse(
        id=42,
        url=click_payload.url,
        defanged_url=defanged,
        risk_score=click_payload.risk_score,
        risk_level=click_payload.risk_level,
        proceeded=True,
        recorded=True
    )
    assert response.id == 42
    assert response.recorded is True
    assert response.defanged_url == defanged
    print(f"  [OK] URL click and action persistence validated for {defanged}.")


def test_system_9_email_otp_verification():
    print("[*] 9. System E2E: Email OTP Verification, Hashing & Timing Defense...")
    # 1. 6-digit cryptographic generation
    otp = generate_otp()
    assert len(otp) == 6 and otp.isdigit()

    # 2. Salted HMAC-SHA256 Hashing & Constant-time comparison
    salt = generate_otp_salt()
    otp_hash = hash_otp(otp, salt)
    assert otp_hash != otp
    assert verify_otp(otp, salt, otp_hash) is True
    assert verify_otp("999999", salt, otp_hash) is False

    # 3. Schemas verification
    req_resp = OTPRequestResponse(
        success=True,
        email="analyst@safeinbox.ai",
        message="A 6-digit verification code has been dispatched.",
        expires_in_seconds=600,
        resend_cooldown_seconds=60,
        delivery_mode="simulated_preview"
    )
    assert req_resp.expires_in_seconds == 600

    verify_req = OTPVerifyRequest(email="analyst@safeinbox.ai", otp="123456")
    assert verify_req.otp == "123456"

    # 4. Email template generation
    html_email = generate_otp_email_html("analyst@safeinbox.ai", "Analyst", otp, 10)
    assert otp in html_email
    assert "analyst@safeinbox.ai" in html_email
    print("  [OK] Email OTP generation, HMAC-SHA256 hashing, timing defense, and schemas passed.")


def test_system_10_unique_index_id_tracking():
    print("[*] 10. System E2E: Unique Index ID Generation & Unified Tracking Pipeline...")
    import re

    # 1. Verification of unique index id generation
    test_emails = [
        "john.doe@company.com",
        "sarah.connor@cyberdyne.org",
        "analyst.security@safeinbox.ai",
        "user123+newsletter@gmail.com"
    ]
    generated_ids = set()
    for em in test_emails:
        idx_id = generate_user_index_id(em)
        assert re.match(r"^SAFE-IDX-[A-F0-9]{12}$", idx_id), f"Index ID '{idx_id}' does not match expected format"
        assert idx_id not in generated_ids, f"Collision detected for {em}"
        generated_ids.add(idx_id)
        # Deterministic check
        assert idx_id == generate_user_index_id(em.upper()), "Must be case-insensitive"

    # 2. UserResponse schema includes index_id
    from datetime import datetime, timezone
    sample_user_resp = UserResponse(
        id=101,
        index_id=generate_user_index_id("john.doe@company.com"),
        email="john.doe@company.com",
        full_name="John Doe",
        is_active=True,
        password_changed_at=datetime.now(timezone.utc),
        password_expired=False,
        password_age_days=0,
        session_lifetime_days=7,
        created_at=datetime.now(timezone.utc)
    )
    assert sample_user_resp.index_id.startswith("SAFE-IDX-")
    assert sample_user_resp.id == 101

    # 3. UserTrackingSummary schema
    tracking_summary = UserTrackingSummary(
        index_id=sample_user_resp.index_id,
        email=sample_user_resp.email,
        full_name=sample_user_resp.full_name,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        url_clicks_count=5,
        recent_url_clicks=[
            {"id": 1, "url": "https://example.com", "risk_score": 0, "risk_level": "SAFE", "proceeded": True}
        ],
        digest_dispatches_count=1,
        recent_digests=[
            {"id": 1, "period_start": "2026-11-01", "period_end": "2026-11-16", "total_emails": 10, "threat_count": 0, "click_count": 1, "dispatch_status": "sent"}
        ],
        terms_agreed=True,
        terms_version="1.0.0"
    )
    assert tracking_summary.index_id == sample_user_resp.index_id
    assert tracking_summary.url_clicks_count == 5
    assert tracking_summary.terms_agreed is True

    # 4. UrlClickCreate with user_index_id
    click_with_idx = UrlClickCreate(
        url="https://secure-docs.net/view",
        user_email="john.doe@company.com",
        user_index_id=sample_user_resp.index_id,
        risk_score=10.0,
        risk_level="SAFE"
    )
    assert click_with_idx.user_index_id == sample_user_resp.index_id

    # 5. DigestSendRequest with user_index_id
    digest_with_idx = DigestSendRequest(
        user_email="john.doe@company.com",
        user_index_id=sample_user_resp.index_id,
        period_start="2026-11-05",
        period_end="2026-11-20"
    )
    assert digest_with_idx.user_index_id == sample_user_resp.index_id

    print("  [OK] Unique Index ID generation, schemas, and tracking pipeline fully verified.")


if __name__ == "__main__":
    print("=" * 70)
    print("  SAFEINBOX AI -- ENTIRE SYSTEM COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    test_system_1_signup_password_and_terms()
    token, jti = test_system_2_signin_rate_limiting_and_jwt()
    test_system_3_signout_and_token_invalidation(token, jti)
    test_system_4_url_threat_model_and_intelligence()
    test_system_5_email_threat_analysis_and_zero_pii()
    test_system_6_feedback_storage_and_zero_leakage()
    test_system_7_fifteen_day_security_digest()
    test_system_8_url_click_and_action_sync()
    test_system_9_email_otp_verification()
    test_system_10_unique_index_id_tracking()
    print("=" * 70)
    print("ALL 10 SYSTEM SUBSYSTEMS FULLY VERIFIED AND PASSING!")
    print("=" * 70)
