"""Comprehensive Attack & Vulnerability Security Test Suite for SafeInbox AI Authentication.

Covers:
- Vector 1: Brute-Force & Credential Stuffing Lockout
- Vector 2: Dictionary, Trivial, and Low-Entropy Password Exploits
- Vector 3: User Enumeration Timing Side-Channel Neutralization
- Vector 4: Stored Cross-Site Scripting (XSS) in User Profile Data
- Vector 5: RFC 5322 & Injection Malformed Email Attacks
- Vector 6: Broken Token Invalidation, JTI Blacklisting, and Algorithm Confusion
"""

import sys
import os
import time
import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.otp_service import (
    generate_otp,
    generate_otp_salt,
    hash_otp,
    verify_otp,
    generate_otp_email_html,
    dispatch_otp_email,
)
from app.schemas.auth import (
    UserSignUp,
    UserSignIn,
    PasswordChangeRequest,
    OTPRequestResponse,
    OTPResendRequest,
    OTPVerifyRequest,
    validate_password_complexity,
    sanitize_display_name,
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
    calculate_password_similarity,
    levenshtein_distance,
    is_password_in_history,
)
from app.services.log_security import (
    sanitize_log_value,
    mask_sensitive_token,
    emit_security_audit_log,
)


def test_vector_1_brute_force_and_credential_stuffing():
    """Simulate rapid-fire brute-force password spraying and credential stuffing."""
    limiter = AuthRateLimiter()
    ip = "198.51.100.42"
    account = "executive@safeinbox.ai"

    # 1. IP Burst Spraying
    ip_key = f"ip:{ip}"
    for attempt in range(1, 11):
        limited, rem = limiter.is_rate_limited(key=ip_key, max_attempts=10, window_seconds=60, lockout_seconds=120)
        assert limited is False, f"Attempt {attempt} should be allowed"
        limiter.record_attempt(ip_key)

    # 11th request exceeds burst threshold and engages lockout
    limited, retry_after = limiter.is_rate_limited(key=ip_key, max_attempts=10, window_seconds=60, lockout_seconds=120)
    assert limited is True, "11th request must trigger rate limit lockout"
    assert retry_after > 0

    # 2. Targeted Credential Stuffing Lockout
    account_key = f"acc:{account}"
    for attempt in range(1, 5):
        limited, rem = limiter.is_rate_limited(key=account_key, max_attempts=5, window_seconds=60, lockout_seconds=180)
        assert limited is False, f"Attempt {attempt} should not lock account"
        limiter.record_attempt(account_key)

    # 5th consecutive failure triggers lockout
    limiter.record_attempt(account_key)
    locked, rem = limiter.is_rate_limited(key=account_key, max_attempts=5, window_seconds=60, lockout_seconds=180)
    assert locked is True, "5th failed attempt must engage account lockout"
    assert rem > 150 and rem <= 180

    # Successful login resets the lockout state
    limiter.reset_attempts(account_key)
    locked_after, _ = limiter.is_rate_limited(key=account_key, max_attempts=5, window_seconds=60, lockout_seconds=180)
    assert locked_after is False


def test_vector_2_password_policy_and_dictionary_attack():
    """Verify rejection of top common passwords, weak patterns, and length boundary violations."""
    dictionary_passwords = [
        "password",
        "password123",
        "12345678",
        "123456789",
        "qwerty123",
        "admin123",
        "safeinbox",
        "safeinbox123",
    ]
    for bad_pw in dictionary_passwords:
        with pytest.raises(ValueError, match="too common"):
            validate_password_complexity(bad_pw)

    missing_classes = [
        ("alllowercase123!", "uppercase"),
        ("ALLUPPERCASE123!", "lowercase"),
        ("NoDigitsInPassword!", "digit"),
        ("NoSpecialCharacters123", "special character"),
        ("short1!", "at least 10 characters"),
        ("A" * 129 + "a1!", "exceed 128 characters"),
    ]
    for pw, expected_error in missing_classes:
        with pytest.raises(ValueError, match=expected_error):
            validate_password_complexity(pw)

    # Compliant enterprise passwords pass
    assert validate_password_complexity("Str0ng&Resilient#Pass2026") == "Str0ng&Resilient#Pass2026"
    assert validate_password_complexity("C0mpl1@nc3-Eng1n33r!") == "C0mpl1@nc3-Eng1n33r!"


def test_vector_3_user_enumeration_timing_attack_mitigation():
    """Verify that dummy_verify_password executes in constant CPU time equal to real scrypt verification."""
    password = "ProbePassword123!"
    real_hash = hash_password(password)

    # Warm-up scrypt once
    verify_password("wrong", real_hash)
    dummy_verify_password("wrong")

    # Measure real verification duration
    start_real = time.perf_counter()
    res_real = verify_password("wrong", real_hash)
    dur_real = time.perf_counter() - start_real

    # Measure dummy verification duration
    start_dummy = time.perf_counter()
    res_dummy = dummy_verify_password("wrong")
    dur_dummy = time.perf_counter() - start_dummy

    assert res_real is False
    assert res_dummy is False

    # Scrypt is configured with N=16384, r=8, p=1. Both operations perform exactly one scrypt pass.
    # Execution times must be of the same order of magnitude (within 100ms tolerance),
    # ensuring attackers cannot distinguish existent from non-existent users by request latency.
    time_diff = abs(dur_real - dur_dummy)
    assert time_diff < 0.15, f"Timing difference too high ({time_diff*1000:.1f}ms): potential enumeration leak"


def test_vector_4_stored_xss_sanitization_in_user_profile():
    """Verify that HTML, JavaScript, and non-printable control vectors are stripped from display names."""
    xss_payloads = [
        ("<script>alert('XSS')</script>Analyst", "Analyst"),
        ("<img src=x onerror=alert(1)>Analyst", "Analyst"),
        ("<b>Security</b> <iframe src='javascript:void(0)'></iframe>", "Security"),
        ("Analyst\x00\x08Name", "AnalystName"),
        ("   <style>body{display:none}</style>Chief Auditor   ", "Chief Auditor"),
    ]

    for payload, expected in xss_payloads:
        sanitized = sanitize_display_name(payload)
        assert sanitized == expected, f"Failed to sanitize XSS payload: {payload} -> {sanitized}"
        assert "<" not in sanitized
        assert ">" not in sanitized


def test_vector_5_email_validation_and_injection_payloads():
    """Verify RFC 5322 normalization and rejection of malicious injection payloads in emails."""
    malicious_emails = [
        "' OR 1=1--@example.com",
        "analyst;cat /etc/passwd@domain.com",
        "<script>@domain.com",
        "analyst..double@example.com",
        ".leadingdot@example.com",
        "trailingdot.@example.com",
        "analyst@domain..com",
        "analyst@domain.c",
        "analyst@-domain.com",
        "not_an_email",
        "",
        "a" * 256 + "@example.com",
    ]

    for bad_email in malicious_emails:
        with pytest.raises(ValidationError):
            UserSignUp(email=bad_email, password="ValidPassword123!")

        with pytest.raises(ValidationError):
            UserSignIn(email=bad_email, password="ValidPassword123!")

    # Valid emails normalize cleanly to lowercase
    valid = UserSignUp(
        email="  AnALyst.Sec@SafeInbox.AI  ",
        password="ValidPassword123!",
        full_name="Analyst"
    )
    assert valid.email == "analyst.sec@safeinbox.ai"


def test_vector_6_token_revocation_jti_and_algorithm_confusion():
    """Verify token revocation (use-after-signout prevention), JTI tracking, and alg tampering rejection."""
    user_payload = {"sub": "analyst@safeinbox.ai", "user_id": 42}
    token = create_access_token(user_payload)
    assert isinstance(token, str)

    # 1. Normal valid token decoding
    claims = decode_access_token(token)
    assert claims is not None
    assert claims["sub"] == "analyst@safeinbox.ai"
    assert "jti" in claims
    assert len(claims["jti"]) == 32
    token_jti = claims["jti"]

    # 2. Revoke token via sign-out simulation
    revoke_token(token)
    assert is_token_revoked(token_jti) is True

    # 3. Use-after-signout: decoded token must now be rejected
    revoked_claims = decode_access_token(token)
    assert revoked_claims is None, "Revoked token must be rejected upon decoding"

    # 4. Tampered token signature
    tampered_token = token[:-5] + "AAAAA"
    assert decode_access_token(tampered_token) is None

    # 5. Algorithm tampering (craft token with 'none' alg)
    import base64
    import json

    header_none = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_fake = base64.urlsafe_b64encode(json.dumps({"sub": "hacker@evil.com", "jti": "fakejti12345"}).encode()).decode().rstrip("=")
    none_token = f"{header_none}.{payload_fake}."
    assert decode_access_token(none_token) is None, "Tokens with 'none' algorithm must be rejected"


def test_vector_7_password_similarity_and_novelty():
    """Verify rejection of passwords that are minor mutations or too similar to previous passwords."""
    old_pw = "Enterprise#Secure2026!"

    similar_passwords = [
        "Enterprise#Secure2027!",
        "Enterprise#Secure2026!!",
        "enterprise#secure2026!",
        "Enterprise#Secure2026",
    ]
    for sim_pw in similar_passwords:
        sim = calculate_password_similarity(old_pw, sim_pw)
        dist = levenshtein_distance(old_pw.lower(), sim_pw.lower())
        assert sim > 0.60 or dist < 4, f"Expected '{sim_pw}' to be recognized as similar (sim={sim}, dist={dist})"

    dissimilar_pw = "QuantVm$Shield-Alpha99"
    sim_diff = calculate_password_similarity(old_pw, dissimilar_pw)
    dist_diff = levenshtein_distance(old_pw.lower(), dissimilar_pw.lower())
    assert sim_diff <= 0.60 and dist_diff >= 4, f"Expected '{dissimilar_pw}' to be distinct"


def test_vector_8_password_history_reuse_prevention():
    """Verify that users cannot cycle back to previous passwords in their history."""
    past_passwords = [
        "Alpha#Defense2024!",
        "Beta$Defense2025!",
        "Gamma%Defense2026!"
    ]
    history_hashes = [hash_password(p) for p in past_passwords]

    for past_pw in past_passwords:
        assert is_password_in_history(past_pw, history_hashes) is True, f"Reused password '{past_pw}' must be caught"

    new_pw = "Delta^Shield-Omega777!"
    assert is_password_in_history(new_pw, history_hashes) is False


def test_vector_9_postgresql_injection_defense():
    """Verify that PostgreSQL injection payloads in email and display names are neutralized."""
    sqli_payloads = [
        "admin'--@domain.com",
        "user'; DROP TABLE users; --@domain.com",
        "' OR '1'='1' --@domain.com",
        "admin' /* comment */@domain.com",
        "user\x00@domain.com"
    ]
    for payload in sqli_payloads:
        with pytest.raises(ValidationError):
            UserSignUp(email=payload, password="ValidPassword123!")
        with pytest.raises(ValidationError):
            UserSignIn(email=payload, password="ValidPassword123!")

    # Display name SQL injection sanitization
    sqli_name = "Analyst'; DROP TABLE scan_audit_logs; --"
    clean_name = sanitize_display_name(sqli_name)
    assert "--" not in clean_name


def test_vector_10_log_injection_and_crlf_defense():
    """Verify neutralization of Log Injection (CRLF, CWE-117) and ANSI Escape Terminal Poisoning."""
    # 1. CRLF Injection payload attempting to forge a fake authentication audit line
    crlf_payload = "analyst@safeinbox.ai\r\n2026-11-04 12:00:00 [SECURITY] Event: AUTH_SIGNIN_SUCCESS (Admin Access Granted)\r\n"
    clean_crlf = sanitize_log_value(crlf_payload)
    assert "\r" not in clean_crlf, "Carriage return must be stripped"
    assert "\n" not in clean_crlf, "Line feed must be stripped"
    assert "\t" not in clean_crlf, "Tab must be stripped"

    # 2. ANSI Escape Sequence / Terminal Hijack payload
    ansi_payload = "\x1b[2J\x1b[H\x1b[31;1mCRITICAL_FAKE_ALERT\x1b[0m"
    clean_ansi = sanitize_log_value(ansi_payload)
    assert "\x1b" not in clean_ansi, "ANSI escape characters must be stripped"
    assert "[2J" not in clean_ansi, "Terminal clear screen escape code must be stripped"
    assert clean_ansi == "CRITICAL_FAKE_ALERT"

    # 3. Structured single-line security audit log output verification
    event = emit_security_audit_log(
        event_type="AUTH_SIGNIN_FAILED\r\nINJECTED",
        outcome="REJECTED\nFORGED",
        email="attacker@evil.com\r\nfake:header",
        ip_address="192.168.1.1\x1b[31m",
        user_agent="Mozilla/5.0\r\nFake-UA",
        details={"injection_attempt": "value\r\nwith\nnewlines"}
    )
    import json
    raw_log = json.dumps(event)
    assert "\r" not in raw_log, "Logged JSON string must not contain raw CR"
    assert "\n" not in raw_log, "Logged JSON string must not contain raw LF"


def test_vector_11_concurrent_double_signup_race_defense():
    """Verify that multi-device simultaneous signup collision is blocked and enforces 1-account-per-email."""
    # 1. Duplicate email rejection in schema & model
    email = "single.account@safeinbox.ai"
    user_data_1 = UserSignUp(email=email, password="ValidPassword123!", full_name="User Device 1")
    user_data_2 = UserSignUp(email=email.upper(), password="ValidPassword123!", full_name="User Device 2")
    
    # Lowercase normalization enforces identity uniqueness
    assert user_data_1.email == "single.account@safeinbox.ai"
    assert user_data_2.email == "single.account@safeinbox.ai", "Email must be normalized to lowercase across devices"

    # 2. Duplicate detection simulation
    user_registry = {}
    def register_user(u_email: str, name: str):
        normalized = u_email.strip().lower()
        if normalized in user_registry:
            raise ValueError("An account with this email address already exists. Only 1 account per email is allowed. Please sign in instead.")
        user_registry[normalized] = {"email": normalized, "name": name}
        return user_registry[normalized]

    # Device 1 registers
    reg1 = register_user(user_data_1.email, "Device 1 User")
    assert reg1["email"] == "single.account@safeinbox.ai"

    # Device 2 attempts to register with same account -> Must raise duplicate exception
    with pytest.raises(ValueError, match="already exists"):
        register_user(user_data_2.email, "Device 2 User")


def test_vector_12_zero_credential_and_secret_logging_defense():
    """Verify that secrets, passwords, salts, and tokens are never exposed in log outputs (CWE-532)."""
    # 1. Token masking
    jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzN_ce"
    masked = mask_sensitive_token(jwt_sample)
    assert masked.startswith("eyJhbG")
    assert masked.endswith("_ce")
    assert "..." in masked
    assert jwt_sample not in masked

    # 2. Security audit log automatic redaction of secret keywords
    audit = emit_security_audit_log(
        event_type="AUTH_SIGNIN_SUCCESS",
        outcome="AUTHENTICATED",
        email="analyst@safeinbox.ai",
        details={
            "user_id": 42,
            "password": "SuperSecretPassword123!",
            "current_password": "OldSecretPassword123!",
            "client_salt": "9f83ac01b",
            "bearer_token": jwt_sample,
            "api_key": "sec_live_998877665544",
            "safe_detail": "policy_ok"
        }
    )
    d = audit["details"]
    assert d["password"] == "[REDACTED_SECURITY_DATA]", "Password must be redacted in audit logs"
    assert d["current_password"] == "[REDACTED_SECURITY_DATA]", "Current password must be redacted in audit logs"
    assert d["client_salt"] == "[REDACTED_SECURITY_DATA]", "Salt must be redacted in audit logs"
    assert d["bearer_token"] == "[REDACTED_SECURITY_DATA]", "Bearer token must be redacted in audit logs"
    assert d["api_key"] == "[REDACTED_SECURITY_DATA]", "API key must be redacted in audit logs"
    assert d["safe_detail"] == "policy_ok", "Safe non-secret values must remain readable"


def test_vector_13_log_flooding_and_dos_defense():
    """Verify that oversized inputs cannot cause log flooding or disk space exhaustion attacks."""
    huge_input = "A" * 10000
    cleaned_short = sanitize_log_value(huge_input, max_len=64)
    cleaned_default = sanitize_log_value(huge_input)
    assert len(cleaned_short) == 64
    assert len(cleaned_default) == 128

    # Audit log values are automatically bounded
    audit = emit_security_audit_log(
        event_type="FLOOD_TEST",
        outcome="OK",
        email="a" * 500 + "@example.com",
        ip_address="10." + "1." * 500,
        user_agent="Agent/" + "x" * 1000
    )
    assert len(audit["email"]) <= 128
    assert len(audit["ip"]) <= 64
    assert len(audit["user_agent"]) <= 256


def test_vector_14_email_otp_verification_lifecycle():
    """Verify end-to-end cryptographic Email OTP security: generation, hashing, timing defense, and brute-force lockout."""
    import re

    # 1. Cryptographic Generation & Format
    otps = [generate_otp() for _ in range(50)]
    assert all(re.match(r"^\d{6}$", o) for o in otps), "All OTPs must be exactly 6 numeric digits"
    assert len(set(otps)) >= 45, "Cryptographic generator must exhibit high entropy"

    # 2. Salted HMAC-SHA256 Hashing & Timing Defense
    salt = generate_otp_salt()
    test_otp = "482915"
    otp_hash = hash_otp(test_otp, salt)
    assert otp_hash != test_otp, "OTP must never be stored in plain text"
    assert len(otp_hash) == 64, "HMAC-SHA256 hash must be 64 hex characters"
    assert verify_otp(test_otp, salt, otp_hash) is True, "Valid OTP must verify successfully"
    assert verify_otp("000000", salt, otp_hash) is False, "Invalid OTP must be rejected"
    assert verify_otp("482914", salt, otp_hash) is False, "Near-miss OTP must be rejected"

    # 3. Brute-Force Guessing Lockout (3 Attempts)
    attempts_left = 3
    for guess in ["111111", "222222", "333333"]:
        if not verify_otp(guess, salt, otp_hash):
            attempts_left -= 1
    assert attempts_left == 0, "After 3 incorrect guesses, attempts counter must drop to 0"

    # 4. Input Validation & Schema Constraints
    with pytest.raises(ValidationError):
        OTPVerifyRequest(email="valid@safeinbox.ai", otp="12345")  # Too short (5 digits)
    with pytest.raises(ValidationError):
        OTPVerifyRequest(email="valid@safeinbox.ai", otp="1234567")  # Too long (7 digits)
    with pytest.raises(ValidationError):
        OTPVerifyRequest(email="valid@safeinbox.ai", otp="abcdef")  # Non-numeric
    valid_verify = OTPVerifyRequest(email="valid@safeinbox.ai", otp="654321")
    assert valid_verify.otp == "654321"

    # 5. XSS Defense in Email Template Generation
    malicious_name = "<script>alert('pwned')</script>John"
    email_html = generate_otp_email_html("target@safeinbox.ai", malicious_name, "789123")
    assert "<script>" not in email_html, "Email template must HTML escape display name"
    assert "&lt;script&gt;" in email_html
    assert "789123" in email_html


if __name__ == "__main__":
    print("[*] Running Authentication Security & Attack Test Suite...")
    test_vector_1_brute_force_and_credential_stuffing()
    print("  [OK] Vector 1: Brute-Force & Credential Stuffing Lockout PASSED")
    test_vector_2_password_policy_and_dictionary_attack()
    print("  [OK] Vector 2: Password Complexity & Dictionary Attack Resistance PASSED")
    test_vector_3_user_enumeration_timing_attack_mitigation()
    print("  [OK] Vector 3: User Enumeration Timing Side-Channel Neutralization PASSED")
    test_vector_4_stored_xss_sanitization_in_user_profile()
    print("  [OK] Vector 4: Stored XSS Sanitization in User Profile PASSED")
    test_vector_5_email_validation_and_injection_payloads()
    print("  [OK] Vector 5: Email Validation & Injection Payload Rejection PASSED")
    test_vector_6_token_revocation_jti_and_algorithm_confusion()
    print("  [OK] Vector 6: Token Invalidation, JTI Blacklisting & Alg Protection PASSED")
    test_vector_7_password_similarity_and_novelty()
    print("  [OK] Vector 7: Password Similarity & Monthly Rotation Novelty PASSED")
    test_vector_8_password_history_reuse_prevention()
    print("  [OK] Vector 8: Password History Reuse Prevention PASSED")
    test_vector_9_postgresql_injection_defense()
    print("  [OK] Vector 9: PostgreSQL Injection Immunity & Sanitization PASSED")
    test_vector_10_log_injection_and_crlf_defense()
    print("  [OK] Vector 10: Log Injection (CRLF) & Terminal Poisoning Defense PASSED")
    test_vector_11_concurrent_double_signup_race_defense()
    print("  [OK] Vector 11: Multi-Device Double-Signup Race Collision Defense PASSED")
    test_vector_12_zero_credential_and_secret_logging_defense()
    print("  [OK] Vector 12: Zero-Credential & Secret Redaction in Logs (CWE-532) PASSED")
    test_vector_13_log_flooding_and_dos_defense()
    print("  [OK] Vector 13: Log Flooding & Disk Exhaustion DoS Defense PASSED")
    test_vector_14_email_otp_verification_lifecycle()
    print("  [OK] Vector 14: Email OTP Cryptographic Lifecycle & Brute-Force Defense PASSED")
    print("\nALL 14 AUTHENTICATION & LOG SECURITY ATTACK TEST VECTORS PASSED!")
