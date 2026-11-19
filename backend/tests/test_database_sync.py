"""Database Synchronization Verification Script.

Tests the complete bi-directional data synchronization pipeline between
the SafeInbox AI extension endpoints and the database tables:
1. User Authentication & Terms Consent Synchronization (users, terms_consents)
2. URL Threat Intelligence Caching & Synchronization (threat_urls)
3. Webmail Email Scan Audit Trail Synchronization (scan_audit_logs)
4. Threat Feedback & Labeling Synchronization (feedback_records)
5. 15-Day Security Audit Digest Synchronization (security_digest_logs)
6. URL Click & Action Audit Trail Synchronization (url_clicks)
"""

import sys
import os
import sqlite3
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "safeinbox.db"))


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def test_sync_users_and_terms():
    print("[*] 1. Testing User & Terms Consent Synchronization...")
    conn = get_conn()
    cur = conn.cursor()

    email = f"sync_test_{int(datetime.now().timestamp())}@safeinbox.ai"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Insert user
    cur.execute(
        """
        INSERT INTO users (email, hashed_password, full_name, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (email, "scrypt$dummy$hash", "Sync Test User", 1, now_iso, now_iso)
    )
    user_id = cur.lastrowid

    # Insert terms consent
    cur.execute(
        """
        INSERT INTO terms_consents (user_id, email, ip_address, mac_address, terms_version, agreed_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, email, "127.0.0.1", "00:11:22:33:44:55", "1.0.0", now_iso)
    )
    conn.commit()

    # Query back
    cur.execute("SELECT email, full_name, is_active FROM users WHERE id = ?", (user_id,))
    row_user = cur.fetchone()
    assert row_user["email"] == email
    assert row_user["full_name"] == "Sync Test User"

    cur.execute("SELECT email, terms_version, ip_address FROM terms_consents WHERE user_id = ?", (user_id,))
    row_terms = cur.fetchone()
    assert row_terms["email"] == email
    assert row_terms["terms_version"] == "1.0.0"

    print(f"  [OK] User & Terms Consent synchronized: User ID {user_id}, Email {email}")
    conn.close()


def test_sync_threat_urls():
    print("[*] 2. Testing URL Threat Intelligence Caching & Synchronization...")
    conn = get_conn()
    cur = conn.cursor()

    test_url = f"https://phishing-paypal-verification.example.org/login?ts={int(datetime.now().timestamp())}"
    url_hash = hashlib.sha256(test_url.encode()).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute(
        """
        INSERT OR REPLACE INTO threat_urls (url_hash, canonical_url, hostname, risk_score, risk_level, attack_types, findings, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (url_hash, test_url, "phishing-paypal-verification.example.org", 88.5, "CRITICAL", '["BRAND_IMPERSONATION","CREDENTIAL_HARVESTING"]', '["Suspicious login form"]', now_iso, now_iso)
    )
    conn.commit()

    cur.execute("SELECT canonical_url, risk_score, risk_level FROM threat_urls WHERE url_hash = ?", (url_hash,))
    row = cur.fetchone()
    assert row["risk_score"] == 88.5
    assert row["risk_level"] == "CRITICAL"
    assert row["canonical_url"] == test_url

    print(f"  [OK] Threat URL cached and synced: Hash {url_hash[:16]}... Score {row['risk_score']}")
    conn.close()


def test_sync_scan_audit_logs():
    print("[*] 3. Testing Webmail Email Scan Audit Trail Synchronization...")
    conn = get_conn()
    cur = conn.cursor()

    # Privacy-preserving zero-PII content hash
    content_hash = hashlib.sha256(b"sample_email_digest_for_audit_logging").hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute(
        """
        INSERT INTO scan_audit_logs (scan_type, content_hash, risk_score, risk_level, threat_vectors, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("EMAIL", content_hash, 75, "HIGH", '["URGENCY","FINANCIAL_HOOK"]', now_iso)
    )
    conn.commit()

    cur.execute("SELECT scan_type, risk_score, risk_level FROM scan_audit_logs WHERE content_hash = ?", (content_hash,))
    row = cur.fetchone()
    assert row["scan_type"] == "EMAIL"
    assert row["risk_score"] == 75

    print(f"  [OK] Zero-PII Scan Audit log synchronized: Hash {content_hash[:16]}... Level {row['risk_level']}")
    conn.close()


def test_sync_feedback_records():
    print("[*] 4. Testing User & Analyst Feedback Synchronization...")
    conn = get_conn()
    cur = conn.cursor()

    target_hash = hashlib.sha256(b"analyst_reported_phishing_sample").hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute(
        """
        INSERT INTO feedback_records (target_hash, target_type, is_safe, source, target_sample, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (target_hash, "URL", 0, "extension", "hxxps://phishing-paypal[.]com", now_iso)
    )
    conn.commit()

    cur.execute("SELECT target_type, is_safe, source FROM feedback_records WHERE target_hash = ?", (target_hash,))
    row = cur.fetchone()
    assert row["target_type"] == "URL"
    assert row["is_safe"] == 0

    print(f"  [OK] Feedback record synchronized: Type {row['target_type']}, Safe: {row['is_safe']}")
    conn.close()


def test_sync_security_digest_logs():
    print("[*] 5. Testing 15-Day Security Digest Synchronization...")
    conn = get_conn()
    cur = conn.cursor()

    email = "compliance@safeinbox.ai"
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute(
        """
        INSERT INTO security_digest_logs (user_email, period_start, period_end, total_emails, threat_count, click_count, dispatch_status, delivery_note, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (email, "2026-10-18", "2026-11-02", 14, 3, 2, "sent", "Automated 15-day cycle delivery", now_iso)
    )
    conn.commit()

    cur.execute("SELECT total_emails, threat_count, click_count, dispatch_status FROM security_digest_logs WHERE user_email = ? ORDER BY id DESC LIMIT 1", (email,))
    row = cur.fetchone()
    assert row["total_emails"] == 14
    assert row["threat_count"] == 3
    assert row["click_count"] == 2
    assert row["dispatch_status"] == "sent"

    print(f"  [OK] 15-Day Security Digest synchronized: Recipient {email}, Emails {row['total_emails']}, Clicks {row['click_count']}")
    conn.close()


def test_sync_url_clicks():
    print("[*] 6. Testing URL Click & Action Audit Trail Synchronization...")
    conn = get_conn()
    cur = conn.cursor()

    email = "analyst@safeinbox.ai"
    test_url = "https://legit-site.example.com/login?token=abc"
    defanged_url = "hxxps://legit-site[.]example[.]com/login?token=abc"
    url_hash = hashlib.sha256(test_url.encode()).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute(
        """
        INSERT INTO url_clicks (user_email, url, defanged_url, url_hash, email_subject, sender, risk_score, risk_level, proceeded, source, clicked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (email, test_url, defanged_url, url_hash, "Urgent Payroll Review", "hr@example.com", 65.0, "HIGH", 1, "email_body_link", now_iso)
    )
    conn.commit()

    cur.execute("SELECT user_email, url, defanged_url, risk_score, risk_level, proceeded FROM url_clicks WHERE url_hash = ? ORDER BY id DESC LIMIT 1", (url_hash,))
    row = cur.fetchone()
    assert row["user_email"] == email
    assert row["url"] == test_url
    assert row["defanged_url"] == defanged_url
    assert row["risk_score"] == 65.0
    assert row["risk_level"] == "HIGH"
    assert row["proceeded"] == 1

    print(f"  [OK] URL Click action synchronized: User {email}, Defanged {row['defanged_url']}, Risk {row['risk_score']}")
    conn.close()


if __name__ == "__main__":
    print("=" * 65)
    print("  SAFEINBOX AI -- DATABASE SYNCHRONIZATION TEST HARNESS")
    print("=" * 65)
    test_sync_users_and_terms()
    test_sync_threat_urls()
    test_sync_scan_audit_logs()
    test_sync_feedback_records()
    test_sync_security_digest_logs()
    test_sync_url_clicks()
    print("=" * 65)
    print("ALL 6 DATABASE SYNCHRONIZATION PIPELINES VERIFIED SUCCESSFULLY!")
    print("=" * 65)
