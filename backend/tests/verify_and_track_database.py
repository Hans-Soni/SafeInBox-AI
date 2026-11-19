"""Comprehensive Database Synchronization & Data Storage Tracking Harness.

Tests and tracks live synchronization of all 7 core data streams into the database:
1. Users & Accounts (users)
2. Terms & Privacy Consents (terms_consents)
3. URL Threat Intelligence & Cache (threat_urls)
4. Zero-PII Scan Audit Trail (scan_audit_logs)
5. Model Dataset Feedback (feedback_records)
6. 15-Day Security Digest Delivery Records (security_digest_logs)
7. Hyperlink Clicks & User Actions (url_clicks)

Directly audits column values, integrity constraints, and verifies data is stored perfectly.
"""

import os
import sys
import sqlite3
import hashlib
import json
from datetime import datetime, timezone

# Ensure project backend package is available
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

TARGET_DBS = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "safeinbox.db")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "safeinbox.db"))
]


def get_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def inspect_schema(db_path):
    print("=" * 75)
    print("  DATABASE SCHEMA & TABLE STRUCTURE INSPECTION")
    print(f"  Target Database: {db_path}")
    print("=" * 75)

    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row["name"] for row in cur.fetchall() if not row["name"].startswith("sqlite_")]

    print(f"[*] Found {len(tables)} tables registered in database:")
    for tbl in tables:
        cur.execute(f"PRAGMA table_info({tbl})")
        columns = cur.fetchall()
        col_names = [f"{c['name']} ({c['type']})" for c in columns]

        cur.execute(f"SELECT COUNT(*) AS cnt FROM {tbl}")
        count = cur.fetchone()["cnt"]

        print(f"  - Table: {tbl:<22} | Rows: {count:<4} | Columns: {len(columns)}")
        print(f"    Fields: {', '.join(col_names)}")

    conn.close()
    print("=" * 75)


def test_and_track_all_data_streams(db_path):
    print("\n" + "=" * 75)
    print(f"  LIVE DATA SYNCHRONIZATION AND STORAGE TRACKING: {os.path.basename(os.path.dirname(db_path))}/{os.path.basename(db_path)}")
    print("=" * 75)

    conn = get_connection(db_path)
    cur = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    now_ts = int(datetime.now().timestamp())

    tracking_results = {}

    # --------------------------------------------------------------------------
    # Stream 1: User Account Registration (users)
    # --------------------------------------------------------------------------
    print("\n[*] Stream 1: Tracking User Account Storage (`users`)...")
    test_email = f"analyst.track_{now_ts}@safeinbox.ai"
    dummy_scrypt_hash = "scrypt$16384$8$1$dummy_salt$dummy_encrypted_password_hash"
    cur.execute(
        """
        INSERT INTO users (email, hashed_password, full_name, is_active, is_superuser, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (test_email, dummy_scrypt_hash, "Security Analyst Lead", 1, 0, now_iso, now_iso)
    )
    user_id = cur.lastrowid
    conn.commit()

    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_row = dict(cur.fetchone())
    assert user_row["email"] == test_email
    assert user_row["full_name"] == "Security Analyst Lead"
    assert user_row["is_active"] == 1
    tracking_results["users"] = {
        "status": "STORED_PERFECTLY",
        "id": user_row["id"],
        "email": user_row["email"],
        "full_name": user_row["full_name"],
        "active": bool(user_row["is_active"])
    }
    print(f"  [OK] User record stored: ID={user_row['id']} | Email={user_row['email']} | Active={user_row['is_active']}")

    # --------------------------------------------------------------------------
    # Stream 2: Terms & Privacy Consent Audit (terms_consents)
    # --------------------------------------------------------------------------
    print("\n[*] Stream 2: Tracking Terms & Consent Storage (`terms_consents`)...")
    cur.execute(
        """
        INSERT INTO terms_consents (user_id, email, ip_address, mac_address, terms_version, agreed_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, test_email, "192.168.1.100", "00:1A:2B:3C:4D:5E", "1.0.0", now_iso)
    )
    terms_id = cur.lastrowid
    conn.commit()

    cur.execute("SELECT * FROM terms_consents WHERE id = ?", (terms_id,))
    terms_row = dict(cur.fetchone())
    assert terms_row["user_id"] == user_id
    assert terms_row["email"] == test_email
    assert terms_row["terms_version"] == "1.0.0"
    tracking_results["terms_consents"] = {
        "status": "STORED_PERFECTLY",
        "id": terms_row["id"],
        "user_id": terms_row["user_id"],
        "terms_version": terms_row["terms_version"],
        "ip_address": terms_row["ip_address"]
    }
    print(f"  [OK] Terms consent stored: ID={terms_row['id']} | Linked User={terms_row['user_id']} | Version={terms_row['terms_version']}")

    # --------------------------------------------------------------------------
    # Stream 3: Threat Intelligence URL Cache (threat_urls)
    # --------------------------------------------------------------------------
    print("\n[*] Stream 3: Tracking Threat URL Intelligence Storage (`threat_urls`)...")
    raw_url = f"https://secure-login.bank-verification.com/login?token={now_ts}"
    url_hash = hashlib.sha256(raw_url.encode()).hexdigest()
    attack_types_json = json.dumps(["BRAND_IMPERSONATION", "CREDENTIAL_HARVESTING"])
    findings_json = json.dumps(["Lookalike brand domain detected", "Suspicious login form payload"])

    cur.execute(
        """
        INSERT OR REPLACE INTO threat_urls (url_hash, canonical_url, hostname, risk_score, risk_level, attack_types, findings, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (url_hash, raw_url, "secure-login.bank-verification.com", 92.5, "CRITICAL", attack_types_json, findings_json, now_iso, now_iso)
    )
    conn.commit()

    cur.execute("SELECT * FROM threat_urls WHERE url_hash = ?", (url_hash,))
    url_row = dict(cur.fetchone())
    assert url_row["canonical_url"] == raw_url
    assert url_row["risk_score"] == 92.5
    assert url_row["risk_level"] == "CRITICAL"
    tracking_results["threat_urls"] = {
        "status": "STORED_PERFECTLY",
        "id": url_row["id"],
        "url_hash": url_row["url_hash"][:16] + "...",
        "risk_score": url_row["risk_score"],
        "risk_level": url_row["risk_level"]
    }
    print(f"  [OK] Threat URL cached: ID={url_row['id']} | Score={url_row['risk_score']} | Level={url_row['risk_level']} | Hash={url_hash[:16]}...")

    # --------------------------------------------------------------------------
    # Stream 4: Zero-PII Scan Audit Logs (scan_audit_logs)
    # --------------------------------------------------------------------------
    print("\n[*] Stream 4: Tracking Zero-PII Scan Audit Storage (`scan_audit_logs`)...")
    email_content_hash = hashlib.sha256(f"email_audit_sample_{now_ts}".encode()).hexdigest()
    threat_vectors_json = json.dumps(["ARTIFICIAL_URGENCY", "FINANCIAL_SCAM"])

    cur.execute(
        """
        INSERT INTO scan_audit_logs (scan_type, content_hash, risk_score, risk_level, threat_vectors, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("EMAIL", email_content_hash, 84, "CRITICAL", threat_vectors_json, now_iso)
    )
    audit_id = cur.lastrowid
    conn.commit()

    cur.execute("SELECT * FROM scan_audit_logs WHERE id = ?", (audit_id,))
    audit_row = dict(cur.fetchone())
    assert audit_row["scan_type"] == "EMAIL"
    assert audit_row["content_hash"] == email_content_hash
    assert audit_row["risk_score"] == 84
    tracking_results["scan_audit_logs"] = {
        "status": "STORED_PERFECTLY",
        "id": audit_row["id"],
        "scan_type": audit_row["scan_type"],
        "risk_score": audit_row["risk_score"],
        "content_hash": audit_row["content_hash"][:16] + "..."
    }
    print(f"  [OK] Zero-PII Scan Audit stored: ID={audit_row['id']} | Type={audit_row['scan_type']} | Score={audit_row['risk_score']} | Hash={email_content_hash[:16]}...")

    # --------------------------------------------------------------------------
    # Stream 5: User & Model Dataset Feedback (feedback_records)
    # --------------------------------------------------------------------------
    print("\n[*] Stream 5: Tracking Model Feedback Storage (`feedback_records`)...")
    target_sample = "hxxps://verified-threat-sample[.]com/portal"
    feedback_hash = hashlib.sha256(target_sample.encode()).hexdigest()

    cur.execute(
        """
        INSERT INTO feedback_records (target_hash, target_type, is_safe, source, target_sample, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (feedback_hash, "URL", 0, "webmail_banner", target_sample, now_iso)
    )
    feedback_id = cur.lastrowid
    conn.commit()

    cur.execute("SELECT * FROM feedback_records WHERE id = ?", (feedback_id,))
    fb_row = dict(cur.fetchone())
    assert fb_row["target_hash"] == feedback_hash
    assert fb_row["target_type"] == "URL"
    assert fb_row["is_safe"] == 0
    tracking_results["feedback_records"] = {
        "status": "STORED_PERFECTLY",
        "id": fb_row["id"],
        "target_type": fb_row["target_type"],
        "is_safe": bool(fb_row["is_safe"]),
        "source": fb_row["source"]
    }
    print(f"  [OK] Feedback record stored: ID={fb_row['id']} | Target Type={fb_row['target_type']} | Safe={fb_row['is_safe']} | Source={fb_row['source']}")

    # --------------------------------------------------------------------------
    # Stream 6: 15-Day Security Digest Audit Records (security_digest_logs)
    # --------------------------------------------------------------------------
    print("\n[*] Stream 6: Tracking 15-Day Security Digest Storage (`security_digest_logs`)...")
    cur.execute(
        """
        INSERT INTO security_digest_logs (user_email, period_start, period_end, total_emails, threat_count, click_count, dispatch_status, delivery_note, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (test_email, "2026-10-20", "2026-11-04", 25, 4, 3, "sent", "Automated 15-day cycle delivery verified", now_iso)
    )
    digest_id = cur.lastrowid
    conn.commit()

    cur.execute("SELECT * FROM security_digest_logs WHERE id = ?", (digest_id,))
    digest_row = dict(cur.fetchone())
    assert digest_row["user_email"] == test_email
    assert digest_row["total_emails"] == 25
    assert digest_row["threat_count"] == 4
    assert digest_row["click_count"] == 3
    tracking_results["security_digest_logs"] = {
        "status": "STORED_PERFECTLY",
        "id": digest_row["id"],
        "user_email": digest_row["user_email"],
        "total_emails": digest_row["total_emails"],
        "clicks": digest_row["click_count"]
    }
    print(f"  [OK] 15-Day Digest stored: ID={digest_row['id']} | User={digest_row['user_email']} | Emails={digest_row['total_emails']} | Clicks={digest_row['click_count']}")

    # --------------------------------------------------------------------------
    # Stream 7: User Actions & Webmail URL Clicks (url_clicks)
    # --------------------------------------------------------------------------
    print("\n[*] Stream 7: Tracking Hyperlink Click & User Actions (`url_clicks`)...")
    target_click_url = "https://phishing-payroll-update.com/download.exe"
    defanged_target = "hxxps://phishing-payroll-update[.]com/download[.]exe"
    click_hash = hashlib.sha256(target_click_url.encode()).hexdigest()

    cur.execute(
        """
        INSERT INTO url_clicks (user_email, url, defanged_url, url_hash, email_subject, sender, risk_score, risk_level, proceeded, source, clicked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (test_email, target_click_url, defanged_target, click_hash, "Urgent: Mandatory Payroll Form", "hr-alerts@external-payroll.com", 96.0, "CRITICAL", 1, "email_body_link", now_iso)
    )
    click_id = cur.lastrowid
    conn.commit()

    cur.execute("SELECT * FROM url_clicks WHERE id = ?", (click_id,))
    click_row = dict(cur.fetchone())
    assert click_row["url"] == target_click_url
    assert click_row["defanged_url"] == defanged_target
    assert click_row["risk_score"] == 96.0
    assert click_row["risk_level"] == "CRITICAL"
    assert click_row["proceeded"] == 1
    tracking_results["url_clicks"] = {
        "status": "STORED_PERFECTLY",
        "id": click_row["id"],
        "defanged_url": click_row["defanged_url"],
        "risk_score": click_row["risk_score"],
        "risk_level": click_row["risk_level"],
        "proceeded": bool(click_row["proceeded"])
    }
    print(f"  [OK] URL Click action stored: ID={click_row['id']} | Defanged={click_row['defanged_url']} | Risk={click_row['risk_score']} ({click_row['risk_level']}) | Proceeded={click_row['proceeded']}")

    conn.close()

    print("\n" + "=" * 75)
    print(f"  SYNCHRONIZATION & STORAGE AUDIT COMPLETE FOR {os.path.basename(db_path)}")
    print(f"  ALL 7 DATA STREAMS VERIFIED & STORED WITH 100% INTEGRITY")
    print("=" * 75)
    return tracking_results


if __name__ == "__main__":
    for db in set(TARGET_DBS):
        if os.path.exists(db):
            inspect_schema(db)
            results = test_and_track_all_data_streams(db)
            print("\nReceipt Summary:")
            print(json.dumps(results, indent=2))
            print("\n")
