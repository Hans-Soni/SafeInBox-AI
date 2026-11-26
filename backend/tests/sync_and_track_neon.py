"""Neon Lakebase Postgres Schema Synchronization & Full Data Tracking Test Harness.

Connects directly to Neon Lakebase Postgres, synchronizes all 7 application tables,
records the Alembic head migration revision, and executes live end-to-end data
storage and retrieval tests across all 7 data streams:
  1. Users (users)
  2. Terms Consents (terms_consents)
  3. Threat URLs (threat_urls)
  4. Scan Audit Logs (scan_audit_logs)
  5. Feedback Records (feedback_records)
  6. 15-Day Security Digest Logs (security_digest_logs)
  7. Hyperlink Clicks (url_clicks)
"""

import asyncio
import os
import sys
import hashlib
import json
from datetime import datetime, timezone, timedelta

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from app.database import engine, Base
from app.config import settings
from app.models.user import User, TermsConsent
from app.models.threat import ThreatURL, FeedbackRecord, ScanAuditLog, UrlClickLog
from app.models.digest import SecurityDigestLog
from sqlalchemy import text, select, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


async def main():
    print("=" * 80)
    print("  NEON LAKEBASE POSTGRES: SCHEMA SYNCHRONIZATION & DATA STORAGE TRACKER")
    print(f"  Project Endpoint: {settings.NEON_HOST}")
    print(f"  Database Name:    {settings.NEON_DATABASE}")
    print("=" * 80)

    # 1. Test Connection
    print("\n[*] Phase 1: Validating Cloud Database Connection...")
    async with engine.connect() as conn:
        res = await conn.execute(text("SELECT version();"))
        pg_ver = res.scalar()
        print(f"    [OK] Connected to Neon Cloud PostgreSQL:")
        print(f"         Version: {pg_ver}")

    # 2. Synchronize Schema (Create all missing tables)
    print("\n[*] Phase 2: Synchronizing Schema & Creating Missing Tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        print("    [OK] Base.metadata.create_all executed successfully.")

        # Ensure alembic_version table exists and is stamped to head
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS alembic_version (
                version_num VARCHAR(32) NOT NULL,
                CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
            );
        """))
        res = await conn.execute(text("SELECT version_num FROM alembic_version;"))
        current_rev = res.scalar()
        if not current_rev:
            await conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('i9d0e1f2a3b4');"))
            print("    [OK] Stamped alembic_version to head revision 'i9d0e1f2a3b4'.")
        else:
            await conn.execute(text("UPDATE alembic_version SET version_num = 'i9d0e1f2a3b4';"))
            print(f"    [OK] Updated alembic_version from '{current_rev}' to head revision 'i9d0e1f2a3b4'.")

    # 3. Inspect Schema in Neon
    print("\n[*] Phase 3: Inspecting Public Schema & Tables in Neon...")
    expected_tables = [
        "users",
        "terms_consents",
        "threat_urls",
        "scan_audit_logs",
        "feedback_records",
        "security_digest_logs",
        "url_clicks",
        "email_otp_verifications",
        "refresh_tokens",
    ]

    async with engine.connect() as conn:
        res = await conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name;
        """))
        existing_tables = [row[0] for row in res.fetchall()]
        print(f"    Found {len(existing_tables)} tables in Neon 'public' schema: {existing_tables}")

        missing = [t for t in expected_tables if t not in existing_tables]
        if missing:
            print(f"    [ERROR] Missing expected tables: {missing}")
            sys.exit(1)
        else:
            print("    [OK] All 7 core SafeInbox AI application tables exist in Neon!")

        # Print column counts for each table
        for tbl in expected_tables:
            res_cols = await conn.execute(text(f"""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns 
                WHERE table_name = '{tbl}' AND table_schema = 'public'
                ORDER BY ordinal_position;
            """))
            cols = res_cols.fetchall()
            res_cnt = await conn.execute(text(f"SELECT COUNT(*) FROM {tbl};"))
            cnt = res_cnt.scalar()
            print(f"    - Table '{tbl:<20}': {len(cols):<2} columns | {cnt:<4} existing rows")

    # 4. Live Data Storage & Synchronization Test across all 7 streams
    print("\n[*] Phase 4: Executing Live Data Storage & Synchronization Across All 7 Streams...")
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    test_suffix = f"test_{int(datetime.now(timezone.utc).timestamp())}"
    test_user_email = f"neon_{test_suffix}@safeinbox.ai"
    test_url = f"https://threat-test-{test_suffix}.example.com/login"
    test_url_hash = hashlib.sha256(test_url.encode()).hexdigest()
    test_email_hash = hashlib.sha256(f"urgent-security-alert-{test_suffix}".encode()).hexdigest()

    async with async_session() as session:
        # Stream 1: Users
        user = User(
            email=test_user_email,
            hashed_password="pbkdf2_sha256$100000$neon_salt_test$f45a8b79c3d2e1f0",
            full_name="Neon Cloud Test User",
            is_active=True,
            is_superuser=False,
            created_at=datetime.now(timezone.utc)
        )
        session.add(user)
        await session.flush()
        user_id = user.id
        print(f"    [1/7] User Account Stream:       Saved user id={user_id}, email={test_user_email}")

        # Stream 2: Terms & Privacy Consents
        consent = TermsConsent(
            user_id=user_id,
            email=test_user_email,
            ip_address="198.51.100.42",
            mac_address="00:1A:2B:3C:4D:5E",
            terms_version="1.0.0",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0",
            agreed_at=datetime.now(timezone.utc)
        )
        session.add(consent)
        await session.flush()
        print(f"    [2/7] Terms Consent Stream:      Saved consent id={consent.id} for user_id={user_id}")

        # Stream 3: Threat URLs
        threat = ThreatURL(
            url_hash=test_url_hash,
            canonical_url=test_url,
            hostname=f"threat-test-{test_suffix}.example.com",
            risk_score=0.96,
            risk_level="CRITICAL",
            attack_types=["credential_phishing", "brand_impersonation"],
            findings=["Known phishing pattern", "Zero-day host detection"],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        session.add(threat)
        await session.flush()
        print(f"    [3/7] Threat URLs Stream:        Saved threat hash={test_url_hash[:16]}... risk_score=0.96")

        # Stream 4: Scan Audit Logs (Zero-PII)
        audit_log = ScanAuditLog(
            scan_type="EMAIL",
            content_hash=test_email_hash,
            risk_score=85,
            risk_level="SUSPICIOUS",
            threat_vectors=["spoofed_display_name", "unusual_urgency", "suspicious_attachment"],
            created_at=datetime.now(timezone.utc)
        )
        session.add(audit_log)
        await session.flush()
        print(f"    [4/7] Scan Audit Log Stream:     Saved zero-PII audit id={audit_log.id}, hash={test_email_hash[:16]}...")

        # Stream 5: Feedback Records (Partitions URL and TEXT)
        feedback_url = FeedbackRecord(
            target_hash=test_url_hash,
            target_type="URL",
            is_safe=False,
            source="extension_sidepanel",
            target_sample=test_url,
            created_at=datetime.now(timezone.utc)
        )
        feedback_text = FeedbackRecord(
            target_hash=test_email_hash,
            target_type="TEXT",
            is_safe=False,
            source="extension_banner",
            target_sample="Urgent password reset required within 24 hours.",
            created_at=datetime.now(timezone.utc)
        )
        session.add_all([feedback_url, feedback_text])
        await session.flush()
        print(f"    [5/7] Model Feedback Stream:     Saved URL feedback (id={feedback_url.id}) & TEXT feedback (id={feedback_text.id})")

        # Stream 6: 15-Day Security Digest Logs
        period_start = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        period_end = datetime.now(timezone.utc).isoformat()
        digest_log = SecurityDigestLog(
            user_email=test_user_email,
            period_start=period_start,
            period_end=period_end,
            total_emails=38,
            threat_count=4,
            click_count=2,
            dispatch_status="sent",
            delivery_note="Successfully delivered via SMTP to Neon-connected user",
            created_at=datetime.now(timezone.utc)
        )
        session.add(digest_log)
        await session.flush()
        print(f"    [6/7] Security Digest Stream:    Saved 15-day digest log id={digest_log.id} (38 emails, 4 threats, 2 clicks)")

        # Stream 7: URL Hyperlink Clicks & User Actions
        click_log = UrlClickLog(
            user_email=test_user_email,
            url=test_url,
            defanged_url=f"hxxps://threat-test-{test_suffix}[.]example[.]com/login",
            url_hash=test_url_hash,
            email_subject="Account Verification Required",
            sender="security-alert@fake-bank.example",
            risk_score=0.96,
            risk_level="CRITICAL",
            proceeded=False,
            source="email_body_link",
            clicked_at=datetime.now(timezone.utc)
        )
        session.add(click_log)
        await session.flush()
        print(f"    [7/7] Hyperlink Clicks Stream:   Saved click action id={click_log.id}, user_email={test_user_email}")

        # Commit all 7 records to Neon
        await session.commit()
        print("\n    --> ALL 7 STREAMS COMMITTED TO NEON POSTGRES! <--")

    # 5. Retrieve & Verify Data Storage from Neon
    print("\n[*] Phase 5: Querying & Validating Stored Data Directly from Neon...")
    async with async_session() as session:
        # Verify User
        res_u = await session.execute(select(User).where(User.email == test_user_email))
        ret_u = res_u.scalar_one_or_none()
        assert ret_u is not None, "Failed to retrieve user from Neon"
        assert ret_u.full_name == "Neon Cloud Test User"
        print(f"    [OK] User retrieved: id={ret_u.id}, email={ret_u.email}, active={ret_u.is_active}")

        # Verify Terms Consent
        res_tc = await session.execute(select(TermsConsent).where(TermsConsent.email == test_user_email))
        ret_tc = res_tc.scalar_one_or_none()
        assert ret_tc is not None, "Failed to retrieve terms consent from Neon"
        assert ret_tc.user_id == ret_u.id
        print(f"    [OK] Terms Consent retrieved: id={ret_tc.id}, IP={ret_tc.ip_address}, MAC={ret_tc.mac_address}")

        # Verify Threat URL
        res_tu = await session.execute(select(ThreatURL).where(ThreatURL.url_hash == test_url_hash))
        ret_tu = res_tu.scalar_one_or_none()
        assert ret_tu is not None, "Failed to retrieve threat url from Neon"
        assert ret_tu.risk_score == 0.96
        assert "credential_phishing" in ret_tu.attack_types
        print(f"    [OK] Threat URL retrieved: hash={ret_tu.url_hash[:16]}..., attack_types={ret_tu.attack_types}")

        # Verify Scan Audit Log
        res_sa = await session.execute(select(ScanAuditLog).where(ScanAuditLog.content_hash == test_email_hash))
        ret_sa = res_sa.scalar_one_or_none()
        assert ret_sa is not None, "Failed to retrieve scan audit log from Neon"
        assert ret_sa.risk_score == 85
        assert "spoofed_display_name" in ret_sa.threat_vectors
        print(f"    [OK] Scan Audit Log retrieved: id={ret_sa.id}, vectors={ret_sa.threat_vectors}")

        # Verify Feedback Records
        res_fb = await session.execute(select(FeedbackRecord).where(FeedbackRecord.target_hash.in_([test_url_hash, test_email_hash])))
        ret_fb = res_fb.scalars().all()
        assert len(ret_fb) == 2, f"Expected 2 feedback records, found {len(ret_fb)}"
        print(f"    [OK] Feedback Records retrieved: {len(ret_fb)} records (URL & TEXT partitioned)")

        # Verify Security Digest Log
        res_sd = await session.execute(select(SecurityDigestLog).where(SecurityDigestLog.user_email == test_user_email))
        ret_sd = res_sd.scalar_one_or_none()
        assert ret_sd is not None, "Failed to retrieve security digest log from Neon"
        assert ret_sd.total_emails == 38
        assert ret_sd.threat_count == 4
        assert ret_sd.click_count == 2
        print(f"    [OK] Security Digest Log retrieved: id={ret_sd.id}, total_emails=38, threats=4, clicks=2")

        # Verify URL Click Log
        res_cl = await session.execute(select(UrlClickLog).where(UrlClickLog.user_email == test_user_email))
        ret_cl = res_cl.scalar_one_or_none()
        assert ret_cl is not None, "Failed to retrieve URL click log from Neon"
        assert ret_cl.proceeded is False
        assert ret_cl.defanged_url.startswith("hxxps://")
        print(f"    [OK] URL Click Log retrieved: id={ret_cl.id}, proceeded={ret_cl.proceeded}, defanged={ret_cl.defanged_url}")

    # 6. Cleanup Test Records
    preserve_data = "--keep" in sys.argv or "--preserve" in sys.argv
    if preserve_data:
        print("\n[*] Phase 6: Preserving test data in Neon (--keep flag detected)...")
        print("    [OK] Test records intentionally retained in your Neon database for inspection!")
    else:
        print("\n[*] Phase 6: Cleaning up test records from Neon...")
        async with async_session() as session:
            await session.execute(text(f"DELETE FROM terms_consents WHERE email = '{test_user_email}';"))
            await session.execute(text(f"DELETE FROM users WHERE email = '{test_user_email}';"))
            await session.execute(text(f"DELETE FROM threat_urls WHERE url_hash = '{test_url_hash}';"))
            await session.execute(text(f"DELETE FROM scan_audit_logs WHERE content_hash = '{test_email_hash}';"))
            await session.execute(text(f"DELETE FROM feedback_records WHERE target_hash IN ('{test_url_hash}', '{test_email_hash}');"))
            await session.execute(text(f"DELETE FROM security_digest_logs WHERE user_email = '{test_user_email}';"))
            await session.execute(text(f"DELETE FROM url_clicks WHERE user_email = '{test_user_email}';"))
            await session.commit()
            print("    [OK] Test records cleaned up successfully.")

    # 7. Final Table Summary
    print("\n" + "=" * 80)
    print("  FINAL NEON DATABASE STATUS REPORT")
    print("=" * 80)
    async with engine.connect() as conn:
        for tbl in expected_tables:
            res_cnt = await conn.execute(text(f"SELECT COUNT(*) FROM {tbl};"))
            cnt = res_cnt.scalar()
            print(f"  [ONLINE] Table: {tbl:<24} | Current Row Count: {cnt}")
    print("=" * 80)
    print("  SYNCHRONIZATION & STORAGE VERIFICATION COMPLETED WITH 100% SUCCESS!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())

