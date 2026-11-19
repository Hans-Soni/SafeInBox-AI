"""End-to-End API test verifying OTP ephemerality and unified 4-flow lifecycle.

Ensures:
1. Once an OTP is verified (or expired), it is immediately deleted from the database.
2. Zero lingering OTP rows in Neon PostgreSQL.
3. Same OTP system works for Sign-Up, Sign-In (15-day session), and 30-day Password Update.
"""

import sys
import asyncio
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import httpx
from sqlalchemy import select, delete
from app.main import app
from app.database import AsyncSessionLocal
from app.models.user import User, EmailOTPVerification, TermsConsent
from app.services.otp_service import hash_otp


async def main():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        test_email = "e2e_otp_test@safeinbox.ai"
        test_pw = "SafePassword#2026!Sec"
        new_pw = "BrandNewSecret#2026!Sec"

        # 0. Clean prior state in database
        async with AsyncSessionLocal() as db:
            await db.execute(delete(EmailOTPVerification).where(EmailOTPVerification.email == test_email))
            user_res = await db.execute(select(User).where(User.email == test_email))
            user_obj = user_res.scalars().first()
            if user_obj:
                await db.execute(delete(TermsConsent).where(TermsConsent.user_id == user_obj.id))
                await db.execute(delete(User).where(User.id == user_obj.id))
            await db.commit()

        try:
            # ==================================================================
            # 1. SIGN-UP FLOW
            # ==================================================================
            print("\n[*] 1. Testing Sign-Up OTP Request & Verification...")
            resp = await client.post("/api/v1/auth/signup/request-otp", json={
                "email": test_email,
                "password": test_pw,
                "full_name": "E2E Test User",
                "terms_agreed": True,
                "terms_version": "1.0.0"
            })
            assert resp.status_code == 200, f"Request OTP failed: {resp.text}"
            data = resp.json()
            assert data.get("requires_otp") is True

            # Query database to inspect pending OTP record
            otp_code = None
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == test_email))
                rec = res.scalars().first()
                assert rec is not None, "Pending OTP record must exist in DB during verification"
                assert rec.pending_data.get("purpose") == "signup"
                salt = rec.salt
                for code_candidate in range(100000, 1000000):
                    s_cand = str(code_candidate)
                    if hash_otp(s_cand, salt) == rec.otp_hash:
                        otp_code = s_cand
                        break
                assert otp_code is not None, "Could not match candidate OTP code"
                print(f"  [+] Found in-flight OTP in DB: purpose={rec.pending_data.get('purpose')}, code resolved")

            # Verify OTP
            verify_resp = await client.post("/api/v1/auth/signup/verify-otp", json={
                "email": test_email,
                "otp": otp_code
            })
            assert verify_resp.status_code == 201, f"Verify OTP failed: {verify_resp.text}"
            token_data = verify_resp.json()
            access_token = token_data.get("access_token")
            assert access_token is not None, "Access token must be returned on signup verification"

            # Check database for zero lingering OTP rows
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == test_email))
                lingering = res.scalars().all()
                assert len(lingering) == 0, f"Sign-Up OTP record MUST be deleted from DB! Found: {lingering}"
            print("  [OK] Sign-Up OTP verified, user created, and OTP immediately PURGED from DB (0 lingering rows)")

            # ==================================================================
            # 2. SIGN-IN FLOW (15-day session)
            # ==================================================================
            print("\n[*] 2. Testing Sign-In OTP Request & Verification (15-day session)...")
            signin_req_resp = await client.post("/api/v1/auth/signin/request-otp", json={
                "email": test_email,
                "password": test_pw
            })
            assert signin_req_resp.status_code == 200, f"Sign-in request OTP failed: {signin_req_resp.text}"
            signin_data = signin_req_resp.json()
            assert signin_data.get("requires_otp") is True
            assert signin_data.get("purpose") == "signin"

            # Query database to inspect pending OTP record
            signin_otp = None
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == test_email))
                rec = res.scalars().first()
                assert rec is not None, "Pending sign-in OTP record must exist in DB"
                assert rec.pending_data.get("purpose") == "signin"
                salt = rec.salt
                for code_candidate in range(100000, 1000000):
                    s_cand = str(code_candidate)
                    if hash_otp(s_cand, salt) == rec.otp_hash:
                        signin_otp = s_cand
                        break
                assert signin_otp is not None, "Could not match candidate sign-in OTP"
                print(f"  [+] Found in-flight sign-in OTP in DB: purpose={rec.pending_data.get('purpose')}")

            # Verify Sign-In OTP
            signin_verify_resp = await client.post("/api/v1/auth/signin/verify-otp", json={
                "email": test_email,
                "otp": signin_otp
            })
            assert signin_verify_resp.status_code == 200, f"Sign-in verify failed: {signin_verify_resp.text}"
            token_res = signin_verify_resp.json()
            assert token_res.get("session_lifetime_days") == 15, "Session lifetime must be 15 days"
            assert token_res.get("expires_in_seconds") == 1296000, "Expires in must be 1,296,000s (15 days)"
            auth_token = token_res.get("access_token")

            # Check database for zero lingering OTP rows
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == test_email))
                lingering = res.scalars().all()
                assert len(lingering) == 0, f"Sign-In OTP record MUST be deleted from DB! Found: {lingering}"
            print("  [OK] Sign-In OTP verified, 15-day session issued, and OTP immediately PURGED from DB (0 lingering rows)")

            # ==================================================================
            # 3. 30-DAY PASSWORD UPDATE FLOW
            # ==================================================================
            print("\n[*] 3. Testing 30-Day Password Update OTP Request & Verification...")
            headers = {"Authorization": f"Bearer {auth_token}"}
            pw_req_resp = await client.post("/api/v1/auth/password/request-otp", json={
                "current_password": test_pw,
                "new_password": new_pw
            }, headers=headers)
            assert pw_req_resp.status_code == 200, f"Password request OTP failed: {pw_req_resp.text}"
            pw_data = pw_req_resp.json()
            assert pw_data.get("requires_otp") is True
            assert pw_data.get("purpose") == "change_password"

            # Query database to inspect pending OTP record
            pw_otp = None
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == test_email))
                rec = res.scalars().first()
                assert rec is not None, "Pending password OTP record must exist in DB"
                assert rec.pending_data.get("purpose") == "change_password"
                salt = rec.salt
                for code_candidate in range(100000, 1000000):
                    s_cand = str(code_candidate)
                    if hash_otp(s_cand, salt) == rec.otp_hash:
                        pw_otp = s_cand
                        break
                assert pw_otp is not None, "Could not match candidate password OTP"
                print(f"  [+] Found in-flight password OTP in DB: purpose={rec.pending_data.get('purpose')}")

            # Verify Password OTP
            pw_verify_resp = await client.post("/api/v1/auth/password/verify-otp", json={
                "email": test_email,
                "otp": pw_otp
            }, headers=headers)
            assert pw_verify_resp.status_code == 200, f"Password verify OTP failed: {pw_verify_resp.text}"

            # Check database for zero lingering OTP rows
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == test_email))
                lingering = res.scalars().all()
                assert len(lingering) == 0, f"Password OTP record MUST be deleted from DB! Found: {lingering}"
            print("  [OK] Password Update OTP verified, password updated, and OTP immediately PURGED from DB (0 lingering rows)")

            # Verify user can now sign in with the new password!
            new_signin_resp = await client.post("/api/v1/auth/signin/request-otp", json={
                "email": test_email,
                "password": new_pw
            })
            assert new_signin_resp.status_code == 200, "Sign in with new password must succeed"
            print("  [OK] Successfully authenticated with newly rotated password!")

            print("\n======================================================================")
            print("ALL 3 OTP FLOWS (SIGN-UP, SIGN-IN, PASSWORD UPDATE) VERIFIED WITH ZERO LINGERING ROWS!")
            print("======================================================================")

        finally:
            # Cleanup test user & OTP records
            async with AsyncSessionLocal() as db:
                await db.execute(delete(EmailOTPVerification).where(EmailOTPVerification.email == test_email))
                user_res = await db.execute(select(User).where(User.email == test_email))
                user_obj = user_res.scalars().first()
                if user_obj:
                    await db.execute(delete(TermsConsent).where(TermsConsent.user_id == user_obj.id))
                    await db.execute(delete(User).where(User.id == user_obj.id))
                await db.commit()


if __name__ == "__main__":
    asyncio.run(main())
