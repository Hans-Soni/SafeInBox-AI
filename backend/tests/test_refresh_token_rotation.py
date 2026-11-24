"""Comprehensive test suite for Refresh Token Rotation (RTR), reuse detection, and session safety."""

import os
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_safeinbox.db"
os.environ["FORCE_HTTPS"] = "false"

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models.user import RefreshToken, User
from app.services.auth_service import decode_access_token, hash_token


@pytest.mark.asyncio
async def test_signup_and_signin_issue_refresh_tokens():
    """Verify that both signup and signin issue short-lived access tokens and single-use refresh tokens."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        test_email = "rtr_user_1@safeinbox.test"
        test_pw = "Str0ng&Complex#Pass2026!"

        # 1. Sign Up
        signup_res = await client.post("/api/v1/auth/signup", json={
            "email": test_email,
            "password": test_pw,
            "full_name": "RTR User One",
            "terms_agreed": True
        })
        assert signup_res.status_code == 201, signup_res.text
        data = signup_res.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["expires_in_seconds"] == 1800  # 30 minutes
        assert data["refresh_expires_in_seconds"] == 1296000  # 15 days

        access_claims = decode_access_token(data["access_token"], check_revocation=False)
        refresh_claims = decode_access_token(data["refresh_token"], check_revocation=False)
        assert access_claims["sub"] == test_email
        assert refresh_claims["sub"] == test_email
        assert refresh_claims["typ"] == "refresh"
        assert "fam" in refresh_claims

        # 2. Sign In
        signin_res = await client.post("/api/v1/auth/signin", json={
            "email": test_email,
            "password": test_pw
        })
        assert signin_res.status_code == 200, signin_res.text
        signin_data = signin_res.json()
        assert "access_token" in signin_data
        assert "refresh_token" in signin_data
        assert signin_data["refresh_token"] != data["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_single_use():
    """Verify that exchanging a refresh token rotates both tokens and invalidates the old refresh token."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        test_email = "rtr_user_2@safeinbox.test"
        test_pw = "Str0ng&Complex#Pass2026!"

        signup_res = await client.post("/api/v1/auth/signup", json={
            "email": test_email,
            "password": test_pw,
            "full_name": "RTR User Two"
        })
        assert signup_res.status_code == 201
        initial_refresh = signup_res.json()["refresh_token"]
        initial_fam = decode_access_token(initial_refresh, check_revocation=False)["fam"]

        # 1. Rotate token
        refresh_res = await client.post("/api/v1/auth/refresh", json={
            "refresh_token": initial_refresh
        })
        assert refresh_res.status_code == 200, refresh_res.text
        rotate_data = refresh_res.json()
        new_access = rotate_data["access_token"]
        new_refresh = rotate_data["refresh_token"]

        assert new_refresh != initial_refresh
        new_fam = decode_access_token(new_refresh, check_revocation=False)["fam"]
        assert new_fam == initial_fam, "Rotated refresh token must remain in the same family"

        # 2. Check old token status in database (must be marked revoked)
        async with AsyncSessionLocal() as session:
            h = hash_token(initial_refresh)
            res = await session.execute(select(RefreshToken).where(RefreshToken.token_hash == h))
            old_record = res.scalar_one_or_none()
            assert old_record is not None
            assert old_record.is_revoked is True


@pytest.mark.asyncio
async def test_refresh_token_reuse_detection_neutralizes_family():
    """Verify that attempting to reuse an already rotated token triggers family invalidation (theft defense)."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        test_email = "rtr_user_3@safeinbox.test"
        test_pw = "Str0ng&Complex#Pass2026!"

        signup_res = await client.post("/api/v1/auth/signup", json={
            "email": test_email,
            "password": test_pw,
            "full_name": "RTR User Three"
        })
        token_1 = signup_res.json()["refresh_token"]

        # First legitimate rotation: token_1 -> token_2
        res1 = await client.post("/api/v1/auth/refresh", json={"refresh_token": token_1})
        assert res1.status_code == 200
        token_2 = res1.json()["refresh_token"]

        # Attacker replays token_1 (reuse detection triggered!)
        res_replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": token_1})
        assert res_replay.status_code == 401
        assert "reuse detected" in res_replay.json()["detail"].lower()

        # Legitimate client tries to use token_2, but it has now been revoked due to family invalidation
        res_victim = await client.post("/api/v1/auth/refresh", json={"refresh_token": token_2})
        assert res_victim.status_code == 401


@pytest.mark.asyncio
async def test_signout_revokes_refresh_tokens():
    """Verify that signout revokes all active refresh tokens for the authenticated user."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        test_email = "rtr_user_4@safeinbox.test"
        test_pw = "Str0ng&Complex#Pass2026!"

        signup_res = await client.post("/api/v1/auth/signup", json={
            "email": test_email,
            "password": test_pw,
            "full_name": "RTR User Four"
        })
        data = signup_res.json()
        access_tok = data["access_token"]
        refresh_tok = data["refresh_token"]

        # Sign out
        signout_res = await client.post("/api/v1/auth/signout", headers={"Authorization": f"Bearer {access_tok}"})
        assert signout_res.status_code == 200

        # Attempt to use refresh token after sign out -> must be rejected
        refresh_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_tok})
        assert refresh_res.status_code == 401
