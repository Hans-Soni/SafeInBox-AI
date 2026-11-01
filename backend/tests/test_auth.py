"""Integration tests for User Sign Up, Sign In, and Authentication API endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.auth_service import hash_password, verify_password


@pytest.mark.asyncio
async def test_password_hashing_and_verification():
    """Verify scrypt password hashing and constant-time verification."""
    password = "SuperSecurePassword123!"
    hashed = hash_password(password)

    assert hashed.startswith("scrypt$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False


@pytest.mark.asyncio
async def test_user_signup_and_duplicate_prevention():
    """Test successful user registration and duplicate email rejection."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. Successful Sign Up
        signup_payload = {
            "email": "analyst@safeinbox.ai",
            "password": "StrongSecurityPassword2026!",
            "full_name": "Security Analyst"
        }
        resp = await client.post("/api/v1/auth/signup", json=signup_payload)
        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "analyst@safeinbox.ai"
        assert data["user"]["full_name"] == "Security Analyst"
        assert data["user"]["is_active"] is True
        assert "password" not in data["user"]
        assert "hashed_password" not in data["user"]

        # 2. Duplicate registration with same email (case-insensitive)
        dup_resp = await client.post("/api/v1/auth/signup", json={
            "email": "ANALYST@SAFEINBOX.AI",
            "password": "AnotherPassword123!",
            "full_name": "Clone User"
        })
        assert dup_resp.status_code == 400
        assert "already registered" in dup_resp.json()["detail"]


@pytest.mark.asyncio
async def test_user_signup_validation_errors():
    """Test rejection of invalid emails and short passwords."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Weak password (< 8 chars)
        short_pw_resp = await client.post("/api/v1/auth/signup", json={
            "email": "short@example.com",
            "password": "short"
        })
        assert short_pw_resp.status_code == 422

        # Invalid email format
        bad_email_resp = await client.post("/api/v1/auth/signup", json={
            "email": "not-an-email",
            "password": "ValidPassword123!"
        })
        assert bad_email_resp.status_code == 422


@pytest.mark.asyncio
async def test_user_signin_and_authentication_flow():
    """Test user sign in, login alias, and invalid credentials rejection."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Register a test account
        user_email = "testuser@safeinbox.ai"
        user_password = "PasswordForTesting123!"
        await client.post("/api/v1/auth/signup", json={
            "email": user_email,
            "password": user_password,
            "full_name": "Test User"
        })

        # 1. Successful Sign In
        signin_resp = await client.post("/api/v1/auth/signin", json={
            "email": user_email,
            "password": user_password
        })
        assert signin_resp.status_code == 200
        token_data = signin_resp.json()
        assert "access_token" in token_data
        token = token_data["access_token"]

        # 2. Login Alias (/login)
        login_resp = await client.post("/api/v1/auth/login", json={
            "email": user_email,
            "password": user_password
        })
        assert login_resp.status_code == 200

        # 3. Wrong password
        wrong_pw_resp = await client.post("/api/v1/auth/signin", json={
            "email": user_email,
            "password": "IncorrectPassword!"
        })
        assert wrong_pw_resp.status_code == 401
        assert "Invalid email or password" in wrong_pw_resp.json()["detail"]

        # 4. Non-existent user
        no_user_resp = await client.post("/api/v1/auth/signin", json={
            "email": "unknown@safeinbox.ai",
            "password": user_password
        })
        assert no_user_resp.status_code == 401

        # 5. Access protected /me endpoint with Bearer token
        me_resp = await client.get("/api/v1/auth/me", headers={
            "Authorization": f"Bearer {token}"
        })
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["email"] == user_email
        assert me_data["full_name"] == "Test User"

        # 6. Access /me without token or with invalid token
        unauth_resp = await client.get("/api/v1/auth/me")
        assert unauth_resp.status_code == 401

        bad_token_resp = await client.get("/api/v1/auth/me", headers={
            "Authorization": "Bearer invalid.token.payload"
        })
        assert bad_token_resp.status_code == 401


@pytest.mark.asyncio
async def test_terms_and_conditions_consent_logging():
    """Verify terms consent logging on sign-in, sign-up, and direct consent endpoints."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. Sign up with terms agreement
        signup_payload = {
            "email": "compliance@safeinbox.ai",
            "password": "CompliantPassword2026!",
            "full_name": "Compliance Officer",
            "terms_agreed": True,
            "terms_version": "1.0.0",
            "mac_address": "00:1A:2B:3C:4D:5E"
        }
        res_signup = await client.post("/api/v1/auth/signup", json=signup_payload)
        assert res_signup.status_code == 201
        data_signup = res_signup.json()
        assert data_signup["terms_consent"] is not None
        assert data_signup["terms_consent"]["email"] == "compliance@safeinbox.ai"
        assert data_signup["terms_consent"]["terms_version"] == "1.0.0"
        assert data_signup["terms_consent"]["mac_address"] == "00:1A:2B:3C:4D:5E"
        assert "ip_address" in data_signup["terms_consent"]
        assert "agreed_at" in data_signup["terms_consent"]

        # 2. Check consent status query
        status_res = await client.get("/api/v1/auth/terms-consent/status?email=compliance@safeinbox.ai")
        assert status_res.status_code == 200
        assert status_res.json()["consented"] is True
        assert status_res.json()["terms_version"] == "1.0.0"

        # 3. Sign in with terms agreement
        signin_payload = {
            "email": "compliance@safeinbox.ai",
            "password": "CompliantPassword2026!",
            "terms_agreed": True,
            "terms_version": "1.0.0",
            "mac_address": "00:1A:2B:3C:4D:5E"
        }
        res_signin = await client.post("/api/v1/auth/signin", json=signin_payload)
        assert res_signin.status_code == 200
        data_signin = res_signin.json()
        assert data_signin["terms_consent"] is not None
        assert data_signin["terms_consent"]["email"] == "compliance@safeinbox.ai"

        # 4. Standalone terms consent submission
        standalone_payload = {
            "email": "guest-analyst@safeinbox.ai",
            "terms_version": "1.0.0",
            "mac_address": "N/A (Browser Sandbox Restricted: W3C Anti-Fingerprinting Policy)"
        }
        res_standalone = await client.post("/api/v1/auth/terms-consent", json=standalone_payload)
        assert res_standalone.status_code == 201
        data_standalone = res_standalone.json()
        assert data_standalone["email"] == "guest-analyst@safeinbox.ai"
        assert data_standalone["terms_version"] == "1.0.0"
        assert "ip_address" in data_standalone
        assert "agreed_at" in data_standalone


