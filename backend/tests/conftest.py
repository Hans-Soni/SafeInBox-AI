"""Shared pytest configuration and test fixtures for SafeInbox AI Backend."""

import os
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_safeinbox.db"
os.environ["FORCE_HTTPS"] = "false"

import pytest
from sqlalchemy import delete

from app.database import AsyncSessionLocal, init_db
from app.models.threat import FeedbackRecord, ScanAuditLog, ThreatURL
from app.models.user import TermsConsent, User
from app.services.auth_service import auth_limiter


@pytest.fixture(autouse=True)
async def prepare_database():
    """Ensure database tables and rate limiters are initialized and clean before each test."""
    auth_limiter.reset()
    await init_db()
    async with AsyncSessionLocal() as session:
        await session.execute(delete(ThreatURL))
        await session.execute(delete(FeedbackRecord))
        await session.execute(delete(ScanAuditLog))
        await session.execute(delete(TermsConsent))
        await session.execute(delete(User))
        await session.commit()


