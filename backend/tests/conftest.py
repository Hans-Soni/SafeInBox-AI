"""Shared pytest configuration and test fixtures for SafeInbox AI Backend."""

import pytest
from sqlalchemy import delete

from app.database import AsyncSessionLocal, init_db
from app.models.threat import FeedbackRecord, ScanAuditLog, ThreatURL
from app.models.user import TermsConsent, User


@pytest.fixture(autouse=True)
async def prepare_database():
    """Ensure database tables are initialized and clean before each test."""
    await init_db()
    async with AsyncSessionLocal() as session:
        await session.execute(delete(ThreatURL))
        await session.execute(delete(FeedbackRecord))
        await session.execute(delete(ScanAuditLog))
        await session.execute(delete(TermsConsent))
        await session.execute(delete(User))
        await session.commit()


