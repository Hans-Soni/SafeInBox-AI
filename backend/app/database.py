"""Database connection, session management, and table initialization."""

from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool

from app.config import settings

is_sqlite = settings.async_database_url.startswith("sqlite")

engine_kwargs = {
    "echo": False,
    "future": True,
    "pool_pre_ping": True,
}

if is_sqlite:
    engine_kwargs["poolclass"] = NullPool
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # Neon Cloud PostgreSQL / pgBouncer Pooler hardening:
    # Disable asyncpg prepared statement caching for transaction-pooled connections
    # and recycle pooled connections periodically to prevent stale sockets.
    engine_kwargs["pool_recycle"] = 300
    engine_kwargs["connect_args"] = {
        "statement_cache_size": 0,
        "prepared_statement_cache_size": 0,
    }

engine = create_async_engine(
    settings.async_database_url,
    **engine_kwargs
)


AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency yielding asynchronous database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables and synchronize any missing columns/indexes."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Synchronize schema columns across PostgreSQL environments
        dialect = conn.dialect.name
        if dialect == "postgresql":
            statements = [
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS index_id VARCHAR(64)",
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_index_id ON users (index_id)",
                "ALTER TABLE url_clicks ADD COLUMN IF NOT EXISTS user_index_id VARCHAR(64)",
                "CREATE INDEX IF NOT EXISTS ix_url_clicks_user_index_id ON url_clicks (user_index_id)",
                "ALTER TABLE security_digest_logs ADD COLUMN IF NOT EXISTS user_index_id VARCHAR(64)",
                "CREATE INDEX IF NOT EXISTS ix_security_digest_logs_user_index_id ON security_digest_logs (user_index_id)",
                "ALTER TABLE terms_consents ADD COLUMN IF NOT EXISTS user_index_id VARCHAR(64)",
                "CREATE INDEX IF NOT EXISTS ix_terms_consents_user_index_id ON terms_consents (user_index_id)",
                "ALTER TABLE scan_audit_logs ADD COLUMN IF NOT EXISTS user_email VARCHAR(255)",
                "CREATE INDEX IF NOT EXISTS ix_scan_audit_logs_user_email ON scan_audit_logs (user_email)",
                "ALTER TABLE scan_audit_logs ADD COLUMN IF NOT EXISTS user_index_id VARCHAR(64)",
                "CREATE INDEX IF NOT EXISTS ix_scan_audit_logs_user_index_id ON scan_audit_logs (user_index_id)",
                "ALTER TABLE url_clicks ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN DEFAULT FALSE",
                "ALTER TABLE url_clicks ADD COLUMN IF NOT EXISTS encrypted_payload TEXT",
                "ALTER TABLE security_digest_logs ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN DEFAULT FALSE",
                "ALTER TABLE security_digest_logs ADD COLUMN IF NOT EXISTS encrypted_payload TEXT",
                "CREATE TABLE IF NOT EXISTS refresh_tokens (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, user_index_id VARCHAR(64), token_hash VARCHAR(64) UNIQUE NOT NULL, family_id VARCHAR(64) NOT NULL, is_revoked BOOLEAN DEFAULT FALSE NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL)",
                "CREATE INDEX IF NOT EXISTS ix_refresh_tokens_token_hash ON refresh_tokens (token_hash)",
                "CREATE INDEX IF NOT EXISTS ix_refresh_tokens_family_id ON refresh_tokens (family_id)",
                "CREATE INDEX IF NOT EXISTS ix_refresh_tokens_user_id ON refresh_tokens (user_id)",
            ]
            for stmt in statements:
                try:
                    await conn.execute(text(stmt))
                except Exception:
                    pass

