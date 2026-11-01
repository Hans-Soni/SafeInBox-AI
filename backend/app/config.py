"""Configuration settings for SafeInbox AI Backend."""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    PROJECT_NAME: str = "SafeInbox AI Cloud Intelligence API"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"

    # Database: Default to asynchronous SQLite for local/testing, or PostgreSQL on Cloud
    DATABASE_URL: str = "sqlite+aiosqlite:///./safeinbox.db"

    # CORS configuration - Allow all for extensions (chrome-extension://*) and local dev
    CORS_ORIGINS: list[str] = ["*"]

    # Security & Rate Limiting
    SECRET_KEY: str = "safeinbox-ai-secret-key-change-in-production-2026-secure"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    MAX_EMAIL_BODY_CHARS: int = 1_000_000  # 1 MB limit
    MAX_URL_LENGTH: int = 4096
    MAX_FEEDBACK_ENTRIES: int = 1000

    # Protocol & Transport Security (HTTPS & TCP only)
    FORCE_HTTPS: bool = False
    HSTS_MAX_AGE_SECONDS: int = 63_072_000  # 2 years HSTS
    HSTS_INCLUDE_SUBDOMAINS: bool = True
    HSTS_PRELOAD: bool = True
    ALLOWED_HOSTS: list[str] = ["*"]

    # Optional Google Web Risk / Safe Browsing API integration
    WEB_RISK_API_KEY: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def is_https_enforced(self) -> bool:
        """Enforce HTTPS in production or when explicitly configured."""
        return self.FORCE_HTTPS or self.ENVIRONMENT.lower() == "production"

    @property
    def async_database_url(self) -> str:
        """Ensure PostgreSQL connection URLs use asyncpg driver and clean SSL parameters for asyncpg."""
        url = self.DATABASE_URL
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

        # Enforce clean SSL/TLS query parameters for asyncpg driver
        if url.startswith("postgresql+asyncpg://"):
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            # asyncpg expects 'ssl', NOT 'sslmode' or 'channel_binding'
            qs.pop("sslmode", None)
            qs.pop("channel_binding", None)
            is_remote = "localhost" not in parsed.netloc and "127.0.0.1" not in parsed.netloc
            if is_remote and "ssl" not in qs:
                qs["ssl"] = ["require"]
            new_query = urlencode(qs, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))

        return url


settings = Settings()

