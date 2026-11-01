"""Main FastAPI application entrypoint for SafeInbox AI Cloud Backend."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.config import settings
from app.database import init_db
from app.routers import auth_router, email_router, feedback_router, health_router, url_router


class SecurityTransportMiddleware(BaseHTTPMiddleware):
    """Enforces HTTPS and attaches strict transport & defense-in-depth headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Check protocol scheme (accounting for Cloud Run / reverse-proxy X-Forwarded-Proto)
        proto = request.headers.get("x-forwarded-proto", request.url.scheme).lower()
        host = request.headers.get("host", request.url.hostname or "").split(":")[0].lower()
        is_local = host in ("localhost", "127.0.0.1", "testserver")

        # In production or when FORCE_HTTPS is true, enforce HTTPS strictly
        if settings.is_https_enforced and proto != "https" and not is_local:
            if request.method in ("GET", "HEAD"):
                secure_url = str(request.url.replace(scheme="https"))
                return RedirectResponse(url=secure_url, status_code=status.HTTP_308_PERMANENT_REDIRECT)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "HTTPS required. Insecure plain HTTP access is blocked."}
            )

        # Validate host if restricted
        if settings.ALLOWED_HOSTS and settings.ALLOWED_HOSTS != ["*"]:
            if host not in settings.ALLOWED_HOSTS and not is_local:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid Host header."}
                )

        response = await call_next(request)

        # Enforce HSTS (Strict-Transport-Security)
        hsts_value = f"max-age={settings.HSTS_MAX_AGE_SECONDS}"
        if settings.HSTS_INCLUDE_SUBDOMAINS:
            hsts_value += "; includeSubDomains"
        if settings.HSTS_PRELOAD:
            hsts_value += "; preload"
        response.headers["Strict-Transport-Security"] = hsts_value

        # Content and Framing Defenses
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none';"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle handler."""
    # Initialize database tables
    await init_db()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Cloud Intelligence & Threat Scanning API for SafeInbox AI Browser Extension.",
    lifespan=lifespan
)

# Security and HTTPS enforcement middleware
app.add_middleware(SecurityTransportMiddleware)

# CORS configuration allowing Chrome extensions and web apps
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(url_router)
app.include_router(email_router)
app.include_router(feedback_router)


@app.get("/")
async def root() -> dict[str, str]:
    """Root metadata endpoint."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "docs_url": "/docs"
    }

