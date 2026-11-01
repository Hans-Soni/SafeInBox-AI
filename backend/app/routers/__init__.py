"""Routers package exports."""

from app.routers.url import router as url_router
from app.routers.email import router as email_router
from app.routers.feedback import router as feedback_router
from app.routers.health import router as health_router
from app.routers.auth import router as auth_router

__all__ = ["url_router", "email_router", "feedback_router", "health_router", "auth_router"]

