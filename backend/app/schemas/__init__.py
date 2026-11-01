"""Schemas package exports."""

from app.schemas.url_scan import URLScanRequest, URLScanResponse
from app.schemas.email_scan import EmailScanRequest, EmailScanResponse
from app.schemas.feedback import FeedbackRequest, FeedbackResponse, HealthResponse
from app.schemas.auth import (
    UserSignUp,
    UserSignIn,
    UserResponse,
    TokenResponse,
    TermsConsentCreate,
    TermsConsentResponse
)

__all__ = [
    "URLScanRequest",
    "URLScanResponse",
    "EmailScanRequest",
    "EmailScanResponse",
    "FeedbackRequest",
    "FeedbackResponse",
    "HealthResponse",
    "UserSignUp",
    "UserSignIn",
    "UserResponse",
    "TokenResponse",
    "TermsConsentCreate",
    "TermsConsentResponse",
]


