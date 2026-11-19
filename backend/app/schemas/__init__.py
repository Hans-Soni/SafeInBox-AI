"""Schemas package exports."""

from app.schemas.url_scan import (
    URLScanRequest,
    URLScanResponse,
    UrlClickCreate,
    UrlClickResponse,
    ScanAuditCreate,
    ScanAuditResponse,
)
from app.schemas.email_scan import EmailScanRequest, EmailScanResponse
from app.schemas.feedback import FeedbackRequest, FeedbackResponse, HealthResponse
from app.schemas.auth import (
    UserSignUp,
    UserSignIn,
    UserResponse,
    TokenResponse,
    TermsConsentCreate,
    TermsConsentResponse,
    OTPRequestResponse,
    OTPResendRequest,
    OTPVerifyRequest,
)

__all__ = [
    "URLScanRequest",
    "URLScanResponse",
    "UrlClickCreate",
    "UrlClickResponse",
    "ScanAuditCreate",
    "ScanAuditResponse",
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
    "OTPRequestResponse",
    "OTPResendRequest",
    "OTPVerifyRequest",
]
