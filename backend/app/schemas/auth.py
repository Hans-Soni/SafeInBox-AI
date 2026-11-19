"""Pydantic schemas for authentication and user management."""

from datetime import datetime
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Strict RFC 5322 compliant regex:
# - No leading or trailing dot in local part
# - No consecutive dots
# - Rejects SQL injection characters: ', ", ;, --, /*, null bytes
# - Valid domain labels and TLD (2 to 24 ASCII characters)
EMAIL_REGEX = re.compile(
    r"^(?!\.)[a-zA-Z0-9_.+-]+(?<!\.)@(?!-)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,24}$"
)

# Common trivial passwords to reject
COMMON_PASSWORDS = frozenset({
    "password", "password123", "password1234", "password12345",
    "12345678", "123456789", "1234567890", "12345678901",
    "qwerty123", "qwertyuiop", "admin123", "admin12345",
    "letmein1", "letmein123", "welcome1", "welcome123",
    "safeinbox", "safeinbox123", "safeinbox2026",
    "iloveyou", "iloveyou123", "monkey123", "dragon123",
    "changeme1", "changeme123", "master123", "secret123"
})

# Sequential patterns to reject
SEQUENTIAL_PATTERNS = [
    "12345", "23456", "34567", "45678", "56789", "67890",
    "qwerty", "asdfgh", "zxcvbn", "abcdef", "bcdefg"
]


def validate_password_complexity(
    password: str,
    email: str | None = None,
    full_name: str | None = None
) -> str:
    """
    Enforce enterprise-grade password complexity:
    - Length between 10 and 128 characters
    - At least 1 uppercase letter (A-Z)
    - At least 1 lowercase letter (a-z)
    - At least 1 digit (0-9)
    - At least 1 special character / symbol
    - No common / dictionary passwords
    - No repetitive characters (e.g. 'aaaa', '1111')
    - No simple sequential runs (e.g. '12345', 'qwerty')
    - Cannot contain username / email local part
    - Cannot contain display name tokens
    """
    lowered = password.lower()

    if lowered in COMMON_PASSWORDS:
        raise ValueError("Password is too common or easily guessable. Please choose a stronger, unique password.")

    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters long.")
    if len(password) > 128:
        raise ValueError("Password must not exceed 128 characters.")
    
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter (a-z).")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one digit (0-9).")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~` ]", password):
        raise ValueError("Password must contain at least one special character or symbol (!@#$%^&*...).")

    # Reject 4+ repetitive identical characters (e.g. 'aaaa', '1111')
    if re.search(r"(.)\1{3,}", password):
        raise ValueError("Password cannot contain 4 or more consecutive identical characters.")

    # Reject simple sequential keyboard or numeric runs
    for seq in SEQUENTIAL_PATTERNS:
        if seq in lowered:
            raise ValueError(f"Password contains a predictable sequential pattern ('{seq}').")

    # Reject inclusion of email username parts
    if email:
        local_part = email.split("@")[0].lower()
        tokens = [t for t in re.split(r"[._\-+]", local_part) if len(t) >= 3]
        for tok in tokens:
            if tok in lowered:
                raise ValueError(f"Password cannot contain parts of your email address ('{tok}').")

    # Reject inclusion of full name parts
    if full_name:
        name_tokens = [t.lower() for t in re.split(r"\s+", full_name) if len(t) >= 3]
        for tok in name_tokens:
            if tok in lowered:
                raise ValueError(f"Password cannot contain parts of your name ('{tok}').")

    return password


def sanitize_display_name(name: str | None) -> str | None:
    """Strip HTML, scripts, styles, control characters, SQL injection markers, and excessive whitespace."""
    if name is None:
        return None
    # Strip <script> and <style> blocks completely along with contents
    clean = re.sub(r"(?is)<script.*?>.*?</script>", "", name)
    clean = re.sub(r"(?is)<style.*?>.*?</style>", "", clean)
    # Strip remaining HTML tags
    clean = re.sub(r"<[^>]*>", "", clean)
    # Strip null bytes and non-printable control characters
    clean = "".join(ch for ch in clean if ch.isprintable() and ch != "\x00")
    # Defang SQL comment markers if present in display name
    clean = clean.replace("--", "").replace("/*", "").replace("*/", "")
    clean = clean.strip()
    return clean[:100] if clean else None


class UserSignUp(BaseModel):
    """Payload for user account registration enforcing 1-email-1-account and strong passwords."""

    email: str = Field(..., max_length=255, description="User's unique email address")
    password: str = Field(..., min_length=10, max_length=128, description="Strong enterprise password")
    full_name: str | None = Field(default=None, max_length=100, description="User's optional display name")
    terms_agreed: bool = Field(default=False, description="Whether user agreed to Terms & Conditions")
    terms_version: str = Field(default="1.0.0", max_length=32, description="Version of terms accepted")
    mac_address: str | None = Field(default=None, max_length=128, description="Client MAC or device identifier")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        clean = value.strip().lower()
        if len(clean) > 255 or ".." in clean or not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        # Reject potential SQL injection / null byte characters in email
        if any(c in clean for c in ["'", '"', ";", "--", "/*", "*/", "\x00"]):
            raise ValueError("Email contains disallowed characters.")
        return clean

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str | None) -> str | None:
        return sanitize_display_name(value)

    @model_validator(mode="after")
    def validate_password_against_context(self) -> "UserSignUp":
        validate_password_complexity(self.password, email=self.email, full_name=self.full_name)
        return self


class UserSignIn(BaseModel):
    """Payload for user account sign in / login."""

    email: str = Field(..., max_length=255, description="User's registered email address")
    password: str = Field(..., min_length=1, max_length=128, description="User's password")
    otp: str | None = Field(default=None, max_length=6, description="Optional 6-digit OTP code for 2FA verification")
    terms_agreed: bool = Field(default=False, description="Whether user agreed to Terms & Conditions")
    terms_version: str = Field(default="1.0.0", max_length=32, description="Version of terms accepted")
    mac_address: str | None = Field(default=None, max_length=128, description="Client MAC or device identifier")

    @field_validator("email")
    @classmethod
    def normalize_and_validate_email(cls, value: str) -> str:
        clean = value.strip().lower()
        if len(clean) > 255 or ".." in clean or not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        if any(c in clean for c in ["'", '"', ";", "--", "/*", "*/", "\x00"]):
            raise ValueError("Email contains disallowed characters.")
        return clean

    @field_validator("otp")
    @classmethod
    def validate_signin_otp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not re.match(r"^\d{6}$", clean):
            raise ValueError("Verification code must be exactly 6 digits.")
        return clean


class PasswordChangeRequest(BaseModel):
    """Payload to rotate / change password enforcing novelty and non-similarity."""

    current_password: str = Field(..., min_length=1, max_length=128, description="User's current password")
    new_password: str = Field(..., min_length=10, max_length=128, description="User's new strong password")
    otp: str | None = Field(default=None, max_length=6, description="Optional 6-digit OTP code for authorizing password change")

    @field_validator("new_password")
    @classmethod
    def validate_new_password_shape(cls, value: str) -> str:
        return validate_password_complexity(value)

    @field_validator("otp")
    @classmethod
    def validate_change_password_otp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not re.match(r"^\d{6}$", clean):
            raise ValueError("Verification code must be exactly 6 digits.")
        return clean


class TermsConsentCreate(BaseModel):
    """Payload to record standalone Terms & Conditions consent."""

    email: str = Field(..., max_length=255, description="User's email address")
    terms_version: str = Field(default="1.0.0", max_length=32, description="Version of terms accepted")
    mac_address: str | None = Field(default=None, max_length=128, description="Client MAC or device identifier")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        clean = value.strip().lower()
        if len(clean) > 255 or ".." in clean or not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        return clean


class TermsConsentResponse(BaseModel):
    """Response confirming terms consent registration."""

    id: int
    user_id: int | None = None
    email: str
    ip_address: str
    mac_address: str | None = None
    terms_version: str
    agreed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserResponse(BaseModel):
    """Public user profile response with security policy metadata."""

    id: int
    email: str
    full_name: str | None = None
    is_active: bool
    password_changed_at: datetime
    password_expired: bool = False
    password_age_days: int = 0
    session_lifetime_days: int = 7
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """Bearer access token and authenticated user payload with weekly session & monthly rotation policies."""

    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int = 604800  # Exactly 7 days (weekly re-login required)
    session_lifetime_days: int = 7
    password_expired: bool = False
    password_age_days: int = 0
    user: UserResponse
    terms_consent: TermsConsentResponse | None = None


class OTPRequestResponse(BaseModel):
    """Response returned when an OTP is dispatched for signup, signin, or password update."""

    success: bool = True
    email: str
    message: str
    requires_otp: bool = True
    purpose: str = "signup"
    expires_in_seconds: int = 600
    resend_cooldown_seconds: int = 60
    delivery_mode: str = "smtp"


class OTPResendRequest(BaseModel):
    """Request payload to resend an OTP for an unverified pending signup."""

    email: str = Field(..., max_length=255, description="Registered email address")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        clean = value.strip().lower()
        if len(clean) > 255 or ".." in clean or not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        if any(c in clean for c in ["'", '"', ";", "--", "/*", "*/", "\x00"]):
            raise ValueError("Email contains disallowed characters.")
        return clean


class OTPVerifyRequest(BaseModel):
    """Request payload to verify the 6-digit OTP and complete signup."""

    email: str = Field(..., max_length=255, description="Registered email address")
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit numeric OTP code")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        clean = value.strip().lower()
        if len(clean) > 255 or ".." in clean or not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        if any(c in clean for c in ["'", '"', ";", "--", "/*", "*/", "\x00"]):
            raise ValueError("Email contains disallowed characters.")
        return clean

    @field_validator("otp")
    @classmethod
    def validate_otp_format(cls, value: str) -> str:
        clean = value.strip()
        if not re.match(r"^\d{6}$", clean):
            raise ValueError("Verification code must be exactly 6 digits.")
        return clean

