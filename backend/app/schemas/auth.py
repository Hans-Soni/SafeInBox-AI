"""Pydantic schemas for authentication and user management."""

from datetime import datetime
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class UserSignUp(BaseModel):
    """Payload for user account registration."""

    email: str = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, max_length=128, description="Password (at least 8 characters)")
    full_name: str | None = Field(default=None, max_length=255, description="User's optional display name")
    terms_agreed: bool = Field(default=False, description="Whether user agreed to Terms & Conditions")
    terms_version: str = Field(default="1.0.0", description="Version of terms accepted")
    mac_address: str | None = Field(default=None, description="Client MAC or device hardware identifier if available")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        clean = value.strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        return clean

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        return value


class UserSignIn(BaseModel):
    """Payload for user account sign in / login."""

    email: str = Field(..., description="User's registered email address")
    password: str = Field(..., description="User's password")
    terms_agreed: bool = Field(default=False, description="Whether user agreed to Terms & Conditions")
    terms_version: str = Field(default="1.0.0", description="Version of terms accepted")
    mac_address: str | None = Field(default=None, description="Client MAC or device hardware identifier if available")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class TermsConsentCreate(BaseModel):
    """Payload to record standalone Terms & Conditions consent."""

    email: str = Field(..., description="User's email address")
    terms_version: str = Field(default="1.0.0", description="Version of terms accepted")
    mac_address: str | None = Field(default=None, description="Client MAC or device hardware identifier if available")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        clean = value.strip().lower()
        if not EMAIL_REGEX.match(clean):
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
    """Public user profile response."""

    id: int
    email: str
    full_name: str | None = None
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """Bearer access token and authenticated user payload."""

    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    terms_consent: TermsConsentResponse | None = None


