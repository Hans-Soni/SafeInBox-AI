"""Authentication endpoints for User Sign Up, Sign In, and Session Validation."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import TermsConsent, User
from app.schemas.auth import (
    TermsConsentCreate,
    TermsConsentResponse,
    TokenResponse,
    UserResponse,
    UserSignIn,
    UserSignUp
)
from app.services.auth_service import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def utcnow() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def get_client_ip(request: Request) -> str:
    """Extract client IP address handling proxies and forward headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


async def record_terms_consent(
    db: AsyncSession,
    email: str,
    ip_address: str,
    mac_address: str | None,
    terms_version: str,
    user_id: int | None = None,
    user_agent: str | None = None
) -> TermsConsent:
    """Persist an immutable Terms & Conditions consent audit record."""
    resolved_mac = mac_address or "N/A (Browser Sandbox Restricted: W3C Anti-Fingerprinting Policy)"
    consent = TermsConsent(
        user_id=user_id,
        email=email,
        ip_address=ip_address,
        mac_address=resolved_mac,
        terms_version=terms_version or "1.0.0",
        user_agent=(user_agent or "")[:512],
        agreed_at=utcnow()
    )
    db.add(consent)
    await db.commit()
    await db.refresh(consent)
    return consent


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def sign_up(
    payload: UserSignUp,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """Register a new user account and return Bearer authentication token."""
    # Check for existing user with this email
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email is already registered."
        )

    # Hash password and create new user
    new_user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name.strip() if payload.full_name else None,
        is_active=True
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Record terms consent if agreed
    consent_resp = None
    if payload.terms_agreed:
        ip = get_client_ip(request)
        ua = request.headers.get("User-Agent")
        consent_record = await record_terms_consent(
            db=db,
            email=new_user.email,
            ip_address=ip,
            mac_address=payload.mac_address,
            terms_version=payload.terms_version,
            user_id=new_user.id,
            user_agent=ua
        )
        consent_resp = TermsConsentResponse.model_validate(consent_record)

    # Issue access token
    token = create_access_token({"sub": new_user.email, "user_id": new_user.id})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(new_user),
        terms_consent=consent_resp
    )


@router.post("/signin", response_model=TokenResponse)
async def sign_in(
    payload: UserSignIn,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """Authenticate an existing user with email and password and return Bearer token."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated."
        )

    # Record terms consent if agreed during sign in
    consent_resp = None
    if payload.terms_agreed:
        ip = get_client_ip(request)
        ua = request.headers.get("User-Agent")
        consent_record = await record_terms_consent(
            db=db,
            email=user.email,
            ip_address=ip,
            mac_address=payload.mac_address,
            terms_version=payload.terms_version,
            user_id=user.id,
            user_agent=ua
        )
        consent_resp = TermsConsentResponse.model_validate(consent_record)

    token = create_access_token({"sub": user.email, "user_id": user.id})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        terms_consent=consent_resp
    )


@router.post("/login", response_model=TokenResponse, include_in_schema=False)
async def login_alias(
    payload: UserSignIn,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """Alias for /signin endpoint."""
    return await sign_in(payload, request, db)


@router.post("/terms-consent", response_model=TermsConsentResponse, status_code=status.HTTP_201_CREATED)
async def submit_terms_consent(
    payload: TermsConsentCreate,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TermsConsentResponse:
    """Record affirmative consent to project Terms & Conditions and Privacy Policy."""
    user_res = await db.execute(select(User).where(User.email == payload.email))
    user = user_res.scalar_one_or_none()
    user_id = user.id if user else None

    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    consent_record = await record_terms_consent(
        db=db,
        email=payload.email,
        ip_address=ip,
        mac_address=payload.mac_address,
        terms_version=payload.terms_version,
        user_id=user_id,
        user_agent=ua
    )
    return TermsConsentResponse.model_validate(consent_record)


@router.get("/terms-consent/status")
async def get_terms_consent_status(
    email: str,
    db: AsyncSession = Depends(get_db)
) -> dict:
    """Check whether an email address has recorded consent to the terms."""
    clean_email = email.strip().lower()
    stmt = (
        select(TermsConsent)
        .where(TermsConsent.email == clean_email)
        .order_by(TermsConsent.agreed_at.desc())
    )
    res = await db.execute(stmt)
    latest = res.scalars().first()
    if not latest:
        return {"consented": False, "email": clean_email}
    return {
        "consented": True,
        "email": clean_email,
        "terms_version": latest.terms_version,
        "ip_address": latest.ip_address,
        "mac_address": latest.mac_address,
        "agreed_at": latest.agreed_at.isoformat()
    }


@router.get("/me", response_model=UserResponse)
async def get_my_profile(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """Retrieve profile of the currently authenticated user."""
    return UserResponse.model_validate(current_user)


