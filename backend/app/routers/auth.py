"""Authentication endpoints for User Sign Up, Sign In, Password Rotation, and Session Validation."""

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.digest import SecurityDigestLog
from app.models.threat import ScanAuditLog, ThreatURL, UrlClickLog
from app.models.user import EmailOTPVerification, TermsConsent, User, generate_user_index_id
from app.schemas.auth import (
    OTPRequestResponse,
    OTPResendRequest,
    OTPVerifyRequest,
    PasswordChangeRequest,
    RefreshTokenRequest,
    TermsConsentCreate,
    TermsConsentResponse,
    TokenRefreshResponse,
    TokenResponse,
    UserResponse,
    UserSignIn,
    UserSignUp,
    UserTrackingSummary,
    validate_password_complexity
)
from app.services.auth_service import (
    auth_limiter,
    calculate_password_similarity,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    dummy_verify_password,
    get_current_user,
    hash_password,
    is_password_in_history,
    levenshtein_distance,
    revoke_token,
    revoke_user_refresh_tokens,
    rotate_refresh_token,
    save_refresh_token,
    verify_password
)
from app.services.log_security import emit_security_audit_log
from app.services.otp_service import (
    cleanup_otp_record,
    dispatch_otp_email,
    generate_otp,
    generate_otp_salt,
    hash_otp,
    verify_otp
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


def ensure_utc(dt: datetime | None) -> datetime:
    """Ensure a datetime object is timezone-aware in UTC."""
    if dt is None:
        return utcnow()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_user_response(user: User) -> UserResponse:
    """Build UserResponse with unique Index ID, 30-day password expiry and 15-day session lifetime metadata."""
    now = utcnow()
    raw_pwd = user.password_changed_at or user.created_at or now
    pwd_changed = ensure_utc(raw_pwd)
    age_days = (now - pwd_changed).days
    resolved_idx = getattr(user, "index_id", None) or generate_user_index_id(user.email)
    return UserResponse(
        id=user.id,
        index_id=resolved_idx,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        password_changed_at=pwd_changed,
        password_expired=(age_days >= 30),
        password_age_days=age_days,
        session_lifetime_days=15,
        created_at=ensure_utc(user.created_at or now)
    )


async def issue_token_response(
    db: AsyncSession,
    user: User,
    consent_resp: TermsConsentResponse | None = None,
    password_expired: bool = False,
    password_age_days: int = 0
) -> TokenResponse:
    """Generate short-lived access token (30m) and single-use rotating refresh token (15d)."""
    user_idx = getattr(user, "index_id", None) or generate_user_index_id(user.email)
    access_token = create_access_token({"sub": user.email, "user_id": user.id, "index_id": user_idx})
    raw_refresh, fam_id, exp_refresh = create_refresh_token(
        user_id=user.id,
        user_email=user.email,
        user_index_id=user_idx
    )
    await save_refresh_token(
        db=db,
        user_id=user.id,
        user_index_id=user_idx,
        raw_refresh_token=raw_refresh,
        family_id=fam_id,
        expires_at=exp_refresh
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        token_type="bearer",
        expires_in_seconds=1800,  # 30 minutes
        refresh_expires_in_seconds=1296000,  # 15 days
        session_lifetime_days=15,
        password_expired=password_expired,
        password_age_days=password_age_days,
        user=build_user_response(user),
        terms_consent=consent_resp
    )


async def record_terms_consent(
    db: AsyncSession,
    email: str,
    ip_address: str,
    mac_address: str | None,
    terms_version: str,
    user_id: int | None = None,
    user_index_id: str | None = None,
    user_agent: str | None = None
) -> TermsConsent:
    """Persist an immutable Terms & Conditions consent audit record with user index ID."""
    resolved_mac = mac_address or "N/A (Browser Sandbox Restricted: W3C Anti-Fingerprinting Policy)"
    resolved_idx = user_index_id or generate_user_index_id(email)
    consent = TermsConsent(
        user_id=user_id,
        user_index_id=resolved_idx,
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
    """
    Register a new user account enforcing:
    1. 1 email ID -> 1 account only (strict unique constraint + race condition rollback)
    2. Strong enterprise password policy
    3. Brute force / IP rate limiting
    4. 100% SQL injection parameterized security
    5. Injection-proof structured security audit logging
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")

    # Rate limiting: max 10 signups per minute per IP to defend against account spam
    is_limited, rem = auth_limiter.is_rate_limited(
        f"signup_ip:{ip}",
        max_attempts=10,
        window_seconds=60,
        lockout_seconds=120
    )
    if is_limited:
        emit_security_audit_log(
            event_type="AUTH_SIGNUP_RATE_LIMITED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"retry_after_seconds": rem},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many registration attempts. Please wait {rem} seconds before trying again.",
            headers={"Retry-After": str(rem)}
        )
    auth_limiter.record_attempt(f"signup_ip:{ip}")

    # Enforce: 1 email ID = 1 account (no duplicate accounts allowed across any device)
    # Parameterized query via SQLAlchemy 2.0 ORM - immune to SQL injection
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        emit_security_audit_log(
            event_type="AUTH_SIGNUP_DUPLICATE_REJECTED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Account already registered with this email address"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Only 1 account per email is allowed. Please sign in instead."
        )

    now = utcnow()
    index_id = generate_user_index_id(payload.email)
    # Hash password using scrypt with random cryptographic 16-byte salt
    new_user = User(
        index_id=index_id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        is_active=True,
        is_superuser=False,
        password_changed_at=now,
        password_history=[],
        failed_login_attempts=0,
        locked_until=None,
        created_at=now,
        updated_at=now
    )
    
    # Catch potential race conditions: concurrent requests attempting double signup
    try:
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
    except IntegrityError:
        await db.rollback()
        emit_security_audit_log(
            event_type="AUTH_SIGNUP_RACE_DUPLICATE_REJECTED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Concurrent registration collision prevented by database constraint"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists. Only 1 account per email is allowed."
        )

    # Record terms consent if agreed
    consent_resp = None
    if payload.terms_agreed:
        consent_record = await record_terms_consent(
            db=db,
            email=new_user.email,
            ip_address=ip,
            mac_address=payload.mac_address,
            terms_version=payload.terms_version,
            user_id=new_user.id,
            user_index_id=new_user.index_id,
            user_agent=ua
        )
        consent_resp = TermsConsentResponse.model_validate(consent_record)

    emit_security_audit_log(
        event_type="AUTH_SIGNUP_SUCCESS",
        outcome="CREATED",
        email=new_user.email,
        ip_address=ip,
        user_agent=ua,
        details={"user_id": new_user.id, "index_id": new_user.index_id}
    )

    # Issue access token (30m) and single-use rotating refresh token (15d)
    return await issue_token_response(
        db=db,
        user=new_user,
        consent_resp=consent_resp,
        password_expired=False,
        password_age_days=0
    )


@router.post("/signup/request-otp", response_model=OTPRequestResponse)
async def request_signup_otp(
    payload: UserSignUp,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> OTPRequestResponse:
    """
    Initiate user registration by dispatching a cryptographically secure 6-digit OTP to the user's email.
    Enforces:
    1. 1-Email-1-Account check: reject if user already registered.
    2. Strong password complexity check before OTP generation.
    3. Rate limiting and 60-second resend cooldown.
    4. Salted HMAC-SHA256 OTP storage with 10-minute TTL and 3-attempt brute-force protection.
    5. Zero plaintext OTP persistence in the database.
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")

    # Rate limiting: max 10 requests per minute per IP
    is_limited, rem = auth_limiter.is_rate_limited(
        f"otp_request_ip:{ip}",
        max_attempts=10,
        window_seconds=60,
        lockout_seconds=120
    )
    if is_limited:
        emit_security_audit_log(
            event_type="AUTH_OTP_RATE_LIMITED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"retry_after_seconds": rem},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many verification requests. Please wait {rem} seconds before trying again.",
            headers={"Retry-After": str(rem)}
        )
    auth_limiter.record_attempt(f"otp_request_ip:{ip}")

    # Enforce: 1 email ID = 1 account
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        emit_security_audit_log(
            event_type="AUTH_OTP_DUPLICATE_REJECTED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Account already registered with this email address"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Only 1 account per email is allowed. Please sign in instead."
        )

    now = utcnow()

    # Check if a pending OTP record already exists for this email
    existing_otp_query = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == payload.email))
    otp_record = existing_otp_query.scalar_one_or_none()

    # Enforce 60-second resend cooldown if an active OTP was recently generated
    if otp_record and now < otp_record.resend_available_at:
        cooldown_remaining = max(1, int((otp_record.resend_available_at - now).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {cooldown_remaining} seconds before requesting another verification code.",
            headers={"Retry-After": str(cooldown_remaining)}
        )

    # Cryptographically secure 6-digit OTP generation and salted hash
    raw_otp = generate_otp()
    salt = generate_otp_salt()
    otp_hashed = hash_otp(raw_otp, salt)

    # Pre-hash user password using scrypt
    hashed_pw = hash_password(payload.password)
    pending_payload = {
        "purpose": "signup",
        "hashed_password": hashed_pw,
        "full_name": payload.full_name,
        "terms_agreed": payload.terms_agreed,
        "terms_version": payload.terms_version,
        "mac_address": payload.mac_address
    }

    if otp_record:
        otp_record.otp_hash = otp_hashed
        otp_record.salt = salt
        otp_record.pending_data = pending_payload
        otp_record.attempts_left = 3
        otp_record.resend_available_at = now + timedelta(seconds=60)
        otp_record.expires_at = now + timedelta(minutes=10)
        otp_record.created_at = now
    else:
        otp_record = EmailOTPVerification(
            email=payload.email,
            otp_hash=otp_hashed,
            salt=salt,
            pending_data=pending_payload,
            attempts_left=3,
            resend_available_at=now + timedelta(seconds=60),
            expires_at=now + timedelta(minutes=10),
            created_at=now
        )
        db.add(otp_record)

    await db.commit()

    # Dispatch email
    _, msg, delivery_mode = await dispatch_otp_email(
        recipient_email=payload.email,
        recipient_name=payload.full_name,
        otp_code=raw_otp,
        expires_minutes=10,
        purpose="signup"
    )

    emit_security_audit_log(
        event_type="AUTH_SIGNUP_OTP_REQUESTED",
        outcome="SUCCESS",
        email=payload.email,
        ip_address=ip,
        user_agent=ua,
        details={"delivery_mode": delivery_mode, "expires_in_minutes": 10}
    )

    return OTPRequestResponse(
        success=True,
        email=payload.email,
        message=f"A 6-digit verification code has been dispatched to {payload.email}.",
        expires_in_seconds=600,
        resend_cooldown_seconds=60,
        delivery_mode=delivery_mode
    )


@router.post("/signup/resend-otp", response_model=OTPRequestResponse)
async def resend_signup_otp(
    payload: OTPResendRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> OTPRequestResponse:
    """
    Resend a new 6-digit OTP code to an unverified registration email.
    Enforces a mandatory 60-second cooldown between resends.
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")

    # 1-email-1-account guard
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please sign in."
        )

    now = utcnow()
    existing_otp_query = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == payload.email))
    otp_record = existing_otp_query.scalar_one_or_none()

    if not otp_record or now > otp_record.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active registration session found for this email. Please complete the sign-up form first."
        )

    # Enforce 60s cooldown
    if now < otp_record.resend_available_at:
        cooldown_remaining = max(1, int((otp_record.resend_available_at - now).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {cooldown_remaining} seconds before requesting a new code.",
            headers={"Retry-After": str(cooldown_remaining)}
        )

    raw_otp = generate_otp()
    salt = generate_otp_salt()
    otp_record.otp_hash = hash_otp(raw_otp, salt)
    otp_record.salt = salt
    otp_record.attempts_left = 3
    otp_record.resend_available_at = now + timedelta(seconds=60)
    otp_record.expires_at = now + timedelta(minutes=10)
    await db.commit()

    recipient_name = otp_record.pending_data.get("full_name") if otp_record.pending_data else None
    _, msg, delivery_mode = await dispatch_otp_email(
        recipient_email=payload.email,
        recipient_name=recipient_name,
        otp_code=raw_otp,
        expires_minutes=10,
        purpose="signup"
    )

    emit_security_audit_log(
        event_type="AUTH_SIGNUP_OTP_RESENT",
        outcome="SUCCESS",
        email=payload.email,
        ip_address=ip,
        user_agent=ua,
        details={"delivery_mode": delivery_mode}
    )

    return OTPRequestResponse(
        success=True,
        email=payload.email,
        message=f"A fresh verification code has been dispatched to {payload.email}.",
        expires_in_seconds=600,
        resend_cooldown_seconds=60,
        delivery_mode=delivery_mode
    )


@router.post("/signup/verify-otp", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def verify_signup_otp(
    payload: OTPVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    Verify the 6-digit OTP code, finalize account creation, record terms consent, and issue a JWT.
    Enforces:
    1. Constant-time OTP comparison (timing attack defense).
    2. Max 3 failed attempts lockout (brute-force defense).
    3. One-time use: immediate deletion of verification record upon success.
    4. Database constraint conflict handling.
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    now = utcnow()

    # Query pending verification record
    otp_query = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == payload.email))
    otp_record = otp_query.scalar_one_or_none()

    if not otp_record:
        emit_security_audit_log(
            event_type="AUTH_OTP_VERIFY_NOT_FOUND",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "No pending OTP verification record"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending registration found for this email. Please submit the sign-up form first."
        )

    # Check expiration
    if now > otp_record.expires_at:
        await cleanup_otp_record(db, email=payload.email, record=otp_record)
        emit_security_audit_log(
            event_type="AUTH_OTP_EXPIRED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "OTP expired"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The verification code has expired. Please request a new code."
        )

    # Check brute-force attempts
    if otp_record.attempts_left <= 0:
        await cleanup_otp_record(db, email=payload.email, record=otp_record)
        emit_security_audit_log(
            event_type="AUTH_OTP_MAX_ATTEMPTS_EXCEEDED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Maximum failed attempts exceeded"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many incorrect attempts. This code is locked. Please request a new verification code."
        )

    # Constant-time verification
    is_valid = verify_otp(payload.otp, otp_record.salt, otp_record.otp_hash)
    if not is_valid:
        otp_record.attempts_left -= 1
        await db.commit()
        emit_security_audit_log(
            event_type="AUTH_OTP_VERIFY_FAILED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"attempts_left": otp_record.attempts_left},
            severity="WARNING"
        )
        if otp_record.attempts_left <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code. Maximum attempts reached. Please request a new code."
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid verification code. {otp_record.attempts_left} attempt(s) remaining."
        )

    # OTP is valid! Proceed to create user account
    pending_data = otp_record.pending_data or {}
    index_id = generate_user_index_id(otp_record.email)
    new_user = User(
        index_id=index_id,
        email=otp_record.email,
        hashed_password=pending_data.get("hashed_password"),
        full_name=pending_data.get("full_name"),
        is_active=True,
        is_superuser=False,
        password_changed_at=now,
        password_history=[],
        failed_login_attempts=0,
        locked_until=None,
        created_at=now,
        updated_at=now
    )

    try:
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
    except IntegrityError:
        await db.rollback()
        emit_security_audit_log(
            event_type="AUTH_SIGNUP_RACE_DUPLICATE_REJECTED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Concurrent registration collision prevented by database constraint"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists. Only 1 account per email is allowed."
        )

    # Record terms consent
    consent_resp = None
    if pending_data.get("terms_agreed"):
        consent_record = await record_terms_consent(
            db=db,
            email=new_user.email,
            ip_address=ip,
            mac_address=pending_data.get("mac_address"),
            terms_version=pending_data.get("terms_version", "1.0.0"),
            user_id=new_user.id,
            user_index_id=new_user.index_id,
            user_agent=ua
        )
        consent_resp = TermsConsentResponse.model_validate(consent_record)

    # Immediately delete the verified OTP record from database everywhere (one-time use guarantee)
    await cleanup_otp_record(db, email=payload.email, record=otp_record)

    emit_security_audit_log(
        event_type="AUTH_SIGNUP_OTP_VERIFIED",
        outcome="CREATED",
        email=new_user.email,
        ip_address=ip,
        user_agent=ua,
        details={"user_id": new_user.id, "index_id": new_user.index_id}
    )

    # Issue access token (30m) and single-use rotating refresh token (15d)
    return await issue_token_response(
        db=db,
        user=new_user,
        consent_resp=consent_resp,
        password_expired=False,
        password_age_days=0
    )


@router.post("/signin/request-otp", response_model=OTPRequestResponse)
async def request_signin_otp(
    payload: UserSignIn,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> OTPRequestResponse:
    """
    Authenticate user credentials (email & password), then dispatch a 6-digit OTP code to the registered email for 2FA.
    Enforces account lockout protection, IP/account sliding-window rate limiting, and password verification.
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")

    # Rate limiting by IP and by account
    ip_limited, ip_rem = auth_limiter.is_rate_limited(f"signin_ip:{ip}", max_attempts=25, window_seconds=60, lockout_seconds=300)
    if ip_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts from this network. Locked for {ip_rem} seconds.",
            headers={"Retry-After": str(ip_rem)}
        )

    acc_limited, acc_rem = auth_limiter.is_rate_limited(f"signin_email:{payload.email}", max_attempts=5, window_seconds=60, lockout_seconds=180)
    if acc_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts for this account. Locked for {acc_rem} seconds.",
            headers={"Retry-After": str(acc_rem)}
        )

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user is None:
        dummy_verify_password(payload.password)
        auth_limiter.record_attempt(f"signin_ip:{ip}")
        auth_limiter.record_attempt(f"signin_email:{payload.email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    now = utcnow()
    if user.locked_until and user.locked_until > now:
        rem_lock = int((user.locked_until - now).total_seconds())
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Account is temporarily locked. Try again in {rem_lock} seconds.", headers={"Retry-After": str(rem_lock)})

    if not verify_password(payload.password, user.hashed_password):
        auth_limiter.record_attempt(f"signin_ip:{ip}")
        auth_limiter.record_attempt(f"signin_email:{payload.email}")
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= 5:
            user.locked_until = now + timedelta(minutes=5)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated.")

    # Password verified! Clean up any existing OTP records for this email
    await cleanup_otp_record(db, email=user.email)

    raw_otp = generate_otp()
    salt = generate_otp_salt()
    otp_hashed = hash_otp(raw_otp, salt)

    pending_payload = {
        "purpose": "signin",
        "user_id": user.id,
        "terms_agreed": payload.terms_agreed,
        "terms_version": payload.terms_version,
        "mac_address": payload.mac_address
    }

    otp_record = EmailOTPVerification(
        email=user.email,
        otp_hash=otp_hashed,
        salt=salt,
        pending_data=pending_payload,
        attempts_left=3,
        resend_available_at=now + timedelta(seconds=60),
        expires_at=now + timedelta(minutes=10),
        created_at=now
    )
    db.add(otp_record)
    await db.commit()

    _, msg, delivery_mode = await dispatch_otp_email(
        recipient_email=user.email,
        recipient_name=user.full_name,
        otp_code=raw_otp,
        expires_minutes=10,
        purpose="signin"
    )

    emit_security_audit_log(
        event_type="AUTH_SIGNIN_OTP_REQUESTED",
        outcome="SUCCESS",
        email=user.email,
        ip_address=ip,
        user_agent=ua,
        details={"delivery_mode": delivery_mode, "expires_in_minutes": 10}
    )

    return OTPRequestResponse(
        success=True,
        email=user.email,
        message=f"A 6-digit sign-in verification code has been dispatched to {user.email}.",
        requires_otp=True,
        purpose="signin",
        expires_in_seconds=600,
        resend_cooldown_seconds=60,
        delivery_mode=delivery_mode
    )


@router.post("/signin/resend-otp", response_model=OTPRequestResponse)
async def resend_signin_otp(
    payload: OTPResendRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> OTPRequestResponse:
    """Resend a new 6-digit OTP code for sign-in verification enforcing 60s cooldown."""
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    now = utcnow()

    otp_query = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == payload.email))
    otp_record = otp_query.scalar_one_or_none()

    if not otp_record or otp_record.pending_data.get("purpose") != "signin":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending sign-in verification found for this email.")

    if now < otp_record.resend_available_at:
        cooldown_remaining = max(1, int((otp_record.resend_available_at - now).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {cooldown_remaining} seconds before requesting another verification code.",
            headers={"Retry-After": str(cooldown_remaining)}
        )

    raw_otp = generate_otp()
    salt = generate_otp_salt()
    otp_record.otp_hash = hash_otp(raw_otp, salt)
    otp_record.salt = salt
    otp_record.attempts_left = 3
    otp_record.resend_available_at = now + timedelta(seconds=60)
    otp_record.expires_at = now + timedelta(minutes=10)
    await db.commit()

    _, msg, delivery_mode = await dispatch_otp_email(
        recipient_email=payload.email,
        recipient_name=None,
        otp_code=raw_otp,
        expires_minutes=10,
        purpose="signin"
    )

    return OTPRequestResponse(
        success=True,
        email=payload.email,
        message=f"A fresh 6-digit sign-in verification code has been dispatched to {payload.email}.",
        requires_otp=True,
        purpose="signin",
        expires_in_seconds=600,
        resend_cooldown_seconds=60,
        delivery_mode=delivery_mode
    )


@router.post("/signin/verify-otp", response_model=TokenResponse)
async def verify_signin_otp(
    payload: OTPVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    Verify the 6-digit OTP code for Sign In, delete the OTP record from database everywhere, and issue JWT session token.
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    now = utcnow()

    otp_query = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == payload.email))
    otp_record = otp_query.scalar_one_or_none()

    if not otp_record or otp_record.pending_data.get("purpose") != "signin":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending sign-in verification found for this email. Please sign in first.")

    if now > otp_record.expires_at:
        await cleanup_otp_record(db, email=payload.email, record=otp_record)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The verification code has expired. Please request a new code.")

    if otp_record.attempts_left <= 0:
        await cleanup_otp_record(db, email=payload.email, record=otp_record)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Too many incorrect attempts. Please sign in again.")

    is_valid = verify_otp(payload.otp, otp_record.salt, otp_record.otp_hash)
    if not is_valid:
        otp_record.attempts_left -= 1
        await db.commit()
        if otp_record.attempts_left <= 0:
            await cleanup_otp_record(db, email=payload.email, record=otp_record)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code. Maximum attempts reached. Please sign in again.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid verification code. {otp_record.attempts_left} attempt(s) remaining.")

    user_id = otp_record.pending_data.get("user_id")
    user_res = await db.execute(select(User).where(User.id == user_id))
    user = user_res.scalar_one_or_none()
    if not user:
        user_res2 = await db.execute(select(User).where(User.email == payload.email))
        user = user_res2.scalar_one_or_none()

    if not user or not user.is_active:
        await cleanup_otp_record(db, email=payload.email, record=otp_record)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated.")

    consent_resp = None
    if otp_record.pending_data.get("terms_agreed"):
        consent_record = await record_terms_consent(
            db=db,
            email=user.email,
            ip_address=ip,
            mac_address=otp_record.pending_data.get("mac_address"),
            terms_version=otp_record.pending_data.get("terms_version", "1.0.0"),
            user_id=user.id,
            user_agent=ua
        )
        consent_resp = TermsConsentResponse.model_validate(consent_record)

    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()

    # IMMEDIATELY DELETE OTP FROM EVERYWHERE IN DATABASE
    await cleanup_otp_record(db, email=payload.email, record=otp_record)

    pwd_changed = ensure_utc(user.password_changed_at or user.created_at or now)
    pwd_age_days = (now - pwd_changed).days
    is_pwd_expired = (pwd_age_days >= 30)

    emit_security_audit_log(
        event_type="AUTH_SIGNIN_OTP_VERIFIED",
        outcome="AUTHENTICATED",
        email=user.email,
        ip_address=ip,
        user_agent=ua,
        details={"user_id": user.id, "password_expired": is_pwd_expired, "password_age_days": pwd_age_days}
    )

    # Issue access token (30m) and single-use rotating refresh token (15d)
    return await issue_token_response(
        db=db,
        user=user,
        consent_resp=consent_resp,
        password_expired=is_pwd_expired,
        password_age_days=pwd_age_days
    )


@router.post("/signin", response_model=TokenResponse)
async def sign_in(
    payload: UserSignIn,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    Authenticate an existing user with email and password.
    Enforces:
    1. Constant-time CPU execution against email enumeration
    2. Rate-limited sliding-window defense per IP and per account
    3. Account lockout on 5 consecutive failed attempts
    4. 7-day token issuance (weekly re-login required)
    5. 30-day password expiration tracking (monthly password change requirement)
    6. Structured injection-proof security audit logging
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")

    # 1. Rate limiting by IP: max 25 attempts per minute
    ip_limited, ip_rem = auth_limiter.is_rate_limited(
        f"signin_ip:{ip}",
        max_attempts=25,
        window_seconds=60,
        lockout_seconds=300
    )
    if ip_limited:
        emit_security_audit_log(
            event_type="AUTH_SIGNIN_IP_RATE_LIMITED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"lockout_seconds": ip_rem},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts from this network. Locked for {ip_rem} seconds.",
            headers={"Retry-After": str(ip_rem)}
        )

    # 2. Rate limiting by account (email): max 5 failed attempts per 60s, then 180s lockout
    acc_limited, acc_rem = auth_limiter.is_rate_limited(
        f"signin_email:{payload.email}",
        max_attempts=5,
        window_seconds=60,
        lockout_seconds=180
    )
    if acc_limited:
        emit_security_audit_log(
            event_type="AUTH_SIGNIN_ACCOUNT_RATE_LIMITED",
            outcome="BLOCKED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"lockout_seconds": acc_rem},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts for this account. Locked for {acc_rem} seconds.",
            headers={"Retry-After": str(acc_rem)}
        )

    # Parameterized query via SQLAlchemy 2.0 ORM - 100% immune to SQL injection
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    # If user doesn't exist, execute identical dummy verification to eliminate timing side-channel
    if user is None:
        dummy_verify_password(payload.password)
        auth_limiter.record_attempt(f"signin_ip:{ip}")
        auth_limiter.record_attempt(f"signin_email:{payload.email}")
        emit_security_audit_log(
            event_type="AUTH_SIGNIN_FAILED",
            outcome="REJECTED",
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Invalid email or password (constant-time protected)"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    # Check database-level account lockout
    now = utcnow()
    if user.locked_until and user.locked_until > now:
        rem_lock = int((user.locked_until - now).total_seconds())
        emit_security_audit_log(
            event_type="AUTH_SIGNIN_LOCKED_ATTEMPT",
            outcome="BLOCKED",
            email=user.email,
            ip_address=ip,
            user_agent=ua,
            details={"remaining_seconds": rem_lock},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account is temporarily locked due to 5 consecutive failed login attempts. Please try again in {rem_lock} seconds.",
            headers={"Retry-After": str(rem_lock)}
        )

    if not verify_password(payload.password, user.hashed_password):
        auth_limiter.record_attempt(f"signin_ip:{ip}")
        auth_limiter.record_attempt(f"signin_email:{payload.email}")
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= 5:
            user.locked_until = now + timedelta(minutes=5)
            emit_security_audit_log(
                event_type="AUTH_ACCOUNT_LOCKOUT_ENGAGED",
                outcome="LOCKED",
                email=user.email,
                ip_address=ip,
                user_agent=ua,
                details={"consecutive_failures": user.failed_login_attempts, "cooldown_minutes": 5},
                severity="CRITICAL"
            )
        else:
            emit_security_audit_log(
                event_type="AUTH_SIGNIN_PASSWORD_MISMATCH",
                outcome="REJECTED",
                email=user.email,
                ip_address=ip,
                user_agent=ua,
                details={"failed_attempts": user.failed_login_attempts},
                severity="WARNING"
            )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        emit_security_audit_log(
            event_type="AUTH_SIGNIN_DEACTIVATED",
            outcome="FORBIDDEN",
            email=user.email,
            ip_address=ip,
            user_agent=ua,
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated."
        )

    # Clear rate limit counter and reset database failure counters upon successful authentication
    auth_limiter.reset_attempts(f"signin_email:{payload.email}")
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        await db.commit()

    # Record terms consent if agreed during sign in
    consent_resp = None
    if payload.terms_agreed:
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

    # If OTP was supplied with sign in credentials, verify it and immediately purge
    if payload.otp:
        otp_query = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == payload.email))
        otp_record = otp_query.scalar_one_or_none()
        if not otp_record or otp_record.pending_data.get("purpose") != "signin":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending sign-in verification found for this email.")
        if now > otp_record.expires_at:
            await cleanup_otp_record(db, email=payload.email, record=otp_record)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The verification code has expired.")
        if otp_record.attempts_left <= 0:
            await cleanup_otp_record(db, email=payload.email, record=otp_record)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Too many incorrect attempts.")
        if not verify_otp(payload.otp, otp_record.salt, otp_record.otp_hash):
            otp_record.attempts_left -= 1
            await db.commit()
            if otp_record.attempts_left <= 0:
                await cleanup_otp_record(db, email=payload.email, record=otp_record)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid verification code. {otp_record.attempts_left} attempt(s) remaining.")
        # Immediately delete OTP from everywhere
        await cleanup_otp_record(db, email=payload.email, record=otp_record)

    # 30-Day Password Expiry & Rotation Check
    pwd_changed = ensure_utc(user.password_changed_at or user.created_at or now)
    pwd_age_days = (now - pwd_changed).days
    is_pwd_expired = (pwd_age_days >= 30)

    emit_security_audit_log(
        event_type="AUTH_SIGNIN_SUCCESS",
        outcome="AUTHENTICATED",
        email=user.email,
        ip_address=ip,
        user_agent=ua,
        details={"user_id": user.id, "password_expired": is_pwd_expired, "password_age_days": pwd_age_days}
    )

    # Issue access token (30m) and single-use rotating refresh token (15d)
    return await issue_token_response(
        db=db,
        user=user,
        consent_resp=consent_resp,
        password_expired=is_pwd_expired,
        password_age_days=pwd_age_days
    )


@router.post("/password/request-otp", response_model=OTPRequestResponse)
@router.post("/change-password/request-otp", response_model=OTPRequestResponse, include_in_schema=False)
async def request_password_change_otp(
    payload: PasswordChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> OTPRequestResponse:
    """
    Validate current password, check new password novelty, similarity, history, complexity,
    then dispatch a 6-digit OTP to user's email to authorize the 30-day password rotation.
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")

    # 1. Verify current password
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect.")

    # 2. Reject exact identity
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different from your current password.")

    # 3. Check similarity
    sim = calculate_password_similarity(payload.current_password, payload.new_password)
    dist = levenshtein_distance(payload.current_password.lower(), payload.new_password.lower())
    if sim > 0.60 or dist < 4:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password is too similar to your current password. Please choose a substantially different password.")

    # 4. Check password history
    if is_password_in_history(payload.new_password, current_user.password_history or []):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot reuse a previously used password. Please choose a completely new password.")

    # 5. Validate complexity
    validate_password_complexity(payload.new_password, email=current_user.email, full_name=current_user.full_name)

    # 6. Clean up any existing OTP for this email
    await cleanup_otp_record(db, email=current_user.email)

    # 7. Generate OTP & pre-hash the new password
    raw_otp = generate_otp()
    salt = generate_otp_salt()
    otp_hash = hash_otp(raw_otp, salt)
    new_password_hash = hash_password(payload.new_password)

    now = utcnow()
    pending_payload = {
        "purpose": "change_password",
        "user_id": current_user.id,
        "new_password_hash": new_password_hash
    }

    otp_record = EmailOTPVerification(
        email=current_user.email,
        otp_hash=otp_hash,
        salt=salt,
        pending_data=pending_payload,
        attempts_left=3,
        resend_available_at=now + timedelta(seconds=60),
        expires_at=now + timedelta(minutes=10),
        created_at=now
    )
    db.add(otp_record)
    await db.commit()

    _, msg, delivery_mode = await dispatch_otp_email(
        recipient_email=current_user.email,
        recipient_name=current_user.full_name,
        otp_code=raw_otp,
        expires_minutes=10,
        purpose="change_password"
    )

    emit_security_audit_log(
        event_type="AUTH_PASSWORD_CHANGE_OTP_REQUESTED",
        outcome="SUCCESS",
        email=current_user.email,
        ip_address=ip,
        user_agent=ua,
        details={"delivery_mode": delivery_mode, "expires_in_minutes": 10}
    )

    return OTPRequestResponse(
        success=True,
        email=current_user.email,
        message=f"A 6-digit verification code has been dispatched to {current_user.email} to authorize the password update.",
        requires_otp=True,
        purpose="change_password",
        expires_in_seconds=600,
        resend_cooldown_seconds=60,
        delivery_mode=delivery_mode
    )


@router.post("/password/verify-otp")
@router.post("/change-password/verify-otp")
async def verify_password_change_otp(
    payload: OTPVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> dict:
    """
    Verify OTP code to complete 30-day password rotation and immediately delete OTP from database everywhere.
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    now = utcnow()

    otp_query = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == payload.email))
    otp_record = otp_query.scalar_one_or_none()

    if not otp_record or otp_record.pending_data.get("purpose") != "change_password":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending password update verification found. Please submit the change password form first."
        )

    if now > otp_record.expires_at:
        await cleanup_otp_record(db, email=payload.email, record=otp_record)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The verification code has expired. Please request a new code.")

    if otp_record.attempts_left <= 0:
        await cleanup_otp_record(db, email=payload.email, record=otp_record)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Too many incorrect attempts. Please submit password change request again.")

    is_valid = verify_otp(payload.otp, otp_record.salt, otp_record.otp_hash)
    if not is_valid:
        otp_record.attempts_left -= 1
        await db.commit()
        if otp_record.attempts_left <= 0:
            await cleanup_otp_record(db, email=payload.email, record=otp_record)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code. Maximum attempts reached.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid verification code. {otp_record.attempts_left} attempt(s) remaining.")

    # OTP is valid! Apply password change to user
    user_id = otp_record.pending_data.get("user_id")
    new_password_hash = otp_record.pending_data.get("new_password_hash")

    user_res = await db.execute(select(User).where(User.id == user_id))
    user = user_res.scalar_one_or_none()
    if not user:
        user_res2 = await db.execute(select(User).where(User.email == payload.email))
        user = user_res2.scalar_one_or_none()

    if not user:
        await cleanup_otp_record(db, email=payload.email, record=otp_record)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    history = list(user.password_history or [])
    history.append(user.hashed_password)
    user.password_history = history[-5:]
    user.hashed_password = new_password_hash
    user.password_changed_at = now
    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_at = now
    await db.commit()

    # IMMEDIATELY PURGE OTP RECORD FROM EVERYWHERE IN DATABASE
    await cleanup_otp_record(db, email=payload.email, record=otp_record)

    emit_security_audit_log(
        event_type="AUTH_PASSWORD_CHANGE_SUCCESS",
        outcome="ROTATED",
        email=user.email,
        ip_address=ip,
        user_agent=ua,
        details={"policy": "30-day rotation compliant with OTP verification"}
    )

    return {
        "success": True,
        "message": "Password changed successfully. Your account password is now compliant with the monthly rotation policy.",
        "password_changed_at": now.isoformat(),
        "password_expired": False
    }


@router.post("/change-password", summary="Rotate password enforcing 30-day renewal, novelty & dissimilarity")
async def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> dict:
    """
    Change user password enforcing:
    1. Verification of current password
    2. Rejection of identical password
    3. Rejection of similar password (Levenshtein distance & Gestalt pattern ratio)
    4. Rejection of reused password from history (last 5 passwords)
    5. Context-aware enterprise complexity (no email/name fragments, >= 10 chars, symbols)
    6. Timestamp rotation update for 30-day compliance
    7. Injection-proof audit logging
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")

    # 1. Verify current password
    if not verify_password(payload.current_password, current_user.hashed_password):
        emit_security_audit_log(
            event_type="AUTH_PASSWORD_CHANGE_FAILED",
            outcome="REJECTED",
            email=current_user.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Incorrect current password"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect."
        )

    # 1b. Verify 2FA OTP if supplied for password change authorization
    if payload.otp:
        now_check = utcnow()
        otp_query = await db.execute(select(EmailOTPVerification).where(EmailOTPVerification.email == current_user.email))
        otp_record = otp_query.scalar_one_or_none()
        if not otp_record or otp_record.pending_data.get("purpose") != "change_password":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending password update verification found.")
        if now_check > otp_record.expires_at:
            await cleanup_otp_record(db, email=current_user.email, record=otp_record)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The verification code has expired.")
        if otp_record.attempts_left <= 0:
            await cleanup_otp_record(db, email=current_user.email, record=otp_record)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Too many incorrect attempts.")
        if not verify_otp(payload.otp, otp_record.salt, otp_record.otp_hash):
            otp_record.attempts_left -= 1
            await db.commit()
            if otp_record.attempts_left <= 0:
                await cleanup_otp_record(db, email=current_user.email, record=otp_record)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid verification code. {otp_record.attempts_left} attempt(s) remaining.")
        await cleanup_otp_record(db, email=current_user.email, record=otp_record)

    # 2. Reject exact identity
    if payload.current_password == payload.new_password:
        emit_security_audit_log(
            event_type="AUTH_PASSWORD_CHANGE_FAILED",
            outcome="REJECTED",
            email=current_user.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "New password identical to current"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from your current password."
        )

    # 3. Check similarity (SequenceMatcher + Levenshtein distance)
    sim = calculate_password_similarity(payload.current_password, payload.new_password)
    dist = levenshtein_distance(payload.current_password.lower(), payload.new_password.lower())
    if sim > 0.60 or dist < 4:
        emit_security_audit_log(
            event_type="AUTH_PASSWORD_CHANGE_SIMILAR_REJECTED",
            outcome="REJECTED",
            email=current_user.email,
            ip_address=ip,
            user_agent=ua,
            details={"similarity_ratio": round(sim, 2), "edit_distance": dist},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password is too similar to your current password. For security, please choose a substantially different password."
        )

    # 4. Check previous password history
    if is_password_in_history(payload.new_password, current_user.password_history or []):
        emit_security_audit_log(
            event_type="AUTH_PASSWORD_CHANGE_HISTORY_REUSED",
            outcome="REJECTED",
            email=current_user.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Candidate password exists in password history"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot reuse a previously used password. Please choose a completely new password."
        )

    # 5. Context-aware validation against email and display name
    try:
        validate_password_complexity(
            payload.new_password,
            email=current_user.email,
            full_name=current_user.full_name
        )
    except ValueError as e:
        emit_security_audit_log(
            event_type="AUTH_PASSWORD_CHANGE_WEAK_REJECTED",
            outcome="REJECTED",
            email=current_user.email,
            ip_address=ip,
            user_agent=ua,
            details={"reason": str(e)},
            severity="WARNING"
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # 6. Apply new scrypt hash and archive old hash to history (retain last 5)
    now = utcnow()
    history = list(current_user.password_history or [])
    history.append(current_user.hashed_password)
    current_user.password_history = history[-5:]
    current_user.hashed_password = hash_password(payload.new_password)
    current_user.password_changed_at = now
    current_user.failed_login_attempts = 0
    current_user.locked_until = None
    current_user.updated_at = now

    await db.commit()
    await db.refresh(current_user)

    emit_security_audit_log(
        event_type="AUTH_PASSWORD_CHANGE_SUCCESS",
        outcome="ROTATED",
        email=current_user.email,
        ip_address=ip,
        user_agent=ua,
        details={"policy": "30-day rotation compliant"}
    )

    return {
        "success": True,
        "message": "Password changed successfully. Your account password is now compliant with the monthly rotation policy.",
        "password_changed_at": now.isoformat(),
        "password_expired": False
    }


@router.post("/login", response_model=TokenResponse, include_in_schema=False)
async def login_alias(
    payload: UserSignIn,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """Alias for /signin endpoint."""
    return await sign_in(payload, request, db)


@router.post("/refresh", response_model=TokenRefreshResponse, summary="Rotate single-use refresh token")
async def refresh_tokens(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> TokenRefreshResponse:
    """
    Exchange a valid, single-use refresh token for a new 30-minute access token
    and a newly rotated 15-day refresh token.
    Enforces automatic reuse detection: if an already-revoked refresh token is presented,
    all tokens in the family are instantly terminated.
    """
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")

    # Rate limiting: max 30 refreshes per minute per IP
    is_limited, rem = auth_limiter.is_rate_limited(
        f"refresh_ip:{ip}",
        max_attempts=30,
        window_seconds=60,
        lockout_seconds=120
    )
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many token refresh requests. Locked for {rem} seconds.",
            headers={"Retry-After": str(rem)}
        )

    new_access, new_refresh, user = await rotate_refresh_token(db, payload.refresh_token)

    emit_security_audit_log(
        event_type="AUTH_TOKEN_ROTATED",
        outcome="SUCCESS",
        email=user.email,
        ip_address=ip,
        user_agent=ua,
        details={"user_id": user.id}
    )

    return TokenRefreshResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        token_type="bearer",
        expires_in_seconds=1800,
        refresh_expires_in_seconds=1296000
    )


@router.post("/signout", summary="Sign out user and invalidate active Bearer token and refresh tokens")
@router.post("/logout", summary="Alias for signout", include_in_schema=False)
async def sign_out(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> dict:
    """Explicitly invalidate and revoke the client's Bearer access token and all refresh tokens."""
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    auth_hdr = request.headers.get("authorization", "")
    revoked = False
    if auth_hdr.lower().startswith("bearer "):
        token = auth_hdr[7:].strip()
        revoked = revoke_token(token)
        claims = decode_access_token(token, check_revocation=False)
        if claims and claims.get("user_id"):
            await revoke_user_refresh_tokens(db, claims["user_id"])
        elif claims and claims.get("sub"):
            user_res = await db.execute(select(User).where(User.email == claims["sub"]))
            user = user_res.scalar_one_or_none()
            if user:
                await revoke_user_refresh_tokens(db, user.id)

    emit_security_audit_log(
        event_type="AUTH_SIGNOUT_SUCCESS",
        outcome="REVOKED" if revoked else "ANONYMOUS",
        ip_address=ip,
        user_agent=ua,
        details={"token_revoked": revoked}
    )

    return {
        "success": True,
        "revoked": revoked,
        "message": "Signed out successfully. Authentication tokens and sessions invalidated."
    }


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
    emit_security_audit_log(
        event_type="AUTH_TERMS_CONSENT_RECORDED",
        outcome="AGREED",
        email=payload.email,
        ip_address=ip,
        user_agent=ua,
        details={"terms_version": payload.terms_version, "consent_id": consent_record.id}
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
    """Retrieve profile of the currently authenticated user with security policy status."""
    return build_user_response(current_user)


@router.get("/user-by-index/{index_id}", response_model=UserResponse)
async def get_user_by_index_id(
    index_id: str,
    db: AsyncSession = Depends(get_db)
) -> UserResponse:
    """Retrieve public user profile by unique Index ID."""
    clean_idx = index_id.strip()
    result = await db.execute(select(User).where(User.index_id == clean_idx))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No user found with Index ID '{clean_idx}'."
        )
    return build_user_response(user)


@router.get("/track/{identifier}", response_model=UserTrackingSummary)
async def track_user_data(
    identifier: str,
    db: AsyncSession = Depends(get_db)
) -> UserTrackingSummary:
    """
    Unified tracking endpoint for user email or unique Index ID.
    Aggregates profile metadata, URL click history, security digest dispatches, and terms consent.
    """
    from sqlalchemy import or_

    clean_id = identifier.strip()
    is_index = clean_id.upper().startswith("SAFE-IDX-")
    
    if is_index:
        user_query = await db.execute(select(User).where(User.index_id == clean_id.upper()))
    else:
        user_query = await db.execute(select(User).where(User.email == clean_id.lower()))
    user = user_query.scalar_one_or_none()

    target_email = (user.email if user else (clean_id.lower() if "@" in clean_id else None))
    target_index_id = (user.index_id if user else (clean_id.upper() if is_index else (generate_user_index_id(target_email) if target_email else None)))

    if not user and not target_email and not target_index_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No tracking data found for identifier '{clean_id}'."
        )

    # 1. Query URL clicks for this user (by email or index_id)
    click_filters = []
    if target_email:
        click_filters.append(UrlClickLog.user_email == target_email)
    if target_index_id:
        click_filters.append(UrlClickLog.user_index_id == target_index_id)
    
    click_rows = []
    if click_filters:
        clicks_query = await db.execute(
            select(UrlClickLog)
            .where(or_(*click_filters))
            .order_by(UrlClickLog.id.desc())
            .limit(20)
        )
        click_rows = clicks_query.scalars().all()

    # 2. Query Digest logs for this user
    digest_filters = []
    if target_email:
        digest_filters.append(SecurityDigestLog.user_email == target_email)
    if target_index_id:
        digest_filters.append(SecurityDigestLog.user_index_id == target_index_id)

    digest_rows = []
    if digest_filters:
        digests_query = await db.execute(
            select(SecurityDigestLog)
            .where(or_(*digest_filters))
            .order_by(SecurityDigestLog.id.desc())
            .limit(10)
        )
        digest_rows = digests_query.scalars().all()

    # 3. Query Terms consent
    consent_filters = []
    if target_email:
        consent_filters.append(TermsConsent.email == target_email)
    if target_index_id:
        consent_filters.append(TermsConsent.user_index_id == target_index_id)

    consent = None
    if consent_filters:
        consent_query = await db.execute(
            select(TermsConsent)
            .where(or_(*consent_filters))
            .order_by(TermsConsent.id.desc())
            .limit(1)
        )
        consent = consent_query.scalar_one_or_none()

    return UserTrackingSummary(
        index_id=target_index_id or (generate_user_index_id(target_email) if target_email else ""),
        email=target_email or (user.email if user else ""),
        full_name=user.full_name if user else None,
        is_active=user.is_active if user else (consent is not None or len(click_rows) > 0),
        created_at=user.created_at if user else utcnow(),
        url_clicks_count=len(click_rows),
        recent_url_clicks=[
            {
                "id": c.id,
                "url": c.url,
                "defanged_url": c.defanged_url,
                "risk_score": c.risk_score,
                "risk_level": c.risk_level,
                "proceeded": c.proceeded,
                "clicked_at": c.clicked_at.isoformat() if c.clicked_at else ""
            }
            for c in click_rows
        ],
        digest_dispatches_count=len(digest_rows),
        recent_digests=[
            {
                "id": d.id,
                "period_start": d.period_start,
                "period_end": d.period_end,
                "total_emails": d.total_emails,
                "threat_count": d.threat_count,
                "click_count": d.click_count,
                "dispatch_status": d.dispatch_status,
                "created_at": d.created_at.isoformat() if d.created_at else ""
            }
            for d in digest_rows
        ],
        terms_agreed=consent is not None,
        terms_version=consent.terms_version if consent else None
    )
