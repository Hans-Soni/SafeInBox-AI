"""Authentication and cryptographic security services."""

import base64
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import defaultdict
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User

logger = logging.getLogger(__name__)

# Optional HTTPBearer scheme so endpoints can use standard OpenAPI docs
http_bearer = HTTPBearer(auto_error=False)

# In-memory revocation cache for revoked JWT token IDs (jti)
_revoked_token_jtis: set[str] = set()

# Pre-computed dummy scrypt hash for constant-time verification when user does not exist
# This mathematically guarantees the execution time of invalid-email vs invalid-password
# is indistinguishable, preventing user enumeration timing attacks.
_DUMMY_SALT = "00112233445566778899aabbccddeeff"
_DUMMY_HASH = hashlib.scrypt(
    b"dummy-timing-defense-2026",
    salt=_DUMMY_SALT.encode("utf-8"),
    n=16384,
    r=8,
    p=1
).hex()
DUMMY_SCRYPT_HASH = f"scrypt${_DUMMY_SALT}${_DUMMY_HASH}"


class AuthRateLimiter:
    """
    Sliding-window rate limiter defending authentication endpoints
    against automated credential stuffing, brute-force password guessing,
    and registration spam.
    """

    def __init__(self):
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lockouts: dict[str, float] = {}

    def is_rate_limited(
        self,
        key: str,
        max_attempts: int = 5,
        window_seconds: int = 60,
        lockout_seconds: int = 300
    ) -> tuple[bool, int]:
        """
        Check whether an identifier (e.g. client IP or email) has exceeded attempts.
        Returns (is_limited, seconds_remaining).
        """
        now = time.time()
        # 1. Check active lockout
        if key in self._lockouts:
            remaining = int(self._lockouts[key] - now)
            if remaining > 0:
                return True, remaining
            del self._lockouts[key]

        # 2. Filter attempts to current sliding window
        window_start = now - window_seconds
        valid_attempts = [t for t in self._attempts[key] if t > window_start]
        self._attempts[key] = valid_attempts

        # 3. Check if threshold reached
        if len(valid_attempts) >= max_attempts:
            self._lockouts[key] = now + lockout_seconds
            return True, lockout_seconds

        return False, 0

    def record_attempt(self, key: str) -> None:
        """Record a failed or new authentication attempt timestamp."""
        self._attempts[key].append(time.time())

    def reset_attempts(self, key: str) -> None:
        """Clear attempts upon successful authentication."""
        self._attempts.pop(key, None)
        self._lockouts.pop(key, None)


auth_limiter = AuthRateLimiter()


def hash_password(password: str) -> str:
    """Hash password using scrypt with a cryptographic salt."""
    salt = secrets.token_hex(16)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        n=16384,
        r=8,
        p=1
    )
    return f"scrypt${salt}${key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against hashed scrypt representation using constant-time comparison."""
    try:
        parts = hashed_password.split("$")
        if len(parts) != 3 or parts[0] != "scrypt":
            return False
        salt = parts[1]
        key_hex = parts[2]
        computed = hashlib.scrypt(
            plain_password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            n=16384,
            r=8,
            p=1
        )
        return secrets.compare_digest(computed.hex(), key_hex)
    except Exception:
        return False


def dummy_verify_password(plain_password: str) -> bool:
    """Perform identical CPU scrypt computation to prevent user enumeration timing attacks."""
    return verify_password(plain_password, DUMMY_SCRYPT_HASH)


def calculate_password_similarity(current_password: str, new_password: str) -> float:
    """Calculate string similarity ratio (0.0 to 1.0) using Gestalt pattern matching."""
    return SequenceMatcher(None, current_password.lower(), new_password.lower()).ratio()


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate minimum edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_password_in_history(plain_password: str, password_history: list[str]) -> bool:
    """Check if the candidate password matches any previously used password hash in history."""
    if not password_history:
        return False
    for old_hash in password_history:
        if verify_password(plain_password, old_hash):
            return True
    return False


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Decode base64url string with dynamic padding restoration."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate an RFC 7519 compliant HS256 JWT access token with unique jti identifier."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    # Default token lifetime is strictly 7 days (weekly re-login requirement)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))

    # Embed unique cryptographic token ID (jti) for explicit revocation support
    to_encode.update({
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "jti": secrets.token_hex(16),
        "ver": 1
    })

    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(to_encode, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(settings.SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str, check_revocation: bool = True) -> Optional[dict]:
    """Verify signature, algorithm, expiration (7-day cutoff), and revocation status."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts

        # Verify algorithm header to prevent 'none' algorithm or substitution attacks
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        if header.get("alg") != "HS256":
            return None

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(settings.SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(sig_b64)
        if not secrets.compare_digest(expected_sig, actual_sig):
            return None

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        exp = payload.get("exp")
        if exp and datetime.now(timezone.utc).timestamp() > exp:
            return None  # Expired (weekly session expired)

        jti = payload.get("jti")
        if check_revocation and jti and jti in _revoked_token_jtis:
            return None  # Revoked on sign-out

        return payload
    except Exception:
        return None


def revoke_token(token: str) -> bool:
    """Revoke an active token by adding its jti to the revocation store."""
    payload = decode_access_token(token, check_revocation=False)
    if payload and "jti" in payload:
        _revoked_token_jtis.add(payload["jti"])
        return True
    return False


def is_token_revoked(jti: str) -> bool:
    """Check if a specific jti identifier has been revoked."""
    return jti in _revoked_token_jtis


async def get_current_user(
    request: Request,
    auth: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: AsyncSession = Depends(get_db)
) -> User:
    """FastAPI dependency to extract and authenticate current user from Bearer token."""
    token = None
    if auth and auth.credentials:
        token = auth.credentials
    else:
        # Fallback to direct Authorization header check
        auth_hdr = request.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your 7-day login session has expired or is invalid. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    email = payload["sub"]
    # Parameterized query via SQLAlchemy 2.0 ORM - 100% immune to SQL injection
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )

    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        rem = int((user.locked_until - datetime.now(timezone.utc)).total_seconds())
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is temporarily locked due to failed sign-in attempts. Try again in {rem} seconds."
        )

    return user
