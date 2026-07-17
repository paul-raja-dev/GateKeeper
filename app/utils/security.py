"""
GateKeeper - Security Utilities

Provides:
- Password hashing (bcrypt)
- Password verification
- JWT token creation and decoding
- Refresh token generation and hashing

Why bcrypt for passwords?
    Bcrypt is intentionally slow — it's designed to resist brute-force attacks.
    Even if your database leaks, attackers can't crack bcrypt hashes in
    reasonable time. Fast hashes like MD5/SHA256 can be cracked at billions
    of attempts per second. Bcrypt limits attempts to ~thousands per second.

    Why SHA-256 for refresh tokens (not bcrypt)?
    Refresh tokens are already random (128-bit UUID), so they don't need
    slow hashing. SHA-256 is fast and sufficient — it just prevents
    reading raw tokens from a leaked database.

Note: We use bcrypt directly instead of passlib because passlib
has compatibility issues with bcrypt >= 4.1.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
from jose import JWTError, jwt

from app.config import get_settings

# ---------------------------------------------------------------------------
# Password Hashing
# ---------------------------------------------------------------------------


def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password using bcrypt.

    Each call produces a different hash (random salt),
    so hash_password("test") != hash_password("test").
    This is by design — prevents rainbow table attacks.
    """
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.

    Returns True if the password matches, False otherwise.
    Internally, bcrypt extracts the salt from the hash and
    re-hashes the plaintext to compare.
    """
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


# ---------------------------------------------------------------------------
# Refresh Tokens
# ---------------------------------------------------------------------------


def create_refresh_token() -> str:
    """
    Generate a cryptographically secure random refresh token.

    Uses secrets.token_urlsafe which generates 32 bytes of randomness
    encoded as a URL-safe base64 string (43 characters).
    This gives 256 bits of entropy — essentially unguessable.
    """
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """
    Hash a token using SHA-256 for database storage.

    We never store raw refresh tokens — if the DB leaks,
    attackers can't use the hashed values to impersonate users.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# JWT Tokens
# ---------------------------------------------------------------------------


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Payload to encode. Typically includes:
              - "sub": user_id (string)
              - "session_id": session UUID (string)
        expires_delta: Custom expiration time. If None, uses settings default.

    Returns:
        Encoded JWT string.

    The token contains:
        - sub: subject (user ID)
        - session_id: which session created this token
        - exp: expiration timestamp
        - iat: issued-at timestamp
        - type: token type ("access")
    """
    settings = get_settings()
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update(
        {
            "exp": expire,
            "iat": datetime.now(UTC),
            "type": "access",
        }
    )

    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm="HS256",
    )


def decode_access_token(token: str) -> dict | None:
    """
    Decode and validate a JWT access token.

    Returns:
        Decoded payload dict if valid, None if invalid/expired.

    python-jose automatically checks:
        - Signature validity (was it signed with our SECRET_KEY?)
        - Expiration (is the token still valid?)
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"],
        )
        # Verify this is an access token, not some other type
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# One-Time Tokens (email verification & password reset)
# ---------------------------------------------------------------------------


def create_email_verify_token(user_id: str) -> str:
    """
    Create a short-lived JWT for email address verification.

    Expires after EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES (default 60 min).
    Payload type is "email_verify" — decode_one_time_token validates this.
    """
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(
        minutes=settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": user_id,
        "type": "email_verify",
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_password_reset_token(user_id: str) -> str:
    """
    Create a short-lived JWT for password reset.

    Expires after PASSWORD_RESET_TOKEN_EXPIRE_MINUTES (default 15 min).
    Payload type is "password_reset" — shorter expiry than verify tokens
    because compromised reset links are higher risk.
    """
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(
        minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": user_id,
        "type": "password_reset",
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_one_time_token(token: str, expected_type: str) -> str | None:
    """
    Decode and validate a one-time JWT (email verify or password reset).

    Args:
        token: The raw JWT string.
        expected_type: "email_verify" or "password_reset".

    Returns:
        The user_id string (from "sub" claim) if valid, None otherwise.

    Why check expected_type?
        Prevents token-type confusion attacks — a password-reset token
        should never be accepted as an email-verification token.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != expected_type:
            return None
        user_id: str | None = payload.get("sub")
        return user_id
    except JWTError:
        return None
