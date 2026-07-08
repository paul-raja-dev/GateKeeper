"""
GateKeeper - Security Utilities

Provides:
- Password hashing (bcrypt)
- Password verification
- JWT token creation
- JWT token decoding

Why bcrypt?
    Bcrypt is intentionally slow — it's designed to resist brute-force attacks.
    Even if your database leaks, attackers can't crack bcrypt hashes in
    reasonable time. Fast hashes like MD5/SHA256 can be cracked at billions
    of attempts per second. Bcrypt limits attempts to ~thousands per second.

Why python-jose for JWT?
    It supports multiple algorithms (HS256, RS256), handles expiration
    automatically, and is well-maintained. We use HS256 (symmetric) for
    simplicity — the same SECRET_KEY signs and verifies tokens.

Note: We use bcrypt directly instead of passlib because passlib
has compatibility issues with bcrypt >= 4.1. Using bcrypt directly
is simpler and more maintainable.
"""

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
# JWT Tokens
# ---------------------------------------------------------------------------


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Payload to encode (typically {"sub": user_id})
        expires_delta: Custom expiration time. If None, uses settings default.

    Returns:
        Encoded JWT string.

    The token contains:
        - sub: subject (user ID)
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
