"""
Tests for Phase 5: Email Verification & Password Reset

All tests run with SMTP_ENABLED=False (default in .env), so tokens are
returned directly in the API response instead of being sent by email.
This makes the test suite completely self-contained — no SMTP server needed.

Covers:
- New user is NOT verified by default
- Email verification happy path (token from resend-verification)
- Cannot verify with an invalid/expired token
- Cannot verify an already-verified account
- Forgot-password returns a token in dev mode
- Password reset happy path
- Cannot reset with an invalid token
- Cannot reset with a weak password
- Token type confusion (reset token rejected by verify endpoint)
"""

import pytest

REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"
ME_URL = "/api/v1/auth/me"
VERIFY_URL = "/api/v1/auth/verify-email"
RESEND_URL = "/api/v1/auth/resend-verification"
FORGOT_URL = "/api/v1/auth/forgot-password"
RESET_URL = "/api/v1/auth/reset-password"


async def register_and_login(client, email: str, password: str = "StrongP@ss1") -> dict:
    """Register a user and return the token pair."""
    await client.post(
        REGISTER_URL,
        json={"email": email, "password": password, "full_name": "Test User"},
    )
    resp = await client.post(LOGIN_URL, json={"email": email, "password": password})
    return resp.json()


async def get_verify_token(client, email: str) -> str:
    """
    Use resend-verification to obtain a token in dev mode.
    Returns the raw token string.
    """
    resp = await client.post(RESEND_URL, json={"email": email})
    assert resp.status_code == 200
    # Dev mode returns: "[dev] Verification token: <token>"
    return resp.json()["message"].split(": ", 1)[1]


async def get_reset_token(client, email: str) -> str:
    """
    Use forgot-password to obtain a reset token in dev mode.
    Returns the raw token string.
    """
    resp = await client.post(FORGOT_URL, json={"email": email})
    assert resp.status_code == 200
    # Dev mode returns: "[dev] Reset token: <token>"
    return resp.json()["message"].split(": ", 1)[1]


# ---------------------------------------------------------------------------
# Default state
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_user_is_not_verified(client):
    """A freshly registered user should have is_verified=False."""
    tokens = await register_and_login(client, "unverified@example.com")
    resp = await client.get(
        ME_URL, headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert resp.status_code == 200
    assert resp.json()["is_verified"] is False


# ---------------------------------------------------------------------------
# Email Verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_email_success(client):
    """Providing a valid token should set is_verified=True."""
    await register_and_login(client, "verify@example.com")
    token = await get_verify_token(client, "verify@example.com")

    resp = await client.get(VERIFY_URL, params={"token": token})

    assert resp.status_code == 200
    assert resp.json()["is_verified"] is True
    assert resp.json()["email"] == "verify@example.com"


@pytest.mark.asyncio
async def test_verify_email_invalid_token(client):
    """A garbage token must return 400."""
    resp = await client.get(VERIFY_URL, params={"token": "totally-invalid-token"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_verify_email_already_verified(client):
    """Verifying an already-verified account should return 400."""
    await register_and_login(client, "alreadydone@example.com")
    token = await get_verify_token(client, "alreadydone@example.com")

    # First verification — succeeds
    first = await client.get(VERIFY_URL, params={"token": token})
    assert first.status_code == 200

    # Attempting to verify again (same token, still valid JWT) should fail
    # because is_verified is now True in the DB
    resp = await client.get(VERIFY_URL, params={"token": token})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_resend_verification_unknown_email(client):
    """Requesting for an unknown email must still return 200 (anti-enumeration)."""
    resp = await client.post(RESEND_URL, json={"email": "ghost@example.com"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Password Reset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_forgot_password_returns_token_in_dev_mode(client):
    """In dev mode (SMTP_ENABLED=False) the token appears in the response."""
    await register_and_login(client, "forgotp@example.com")
    resp = await client.post(FORGOT_URL, json={"email": "forgotp@example.com"})

    assert resp.status_code == 200
    assert "[dev] Reset token:" in resp.json()["message"]


@pytest.mark.asyncio
async def test_forgot_password_unknown_email(client):
    """Unknown email must still return 200 (anti-enumeration)."""
    resp = await client.post(FORGOT_URL, json={"email": "nobody@example.com"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_reset_password_success(client):
    """Happy path: reset password and login with the new password."""
    await register_and_login(client, "resetme@example.com")
    token = await get_reset_token(client, "resetme@example.com")

    resp = await client.post(
        RESET_URL,
        json={"token": token, "new_password": "NewP@ssword99"},
    )
    assert resp.status_code == 200

    # Old password should no longer work
    old_login = await client.post(
        LOGIN_URL,
        json={"email": "resetme@example.com", "password": "StrongP@ss1"},
    )
    assert old_login.status_code == 401

    # New password should work
    new_login = await client.post(
        LOGIN_URL,
        json={"email": "resetme@example.com", "password": "NewP@ssword99"},
    )
    assert new_login.status_code == 200


@pytest.mark.asyncio
async def test_reset_password_invalid_token(client):
    """A garbage reset token must return 400."""
    resp = await client.post(
        RESET_URL,
        json={"token": "fake-garbage-token", "new_password": "NewP@ssword99"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_reset_password_weak_password(client):
    """Schema validation should reject passwords that don't meet strength rules."""
    await register_and_login(client, "weakpw@example.com")
    token = await get_reset_token(client, "weakpw@example.com")

    resp = await client.post(
        RESET_URL,
        json={"token": token, "new_password": "tooweak"},
    )
    assert resp.status_code == 422  # Pydantic validation error


@pytest.mark.asyncio
async def test_token_type_confusion(client):
    """A password-reset token must not be accepted as an email-verify token."""
    await register_and_login(client, "confused@example.com")
    reset_token = await get_reset_token(client, "confused@example.com")

    # Try to use a reset token as a verification token
    resp = await client.get(VERIFY_URL, params={"token": reset_token})
    assert resp.status_code == 400
