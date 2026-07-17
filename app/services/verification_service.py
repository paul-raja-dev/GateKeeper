"""
GateKeeper - Email Verification & Password Reset Service

Business logic for:
- Sending verification emails and marking accounts as verified
- Sending password reset emails and processing resets

Separation from auth_service keeps each service focused.
All DB operations are done here; routes stay thin.
"""

import logging
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.services.email_service import (
    send_password_reset_email,
    send_verification_email,
)
from app.utils.security import (
    create_email_verify_token,
    create_password_reset_token,
    decode_one_time_token,
    hash_password,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Email Verification
# ---------------------------------------------------------------------------


async def send_verification(db: AsyncSession, user: User) -> str:
    """
    Generate a verification token and dispatch the verification email.

    Args:
        db: Database session (unused here, reserved for future audit log)
        user: The user who needs to verify their email

    Returns:
        The raw verification token (returned in API response when SMTP
        is disabled, so developers can test without a mail server).

    Raises:
        HTTPException 400: If the user is already verified.
    """
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already verified",
        )

    token = create_email_verify_token(str(user.id))
    await send_verification_email(user.email, token)

    logger.info("Verification email dispatched for user: %s", user.email)
    return token


async def verify_email(db: AsyncSession, token: str) -> User:
    """
    Verify a user's email address using a one-time token.

    Args:
        db: Database session
        token: The raw JWT from the verification link

    Returns:
        The updated User object with is_verified=True.

    Raises:
        HTTPException 400: If the token is invalid, expired, or already used.
        HTTPException 404: If the user no longer exists.
    """
    user_id_str = decode_one_time_token(token, expected_type="email_verify")
    if user_id_str is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        ) from None

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already verified",
        )

    user.is_verified = True
    await db.commit()
    await db.refresh(user)

    logger.info("Email verified for user: %s", user.email)
    return user


# ---------------------------------------------------------------------------
# Password Reset
# ---------------------------------------------------------------------------


async def request_password_reset(db: AsyncSession, email: str) -> str | None:
    """
    Initiate a password reset flow for the given email.

    Security note: We always return a 200 response regardless of whether
    the email exists. This prevents email enumeration — an attacker
    shouldn't be able to discover which emails are registered by
    observing different responses.

    Args:
        db: Database session
        email: The email to send the reset link to

    Returns:
        The raw reset token if the user was found (for dev/test when SMTP
        is disabled), or None if the email isn't registered.
    """
    email = email.lower().strip()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        logger.info("Password reset requested for unknown email: %s", email)
        return None

    if not user.is_active:
        logger.info("Password reset requested for disabled account: %s", email)
        return None

    token = create_password_reset_token(str(user.id))
    await send_password_reset_email(user.email, token)

    logger.info("Password reset email dispatched for user: %s", user.email)
    return token


async def reset_password(db: AsyncSession, token: str, new_password: str) -> User:
    """
    Reset a user's password using a one-time reset token.

    Args:
        db: Database session
        token: The raw JWT from the password reset link
        new_password: The new plaintext password (will be hashed here)

    Returns:
        The updated User object.

    Raises:
        HTTPException 400: If the token is invalid or expired.
        HTTPException 404: If the user no longer exists.
    """
    user_id_str = decode_one_time_token(token, expected_type="password_reset")
    if user_id_str is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        ) from None

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    user.hashed_password = hash_password(new_password)
    await db.commit()
    await db.refresh(user)

    logger.info("Password reset completed for user: %s", user.email)
    return user
