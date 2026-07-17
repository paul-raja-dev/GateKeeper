"""
GateKeeper - Session Service

Business logic for session management:
- Creating sessions on login
- Refreshing tokens (with rotation)
- Revoking sessions (logout)
- Listing active sessions

Token rotation security:
    Each refresh token can only be used ONCE. When a token is used,
    the old session is revoked and a new one is created. This limits
    the damage if a refresh token is stolen — the legitimate user's
    next refresh attempt will fail, alerting them to the breach.
"""

import logging
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.session import Session
from app.utils.security import (
    create_access_token,
    create_refresh_token,
    hash_token,
)

logger = logging.getLogger(__name__)


async def create_session(
    db: AsyncSession,
    user_id: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    """
    Create a new login session and return a token pair.

    Called after successful authentication. Creates a session record
    in the database and returns both access and refresh tokens.

    Args:
        db: Database session
        user_id: UUID string of the authenticated user
        ip_address: Client's IP address
        user_agent: Client's User-Agent header

    Returns:
        dict with access_token, refresh_token, and token_type
    """
    settings = get_settings()

    # Generate a random refresh token
    raw_refresh_token = create_refresh_token()

    # Calculate expiry
    expires_at = datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    # Create session record with HASHED refresh token
    session = Session(
        user_id=user_id,
        refresh_token_hash=hash_token(raw_refresh_token),
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
    )

    db.add(session)
    await db.flush()
    await db.refresh(session)

    # Create access token with session_id in payload
    access_token = create_access_token(
        data={"sub": str(user_id), "session_id": str(session.id)}
    )

    logger.info("Session created for user %s from %s", user_id, ip_address)

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
        "token_type": "bearer",
    }


async def refresh_session(
    db: AsyncSession,
    raw_refresh_token: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    """
    Refresh a session — rotate the refresh token and issue a new token pair.

    Steps:
    1. Hash the incoming refresh token
    2. Look up the session by hash
    3. Validate: not revoked, not expired
    4. Revoke the old session
    5. Create a new session with a fresh refresh token
    6. Return new token pair

    This is token rotation — each refresh token is single-use.

    Args:
        db: Database session
        raw_refresh_token: The raw refresh token string from the client
        ip_address: Client's current IP
        user_agent: Client's current User-Agent

    Returns:
        dict with new access_token, refresh_token, and token_type

    Raises:
        HTTPException 401: If token is invalid, revoked, or expired
    """
    token_hash = hash_token(raw_refresh_token)

    # Find the session by token hash
    result = await db.execute(
        select(Session).where(Session.refresh_token_hash == token_hash)
    )
    session = result.scalar_one_or_none()

    if session is None:
        logger.warning("Refresh attempt with unknown token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # Check if revoked
    if session.is_revoked:
        logger.warning(
            "Refresh attempt with revoked token for user %s",
            session.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # Check if expired
    if session.expires_at < datetime.now(UTC):
        logger.warning(
            "Refresh attempt with expired token for user %s",
            session.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )

    # Revoke the old session (token rotation)
    session.is_revoked = True
    await db.flush()

    # Create a new session
    return await create_session(
        db=db,
        user_id=str(session.user_id),
        ip_address=ip_address or session.ip_address,
        user_agent=user_agent or session.user_agent,
    )


async def revoke_session(
    db: AsyncSession,
    session_id: str,
    user_id: str,
) -> None:
    """
    Revoke a specific session (logout from one device).

    Args:
        db: Database session
        session_id: UUID of the session to revoke
        user_id: UUID of the user (to verify ownership)

    Raises:
        HTTPException 404: If session not found or doesn't belong to user
    """
    result = await db.execute(
        select(Session).where(
            Session.id == session_id,
            Session.user_id == user_id,
            Session.is_revoked.is_(False),
        )
    )
    session = result.scalar_one_or_none()

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    session.is_revoked = True
    await db.flush()

    logger.info("Session %s revoked for user %s", session_id, user_id)


async def revoke_all_sessions(
    db: AsyncSession,
    user_id: str,
) -> int:
    """
    Revoke ALL active sessions for a user (logout everywhere).

    Returns the number of sessions revoked.
    """
    result = await db.execute(
        select(Session).where(
            Session.user_id == user_id,
            Session.is_revoked.is_(False),
        )
    )
    sessions = result.scalars().all()

    count = 0
    for session in sessions:
        session.is_revoked = True
        count += 1

    await db.flush()
    logger.info("Revoked %d sessions for user %s", count, user_id)
    return count


async def get_active_sessions(
    db: AsyncSession,
    user_id: str,
) -> list[Session]:
    """
    Get all active (non-revoked, non-expired) sessions for a user.

    Returns list of Session objects, ordered by most recent first.
    """
    now = datetime.now(UTC)
    result = await db.execute(
        select(Session)
        .where(
            Session.user_id == user_id,
            Session.is_revoked.is_(False),
            Session.expires_at > now,
        )
        .order_by(Session.last_active_at.desc())
    )
    return list(result.scalars().all())
