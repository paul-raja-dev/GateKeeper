"""
GateKeeper - FastAPI Dependencies

Reusable dependencies injected into route handlers via FastAPI's
Depends() system.

Dependencies:
- get_current_user: Extracts Bearer token, decodes JWT, returns User
- get_current_session_id: Extracts session_id from JWT payload

Usage in a route:
    @router.get("/protected")
    async def protected_route(
        current_user: User = Depends(get_current_user),
        session_id: str = Depends(get_current_session_id),
    ):
        return {"user": current_user.email, "session": session_id}
"""

import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.utils.security import decode_access_token

# OAuth2PasswordBearer extracts the token from the Authorization header.
# tokenUrl is the endpoint clients use to obtain tokens (for Swagger UI).
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def _decode_and_validate_token(token: str) -> dict:
    """
    Decode JWT and validate its structure.

    Returns the full payload dict. Raises 401 if invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    if payload.get("sub") is None:
        raise credentials_exception

    return payload


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency that returns the currently authenticated user.

    Raises:
        HTTPException 401: If token is missing, invalid, expired,
                           or user doesn't exist.
        HTTPException 403: If account is disabled.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = _decode_and_validate_token(token)
    user_id_str = payload.get("sub")

    # Parse UUID
    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise credentials_exception from None

    # Look up the user in the database
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    # Check if the account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    return user


def get_current_session_id(
    token: str = Depends(oauth2_scheme),
) -> str:
    """
    Dependency that extracts the session_id from the JWT payload.

    Used by logout to know which session to revoke.
    """
    payload = _decode_and_validate_token(token)
    session_id = payload.get("session_id")

    if session_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing session information",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return session_id
