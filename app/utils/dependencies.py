"""
GateKeeper - FastAPI Dependencies

Reusable dependencies injected into route handlers via FastAPI's
Depends() system.

The main dependency here is get_current_user, which:
1. Extracts the Bearer token from the Authorization header
2. Decodes and validates the JWT
3. Looks up the user in the database
4. Returns the User object or raises 401

Usage in a route:
    @router.get("/protected")
    async def protected_route(
        current_user: User = Depends(get_current_user),
    ):
        return {"message": f"Hello {current_user.full_name}"}
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


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency that returns the currently authenticated user.

    Raises:
        HTTPException 401: If token is missing, invalid, expired,
                           or user doesn't exist / is inactive.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Decode the JWT
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    # Extract user ID from the token's "sub" (subject) claim
    user_id_str: str | None = payload.get("sub")
    if user_id_str is None:
        raise credentials_exception

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
