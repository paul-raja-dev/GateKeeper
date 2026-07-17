"""
GateKeeper - Authentication Service

Business logic for user registration and authentication.

This is the "thick" layer — all decisions and orchestration happen here.
Routes call these functions and return the results. Routes should never
contain business logic directly.

Why a service layer?
- Testable without HTTP (you can call these functions directly in tests)
- Reusable (multiple routes or background tasks can use the same logic)
- Single responsibility (routes handle HTTP, services handle logic)
"""

import logging

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.schemas.auth import UserLogin, UserRegister
from app.utils.security import (
    hash_password,
    verify_password,
)

logger = logging.getLogger(__name__)


async def register_user(
    db: AsyncSession,
    user_data: UserRegister,
) -> User:
    """
    Register a new user account.

    Steps:
    1. Check if email already exists → 409 Conflict
    2. Hash the password
    3. Create the user record
    4. Return the created user

    Args:
        db: Database session
        user_data: Validated registration data

    Returns:
        The newly created User object

    Raises:
        HTTPException 409: If email is already registered
    """
    # Check for existing email
    result = await db.execute(select(User).where(User.email == user_data.email))
    existing_user = result.scalar_one_or_none()

    if existing_user is not None:
        logger.warning(
            "Registration attempt with existing email: %s",
            user_data.email,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )

    # Create user with hashed password
    user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
    )

    db.add(user)
    # Flush to get the generated ID and timestamps without committing.
    # The actual commit happens in get_db() dependency after the
    # route handler returns successfully.
    await db.flush()
    await db.refresh(user)

    logger.info("New user registered: %s", user.email)
    return user


async def authenticate_user(
    db: AsyncSession,
    login_data: UserLogin,
) -> User:
    """
    Authenticate a user by verifying their credentials.

    Returns the User object if credentials are valid. The caller
    (route handler) is responsible for creating a session.

    Steps:
    1. Find user by email → 401 if not found
    2. Verify password → 401 if wrong
    3. Check account is active → 403 if disabled
    4. Return the authenticated User

    Args:
        db: Database session
        login_data: Validated login credentials

    Returns:
        The authenticated User object

    Raises:
        HTTPException 401: If credentials are invalid
        HTTPException 403: If account is disabled

    Security note:
        We use the same error message for "user not found" and
        "wrong password" to prevent user enumeration attacks.
    """
    # Find user by email
    result = await db.execute(select(User).where(User.email == login_data.email))
    user = result.scalar_one_or_none()

    # Intentionally vague error message — prevents user enumeration
    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if user is None:
        logger.warning(
            "Login attempt with non-existent email: %s",
            login_data.email,
        )
        raise invalid_credentials

    # Verify password
    if not verify_password(login_data.password, user.hashed_password):
        logger.warning("Failed login attempt for: %s", user.email)
        raise invalid_credentials

    # Check if account is active
    if not user.is_active:
        logger.warning("Login attempt on disabled account: %s", user.email)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    logger.info("Successful login: %s", user.email)
    return user
