"""
GateKeeper - Authentication Routes

Endpoints:
    POST /api/v1/auth/register    — Create a new user account
    POST /api/v1/auth/login       — Authenticate and get token pair
    POST /api/v1/auth/refresh     — Refresh tokens (rotate)
    POST /api/v1/auth/logout      — Revoke current session
    POST /api/v1/auth/logout-all  — Revoke ALL sessions
    GET  /api/v1/auth/me          — Get current user profile (protected)

These routes are intentionally thin — they parse the request,
call the service layer, and return the response. No business logic here.
"""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    RefreshTokenRequest,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.services import auth_service, session_service
from app.utils.dependencies import get_current_session_id, get_current_user

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    responses={
        409: {"description": "Email already registered"},
        422: {"description": "Validation error (weak password, invalid email)"},
    },
)
async def register(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new user account.

    - Validates email format and uniqueness
    - Enforces password strength requirements
    - Returns the created user (without password)
    """
    user = await auth_service.register_user(db=db, user_data=user_data)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and get token pair",
    responses={
        401: {"description": "Invalid email or password"},
        403: {"description": "Account is disabled"},
    },
)
async def login(
    login_data: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate with email and password.

    Returns an access token (short-lived) and a refresh token (long-lived).
    Use the refresh token to get new access tokens without re-entering
    credentials.
    """
    # Authenticate (validates credentials)
    user = await auth_service.authenticate_user(db=db, login_data=login_data)

    # Create session with device info
    tokens = await session_service.create_session(
        db=db,
        user_id=str(user.id),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(**tokens)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    responses={
        401: {"description": "Invalid, revoked, or expired refresh token"},
    },
)
async def refresh(
    body: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Exchange a refresh token for a new token pair.

    The old refresh token is revoked (single-use). A new refresh token
    is returned alongside the new access token.
    """
    tokens = await session_service.refresh_session(
        db=db,
        raw_refresh_token=body.refresh_token,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(**tokens)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout current session",
    responses={
        401: {"description": "Not authenticated"},
    },
)
async def logout(
    current_user: User = Depends(get_current_user),
    session_id: str = Depends(get_current_session_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke the current session's refresh token.

    The access token will remain valid until it expires (short-lived),
    but the refresh token can no longer be used to get new tokens.
    """
    await session_service.revoke_session(
        db=db, session_id=session_id, user_id=str(current_user.id)
    )


@router.post(
    "/logout-all",
    status_code=status.HTTP_200_OK,
    summary="Logout all sessions",
    responses={
        401: {"description": "Not authenticated"},
    },
)
async def logout_all(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke ALL active sessions for the current user.

    Use this when you suspect your account has been compromised.
    All devices will need to log in again.
    """
    count = await session_service.revoke_all_sessions(
        db=db, user_id=str(current_user.id)
    )
    return {"message": f"Logged out from {count} sessions"}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    responses={
        401: {"description": "Not authenticated"},
    },
)
async def get_me(
    current_user: User = Depends(get_current_user),
):
    """
    Get the profile of the currently authenticated user.

    Requires a valid JWT access token in the Authorization header.
    """
    return current_user
