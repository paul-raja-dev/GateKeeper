"""
GateKeeper - Authentication Routes

Endpoints:
    POST /api/v1/auth/register             — Create a new user account
    POST /api/v1/auth/login                — Authenticate and get token pair
    POST /api/v1/auth/refresh              — Refresh tokens (rotate)
    POST /api/v1/auth/logout               — Revoke current session
    POST /api/v1/auth/logout-all           — Revoke ALL sessions
    GET  /api/v1/auth/me                   — Get current user profile
    GET  /api/v1/auth/verify-email         — Verify email address (via token)
    POST /api/v1/auth/resend-verification  — Resend verification email
    POST /api/v1/auth/forgot-password      — Request a password reset email
    POST /api/v1/auth/reset-password       — Complete a password reset

These routes are intentionally thin — they parse the request,
call the service layer, and return the response. No business logic here.
"""

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    MessageResponse,
    RefreshTokenRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.services import auth_service, session_service, verification_service
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


# ---------------------------------------------------------------------------
# Phase 5: Email Verification & Password Reset
# ---------------------------------------------------------------------------


@router.get(
    "/verify-email",
    response_model=UserResponse,
    summary="Verify email address",
    responses={
        400: {"description": "Invalid or expired token / already verified"},
    },
)
async def verify_email(
    token: str = Query(..., description="Verification token from the email link"),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify a user's email address using the token from the verification email.

    The token is a short-lived signed JWT (1 hour). Once used, the user's
    is_verified flag is set to True permanently.
    """
    return await verification_service.verify_email(db=db, token=token)


@router.post(
    "/resend-verification",
    response_model=MessageResponse,
    summary="Resend verification email",
    responses={
        400: {"description": "Email already verified"},
    },
)
async def resend_verification(
    body: ResendVerificationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Resend the email verification link.

    If SMTP is disabled (dev mode), the token is returned in the response.
    """
    from sqlalchemy import select

    from app.models.user import User as UserModel

    result = await db.execute(select(UserModel).where(UserModel.email == body.email))
    user = result.scalar_one_or_none()

    if user is None:
        # Anti-enumeration: always return 200
        return MessageResponse(
            message="If this email is registered, a verification link has been sent."
        )

    token = await verification_service.send_verification(db=db, user=user)

    from app.config import get_settings

    settings = get_settings()
    if not settings.SMTP_ENABLED:
        return MessageResponse(message=f"[dev] Verification token: {token}")

    return MessageResponse(message="Verification email sent. Check your inbox.")


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request a password reset email",
)
async def forgot_password(
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Send a password reset email for the given address.

    Always returns 200 to prevent email enumeration.
    If SMTP is disabled (dev mode), the reset token is included in the response.
    """
    token = await verification_service.request_password_reset(db=db, email=body.email)

    from app.config import get_settings

    settings = get_settings()
    if token and not settings.SMTP_ENABLED:
        return MessageResponse(message=f"[dev] Reset token: {token}")

    return MessageResponse(
        message="If this email is registered, a password reset link has been sent."
    )


@router.post(
    "/reset-password",
    response_model=UserResponse,
    summary="Reset password using token",
    responses={
        400: {"description": "Invalid or expired reset token / weak password"},
    },
)
async def reset_password(
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Set a new password using the reset token from the email.

    The token expires after 15 minutes and is single-use (embedded expiry
    in the JWT). After a successful reset, all existing sessions should be
    revoked (future enhancement — Phase 11 hardening).
    """
    return await verification_service.reset_password(
        db=db, token=body.token, new_password=body.new_password
    )
