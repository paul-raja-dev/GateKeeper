"""
GateKeeper - Authentication Routes

Endpoints:
    POST /api/v1/auth/register  — Create a new user account
    POST /api/v1/auth/login     — Authenticate and get JWT token
    GET  /api/v1/auth/me        — Get current user profile (protected)

These routes are intentionally thin — they parse the request,
call the service layer, and return the response. No business logic here.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.services import auth_service
from app.utils.dependencies import get_current_user

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
    summary="Login and get access token",
    responses={
        401: {"description": "Invalid email or password"},
        403: {"description": "Account is disabled"},
    },
)
async def login(
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate with email and password.

    Returns a JWT access token that must be included in the
    Authorization header for protected endpoints:

        Authorization: Bearer <access_token>
    """
    access_token = await auth_service.authenticate_user(db=db, login_data=login_data)
    return TokenResponse(access_token=access_token)


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
