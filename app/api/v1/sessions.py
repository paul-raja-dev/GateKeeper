"""
GateKeeper - Session Management Routes

Endpoints:
    GET    /api/v1/sessions      — List active sessions
    DELETE /api/v1/sessions/{id} — Revoke a specific session
"""

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import SessionResponse
from app.services import session_service
from app.utils.dependencies import get_current_session_id, get_current_user

router = APIRouter()


@router.get(
    "",
    response_model=list[SessionResponse],
    summary="List active sessions",
    responses={
        401: {"description": "Not authenticated"},
    },
)
async def list_sessions(
    current_user: User = Depends(get_current_user),
    current_session_id: str = Depends(get_current_session_id),
    db: AsyncSession = Depends(get_db),
):
    """
    List all active sessions for the current user.

    Each session represents a logged-in device/browser.
    The current session is marked with `is_current: true`.
    """
    sessions = await session_service.get_active_sessions(
        db=db, user_id=str(current_user.id)
    )

    result = []
    for s in sessions:
        session_data = SessionResponse.model_validate(s)
        session_data.is_current = str(s.id) == current_session_id
        result.append(session_data)

    return result


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a specific session",
    responses={
        401: {"description": "Not authenticated"},
        404: {"description": "Session not found"},
    },
)
async def revoke_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke a specific session by its ID.

    Use this to log out a specific device remotely.
    """
    await session_service.revoke_session(
        db=db, session_id=str(session_id), user_id=str(current_user.id)
    )
