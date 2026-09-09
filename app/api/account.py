"""Account and session management REST API."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from app.dependencies.auth import require_session_user
from app.models.user import User
from app.services.sessions import list_user_sessions, revoke_session
from app.services.users import update_user_profile

router = APIRouter(prefix="/api/account", tags=["Account Management"])


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    avatar_url: Optional[str] = None


class SessionResponse(BaseModel):
    id: str
    created_at: str
    expires_at: str
    last_seen_at: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@router.get("")
async def get_account(user: User = Depends(require_session_user)):
    """Get profile information for currently authenticated user."""
    return {
        "id": user.id,
        "email": user.email,
        "email_verified": user.email_verified,
        "name": user.name,
        "given_name": user.given_name,
        "family_name": user.family_name,
        "avatar_url": user.avatar_url,
        "created_at": user.created_at.isoformat(),
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


@router.patch("")
async def patch_account(
    payload: UpdateProfileRequest,
    user: User = Depends(require_session_user),
):
    """Update profile details."""
    updated = await update_user_profile(
        user=user,
        name=payload.name,
        given_name=payload.given_name,
        family_name=payload.family_name,
        avatar_url=payload.avatar_url,
    )
    return {
        "message": "Profile updated successfully",
        "user": {
            "id": updated.id,
            "name": updated.name,
            "given_name": updated.given_name,
            "family_name": updated.family_name,
            "avatar_url": updated.avatar_url,
        },
    }


@router.get("/sessions", response_model=List[SessionResponse])
async def get_sessions(user: User = Depends(require_session_user)):
    """List active browser sessions for the authenticated user."""
    sessions = await list_user_sessions(user.id)
    return [
        SessionResponse(
            id=s.id,
            created_at=s.created_at.isoformat(),
            expires_at=s.expires_at.isoformat(),
            last_seen_at=s.last_seen_at.isoformat(),
            ip_address=s.ip_address,
            user_agent=s.user_agent,
        )
        for s in sessions
    ]


@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: str,
    user: User = Depends(require_session_user),
):
    """Revoke a specific active session."""
    revoked = await revoke_session(session_id=session_id, user_id=user.id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found or already revoked")
    return {"message": "Session revoked successfully"}
