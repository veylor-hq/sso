"""Administrative API endpoints for Veylor SSO."""

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field
from app.dependencies.auth import require_admin_user
from app.models.oauth_client import OAuthClient
from app.models.session import BrowserSession
from app.models.user import User
from app.security.passwords import hash_password
from app.security.random import generate_opaque_id, generate_opaque_token, hash_token
from app.services.authentication import create_password_reset_token
from app.services.email import send_password_reset_email

router = APIRouter(
    prefix="/api/admin",
    tags=["Admin Command API"],
    dependencies=[Depends(require_admin_user)],
)


# ============================================================================
# Schemas: OAuth Clients
# ============================================================================

class CreateClientRequest(BaseModel):
    client_id: str = Field(..., min_length=2, max_length=50)
    client_name: str = Field(..., min_length=2, max_length=100)
    client_type: str = Field(default="public")
    redirect_uris: List[str] = Field(..., min_length=1)
    allowed_scopes: List[str] = Field(default=["openid", "profile", "email"])
    trusted: bool = Field(default=False)
    generate_secret: bool = Field(default=False)


class UpdateClientRequest(BaseModel):
    client_name: Optional[str] = None
    client_type: Optional[str] = None
    redirect_uris: Optional[List[str]] = None
    allowed_scopes: Optional[List[str]] = None
    trusted: Optional[bool] = None
    disabled: Optional[bool] = None


class ClientResponse(BaseModel):
    client_id: str
    client_name: str
    client_type: str
    redirect_uris: List[str]
    allowed_scopes: List[str]
    trusted: bool
    disabled: bool
    has_secret: bool
    client_secret: Optional[str] = None
    created_at: str
    updated_at: str

    @classmethod
    def from_model(cls, client: OAuthClient, raw_secret: Optional[str] = None) -> "ClientResponse":
        return cls(
            client_id=client.client_id,
            client_name=client.client_name,
            client_type=client.client_type,
            redirect_uris=client.redirect_uris,
            allowed_scopes=client.allowed_scopes,
            trusted=client.trusted,
            disabled=client.disabled,
            has_secret=bool(client.client_secret_hash),
            client_secret=raw_secret,
            created_at=client.created_at.isoformat(),
            updated_at=client.updated_at.isoformat(),
        )


# ============================================================================
# Schemas: Users
# ============================================================================

class CreateUserRequest(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=8, max_length=128)
    email_verified: bool = Field(default=True)
    authorized_apps: List[str] = Field(default_factory=list)
    is_admin: bool = Field(default=False)


class UpdateUserRequest(BaseModel):
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email_verified: Optional[bool] = None
    disabled: Optional[bool] = None
    is_admin: Optional[bool] = None
    authorized_apps: Optional[List[str]] = None


class ResetUserPasswordRequest(BaseModel):
    new_password: Optional[str] = Field(default=None, min_length=8, max_length=128)
    send_reset_email: bool = Field(default=False)


class UserAdminOut(BaseModel):
    id: str
    email: str
    email_verified: bool
    name: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    avatar_url: Optional[str] = None
    google_sub: Optional[str] = None
    auth_provider: str
    is_admin: bool
    authorized_apps: List[str]
    disabled: bool
    created_at: str
    updated_at: str
    last_login_at: Optional[str] = None

    @classmethod
    def from_model(cls, user: User) -> "UserAdminOut":
        return cls(
            id=user.id,
            email=user.email,
            email_verified=user.email_verified,
            name=user.name,
            given_name=user.given_name,
            family_name=user.family_name,
            avatar_url=user.avatar_url,
            google_sub=user.google_sub,
            auth_provider=user.auth_provider,
            is_admin=user.is_admin,
            authorized_apps=user.authorized_apps or [],
            disabled=user.disabled,
            created_at=user.created_at.isoformat(),
            updated_at=user.updated_at.isoformat(),
            last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        )


class PaginatedUsersResponse(BaseModel):
    items: List[UserAdminOut]
    total: int
    limit: int
    skip: int


# ============================================================================
# Insights
# ============================================================================

@router.get("/insights")
async def get_system_insights() -> Dict[str, Any]:
    """Retrieve comprehensive ecosystem usage metrics and KPIs."""
    now = datetime.now(timezone.utc)
    t_24h = now - timedelta(hours=24)
    t_7d = now - timedelta(days=7)
    t_30d = now - timedelta(days=30)

    total_users = await User.count()
    verified_users = await User.find(User.email_verified == True).count()
    disabled_users = await User.find(User.disabled == True).count()

    active_24h = await User.find(User.last_login_at >= t_24h).count()
    active_7d = await User.find(User.last_login_at >= t_7d).count()
    active_30d = await User.find(User.last_login_at >= t_30d).count()

    local_provider_users = await User.find(User.auth_provider == "local").count()
    google_provider_users = await User.find(User.auth_provider == "google").count()

    # Apps distribution
    known_apps = ["egarage", "relay", "pager", "warden"]
    apps_distribution: Dict[str, int] = {}
    for app_id in known_apps:
        cnt = await User.find({"authorized_apps": app_id}).count()
        apps_distribution[app_id] = cnt

    total_sessions = await BrowserSession.find(BrowserSession.revoked_at == None).count()
    total_clients = await OAuthClient.count()
    trusted_clients = await OAuthClient.find(OAuthClient.trusted == True).count()

    # 5 most recent registrations
    recent_users = await User.find_all().sort("-created_at").limit(5).to_list()

    return {
        "summary": {
            "total_users": total_users,
            "verified_users": verified_users,
            "disabled_users": disabled_users,
            "active_users_24h": active_24h,
            "active_users_7d": active_7d,
            "active_users_30d": active_30d,
            "active_sessions": total_sessions,
            "total_clients": total_clients,
            "trusted_clients": trusted_clients,
        },
        "providers": {
            "local": local_provider_users,
            "google": google_provider_users,
        },
        "apps_distribution": apps_distribution,
        "recent_users": [UserAdminOut.from_model(u) for u in recent_users],
    }


# ============================================================================
# OAuth Clients CRUD
# ============================================================================

@router.get("/clients", response_model=List[ClientResponse])
async def list_clients():
    """List all registered OAuth clients."""
    clients = await OAuthClient.find_all().sort("-created_at").to_list()
    return [ClientResponse.from_model(c) for c in clients]


@router.post("/clients", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
async def create_client(payload: CreateClientRequest):
    """Register a new trusted website / OAuth client."""
    client_id = payload.client_id.strip().lower()
    existing = await OAuthClient.find_one(OAuthClient.client_id == client_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Client '{client_id}' already exists.",
        )

    raw_secret = None
    secret_hash = None
    if payload.generate_secret or payload.client_type == "confidential":
        raw_secret = f"vsec_{generate_opaque_token(24)}"
        secret_hash = hash_token(raw_secret)

    now = datetime.now(timezone.utc)
    clean_uris = [uri.strip() for uri in payload.redirect_uris if uri.strip()]
    client = OAuthClient(
        client_id=client_id,
        client_name=payload.client_name.strip(),
        client_secret_hash=secret_hash,
        client_type=payload.client_type,
        redirect_uris=clean_uris,
        allowed_scopes=payload.allowed_scopes,
        trusted=payload.trusted,
        disabled=False,
        created_at=now,
        updated_at=now,
    )
    await client.insert()
    return ClientResponse.from_model(client, raw_secret=raw_secret)


@router.get("/clients/{client_id}", response_model=ClientResponse)
async def get_client(client_id: str):
    """Retrieve details for an OAuth client."""
    client = await OAuthClient.find_one(OAuthClient.client_id == client_id)
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    return ClientResponse.from_model(client)


@router.put("/clients/{client_id}", response_model=ClientResponse)
@router.patch("/clients/{client_id}", response_model=ClientResponse)
async def update_client(client_id: str, payload: UpdateClientRequest):
    """Update OAuth client configuration."""
    client = await OAuthClient.find_one(OAuthClient.client_id == client_id)
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    if payload.client_name is not None:
        client.client_name = payload.client_name.strip()
    if payload.client_type is not None:
        client.client_type = payload.client_type
    if payload.redirect_uris is not None:
        client.redirect_uris = [uri.strip() for uri in payload.redirect_uris if uri.strip()]
    if payload.allowed_scopes is not None:
        client.allowed_scopes = payload.allowed_scopes
    if payload.trusted is not None:
        client.trusted = payload.trusted
    if payload.disabled is not None:
        client.disabled = payload.disabled

    client.updated_at = datetime.now(timezone.utc)
    await client.save()
    return ClientResponse.from_model(client)


@router.delete("/clients/{client_id}", status_code=status.HTTP_200_OK)
async def delete_client(client_id: str):
    """Delete an OAuth client."""
    client = await OAuthClient.find_one(OAuthClient.client_id == client_id)
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    await client.delete()
    return {"message": f"Client '{client_id}' successfully deleted"}


@router.post("/clients/{client_id}/regenerate-secret")
async def regenerate_client_secret(client_id: str) -> Dict[str, str]:
    """Generate a new cryptographic client secret."""
    client = await OAuthClient.find_one(OAuthClient.client_id == client_id)
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    raw_secret = f"vsec_{generate_opaque_token(24)}"
    client.client_secret_hash = hash_token(raw_secret)
    client.client_type = "confidential"
    client.updated_at = datetime.now(timezone.utc)
    await client.save()

    return {
        "client_id": client.client_id,
        "client_secret": raw_secret,
        "message": "Secret generated. Store this secret securely. It will not be shown again.",
    }


# ============================================================================
# User Directory CRUD & App Filtering
# ============================================================================

@router.get("/users", response_model=PaginatedUsersResponse)
async def list_users(
    search: Optional[str] = Query(None, description="Search email, name, or id"),
    app: Optional[str] = Query(None, description="Filter by app: egarage, relay, pager, warden"),
    provider: Optional[str] = Query(None, description="Filter by provider: local, google"),
    verified: Optional[bool] = Query(None, description="Filter by email verification"),
    disabled: Optional[bool] = Query(None, description="Filter by disabled status"),
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
):
    """List users with multi-dimensional app filtering, search, and pagination."""
    criteria: Dict[str, Any] = {}

    if search:
        s = search.strip()
        rgx = re.compile(re.escape(s), re.IGNORECASE)
        criteria["$or"] = [
            {"email": rgx},
            {"name": rgx},
            {"id": rgx},
        ]

    if app:
        criteria["authorized_apps"] = app.strip().lower()

    if provider:
        criteria["auth_provider"] = provider.strip().lower()

    if verified is not None:
        criteria["email_verified"] = verified

    if disabled is not None:
        criteria["disabled"] = disabled

    total = await User.find(criteria).count()
    users = await User.find(criteria).sort("-created_at").skip(skip).limit(limit).to_list()

    return PaginatedUsersResponse(
        items=[UserAdminOut.from_model(u) for u in users],
        total=total,
        limit=limit,
        skip=skip,
    )


@router.post("/users", response_model=UserAdminOut, status_code=status.HTTP_201_CREATED)
async def create_user_admin(payload: CreateUserRequest):
    """Manually create a new user account with assigned apps."""
    norm_email = payload.email.strip().lower()
    existing = await User.find_one(User.email == norm_email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email '{norm_email}' already exists.",
        )

    now = datetime.now(timezone.utc)
    user_id = generate_opaque_id("usr")
    pw_hash = hash_password(payload.password)

    user = User(
        id=user_id,
        email=norm_email,
        email_verified=payload.email_verified,
        password_hash=pw_hash,
        name=payload.name.strip(),
        auth_provider="local",
        is_admin=payload.is_admin,
        authorized_apps=[a.strip().lower() for a in payload.authorized_apps if a.strip()],
        disabled=False,
        created_at=now,
        updated_at=now,
    )
    await user.insert()
    return UserAdminOut.from_model(user)


@router.get("/users/{user_id}", response_model=UserAdminOut)
async def get_user_detail(user_id: str):
    """Retrieve full profile for a specific user."""
    user = await User.find_one(User.id == user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserAdminOut.from_model(user)


@router.put("/users/{user_id}", response_model=UserAdminOut)
@router.patch("/users/{user_id}", response_model=UserAdminOut)
async def update_user(user_id: str, payload: UpdateUserRequest):
    """Update user profile, status, assigned apps, or privileges."""
    user = await User.find_one(User.id == user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.name is not None:
        user.name = payload.name.strip()
    if payload.given_name is not None:
        user.given_name = payload.given_name.strip() or None
    if payload.family_name is not None:
        user.family_name = payload.family_name.strip() or None
    if payload.email_verified is not None:
        user.email_verified = payload.email_verified
    if payload.disabled is not None:
        user.disabled = payload.disabled
    if payload.is_admin is not None:
        user.is_admin = payload.is_admin
    if payload.authorized_apps is not None:
        user.authorized_apps = [a.strip().lower() for a in payload.authorized_apps if a.strip()]

    user.updated_at = datetime.now(timezone.utc)
    await user.save()
    return UserAdminOut.from_model(user)


@router.delete("/users/{user_id}")
async def delete_user(user_id: str):
    """Delete a user account and terminate all their sessions."""
    user = await User.find_one(User.id == user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Revoke all sessions
    await BrowserSession.find(BrowserSession.user_id == user_id).delete()
    await user.delete()
    return {"message": f"User '{user_id}' ({user.email}) successfully deleted"}


@router.post("/users/{user_id}/reset-password")
async def reset_user_password(user_id: str, payload: ResetUserPasswordRequest):
    """Set a new password directly or dispatch a reset link email."""
    user = await User.find_one(User.id == user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.new_password:
        user.password_hash = hash_password(payload.new_password)
        user.updated_at = datetime.now(timezone.utc)
        await user.save()
        # Revoke all active sessions on administrative password reset
        now = datetime.now(timezone.utc)
        await BrowserSession.find(
            BrowserSession.user_id == user.id,
            BrowserSession.revoked_at == None,
        ).update({"$set": {"revoked_at": now}})
        return {"message": f"Password updated directly for {user.email}"}

    if payload.send_reset_email:
        res = await create_password_reset_token(user.email)
        if res:
            _, token = res
            await send_password_reset_email(user.email, token)
            return {"message": f"Password reset email dispatched to {user.email}"}
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to generate password reset token")

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Specify either new_password or send_reset_email")


# ============================================================================
# Active Browser Sessions
# ============================================================================

@router.get("/sessions")
async def list_active_sessions(limit: int = Query(50, ge=1, le=100)) -> List[Dict[str, Any]]:
    """List recent active browser sessions across all users."""
    sessions = await BrowserSession.find(BrowserSession.revoked_at == None).sort("-last_seen_at").limit(limit).to_list()
    out = []
    for s in sessions:
        user = await User.find_one(User.id == s.user_id)
        out.append({
            "session_id": s.id,
            "user_id": s.user_id,
            "user_email": user.email if user else "unknown",
            "user_name": user.name if user else "Unknown",
            "ip_address": s.ip_address,
            "user_agent": s.user_agent,
            "created_at": s.created_at.isoformat(),
            "last_active_at": s.last_seen_at.isoformat(),
        })
    return out


@router.delete("/sessions/{session_id}")
async def revoke_session_admin(session_id: str):
    """Terminate an active browser session."""
    session = await BrowserSession.find_one(BrowserSession.id == session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    session.revoked_at = datetime.now(timezone.utc)
    await session.save()
    return {"message": "Session terminated"}


@router.delete("/users/{user_id}/sessions")
async def revoke_all_user_sessions_admin(user_id: str):
    """Terminate all active browser sessions for a user."""
    sessions = await BrowserSession.find(
        BrowserSession.user_id == user_id,
        BrowserSession.revoked_at == None,
    ).to_list()
    now = datetime.now(timezone.utc)
    for s in sessions:
        s.revoked_at = now
        await s.save()
    return {"message": f"Terminated {len(sessions)} active session(s) for user {user_id}"}
