"""Authentication REST endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from app.config import get_settings
from app.dependencies.auth import get_optional_session, require_session_user
from app.dependencies.rate_limit import (
    rate_limit_forgot_password,
    rate_limit_login,
    rate_limit_register,
)
from app.models.session import BrowserSession
from app.models.user import User
from app.security.rate_limit import get_client_ip
from app.services.authentication import (
    authenticate_user,
    create_email_verification_token,
    create_password_reset_token,
    resend_email_verification,
    reset_password_with_token,
    verify_email_with_token,
)
from app.security.google import verify_google_id_token, verify_google_access_token
from app.services.email import send_password_reset_email, send_verification_email
from app.services.sessions import create_session, revoke_session
from app.services.users import create_user, get_or_create_google_user
from app.services.client_registry import resolve_and_verify_service_from_request

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# Schemas
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    name: str = Field(..., min_length=1, max_length=100)
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    client_id: Optional[str] = None
    app: Optional[str] = None
    authorized_apps: Optional[List[str]] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    client_id: Optional[str] = None


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)


class VerifyEmailRequest(BaseModel):
    token: str


class UserResponse(BaseModel):
    id: str
    email: str
    email_verified: bool
    name: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: str

    @classmethod
    def from_user(cls, user: User) -> "UserResponse":
        return cls(
            id=user.id,
            email=user.email,
            email_verified=user.email_verified,
            name=user.name,
            given_name=user.given_name,
            family_name=user.family_name,
            avatar_url=user.avatar_url,
            created_at=user.created_at.isoformat(),
        )


def _set_session_cookie(response: Response, raw_token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.SESSION_TTL_SECONDS,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        domain=settings.SESSION_COOKIE_DOMAIN,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        domain=settings.SESSION_COOKIE_DOMAIN,
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit_register)])
async def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
):
    """Register a new Veylor account, establish a server session, and send verification email."""
    # Enforce origin security and resolve service name-id from SSO database
    client = await resolve_and_verify_service_from_request(
        request=request,
        client_id_hint=payload.client_id or payload.app,
    )
    assigned_app = client.client_id if client else None

    try:
        user = await create_user(
            email=payload.email,
            password=payload.password,
            name=payload.name,
            given_name=payload.given_name,
            family_name=payload.family_name,
            authorized_apps=payload.authorized_apps,
            app=assigned_app,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Create browser session for SSO
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    _, raw_token = await create_session(user_id=user.id, ip_address=ip, user_agent=ua)
    _set_session_cookie(response, raw_token)

    # Issue verification email
    token = await create_email_verification_token(user.id)
    await send_verification_email(user.email, token)

    return UserResponse.from_user(user)


@router.post("/login", response_model=UserResponse, dependencies=[Depends(rate_limit_login)])
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
):
    """Authenticate user with email and password, creating a secure server-side session."""
    # Enforce origin security and resolve service name-id from SSO database
    client = await resolve_and_verify_service_from_request(
        request=request,
        client_id_hint=payload.client_id,
    )

    user, err = await authenticate_user(payload.email, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=err or "Invalid credentials",
        )

    # If login originates from a verified service, ensure service is in authorized_apps
    if client:
        if user.authorized_apps is None:
            user.authorized_apps = []
        if client.client_id not in user.authorized_apps:
            user.authorized_apps.append(client.client_id)
            await user.save()

    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    _, raw_token = await create_session(user_id=user.id, ip_address=ip, user_agent=ua)
    _set_session_cookie(response, raw_token)

    return UserResponse.from_user(user)


@router.post("/logout")
async def logout(
    response: Response,
    session: Optional[BrowserSession] = Depends(get_optional_session),
):
    """Revoke active browser session and clear session cookie."""
    if session:
        await revoke_session(session.id)
    _clear_session_cookie(response)
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(require_session_user)):
    """Return currently authenticated user profile."""
    return UserResponse.from_user(user)


@router.post("/forgot-password", dependencies=[Depends(rate_limit_forgot_password)])
async def forgot_password(payload: ForgotPasswordRequest):
    """Initiate password reset.

    Always returns a generic success message to prevent user enumeration attacks.
    """
    res = await create_password_reset_token(payload.email)
    if res:
        user, token = res
        await send_password_reset_email(user.email, token)
    return {"message": "If an account with that email exists, password reset instructions have been sent."}


@router.post("/reset-password", dependencies=[Depends(rate_limit_forgot_password)])
async def reset_password(payload: ResetPasswordRequest):
    """Reset password using received token."""
    success, msg = await reset_password_with_token(payload.token, payload.new_password)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    return {"message": msg}


@router.post("/verify-email")
async def verify_email(payload: VerifyEmailRequest):
    """Confirm email address with token."""
    success, msg = await verify_email_with_token(payload.token)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    return {"message": msg}


@router.post("/resend-verification", dependencies=[Depends(rate_limit_forgot_password)])
async def resend_verification(payload: ResendVerificationRequest):
    """Resend email verification link.

    Always returns a generic message to prevent email enumeration attacks.
    """
    success, token = await resend_email_verification(payload.email)
    if success and token:
        await send_verification_email(payload.email, token)
    return {"message": "If an unverified account with that email exists, a verification link has been sent."}


class GoogleLoginRequest(BaseModel):
    id_token: Optional[str] = None
    access_token: Optional[str] = None
    client_id: Optional[str] = None
    app: Optional[str] = None
    authorized_apps: Optional[List[str]] = None


@router.post("/google", response_model=UserResponse, dependencies=[Depends(rate_limit_login)])
async def login_google(
    payload: GoogleLoginRequest,
    request: Request,
    response: Response,
):
    """Authenticate or register user via Google ID Token or Access Token for first-party clients."""
    if not payload.id_token and not payload.access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either id_token or access_token must be provided",
        )

    # Enforce origin security and resolve service name-id from SSO database
    client = await resolve_and_verify_service_from_request(
        request=request,
        client_id_hint=payload.client_id or payload.app,
    )
    assigned_app = client.client_id if client else None

    google_payload = None
    if payload.id_token:
        google_payload = await verify_google_id_token(payload.id_token)
    elif payload.access_token:
        google_payload = await verify_google_access_token(payload.access_token)

    if not google_payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or unverified Google token",
        )

    email = google_payload.get("email")
    google_sub = str(google_payload.get("sub") or google_payload.get("user_id") or "")
    name = google_payload.get("name") or (email.split("@")[0] if email else "Veylor User")
    picture = google_payload.get("picture")

    try:
        user = await get_or_create_google_user(
            email=email,
            google_sub=google_sub,
            name=name,
            avatar_url=picture,
            authorized_apps=payload.authorized_apps,
            app=assigned_app,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if user.disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account has been disabled.")

    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    _, raw_token = await create_session(user_id=user.id, ip_address=ip, user_agent=ua)
    _set_session_cookie(response, raw_token)

    return UserResponse.from_user(user)

