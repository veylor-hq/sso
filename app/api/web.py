"""Server-rendered web authentication UI routes using Jinja2 templates."""

import urllib.parse
from typing import Optional
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.dependencies.auth import get_optional_user, require_session_user
from app.models.user import User
from app.security.csrf import CSRF_COOKIE_NAME, generate_csrf_token, verify_csrf_token
from app.security.rate_limit import get_client_ip
from app.services.authentication import (
    authenticate_user,
    create_email_verification_token,
    create_password_reset_token,
    reset_password_with_token,
    verify_email_with_token,
)
from app.services.email import send_password_reset_email, send_verification_email
from app.services.oauth import (
    OAuthError,
    create_authorization_code,
    get_client_by_id,
    validate_authorize_request,
)
from app.services.sessions import create_session, list_user_sessions, revoke_session
from app.services.users import create_user

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory="app/templates")


def _render_with_csrf(
    request: Request,
    template_name: str,
    context: dict,
    response_status: int = 200,
) -> HTMLResponse:
    """Helper to inject CSRF token into template and set CSRF cookie if not present."""
    csrf_token = request.cookies.get(CSRF_COOKIE_NAME) or generate_csrf_token()
    context["request"] = request
    context["csrf_token"] = csrf_token
    context["settings"] = get_settings()

    resp = templates.TemplateResponse(
        request=request,
        name=template_name,
        context=context,
        status_code=response_status,
    )
    if CSRF_COOKIE_NAME not in request.cookies:
        settings = get_settings()
        resp.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            httponly=True,
            secure=settings.SESSION_COOKIE_SECURE,
            samesite="lax",
            path="/",
        )
    return resp


def _set_auth_cookie(response: Response, raw_token: str) -> None:
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


def _clear_auth_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        domain=settings.SESSION_COOKIE_DOMAIN,
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


# ---------------------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    return_to: Optional[str] = None,
    user: Optional[User] = Depends(get_optional_user),
):
    if user:
        if return_to and return_to.startswith("/"):
            return RedirectResponse(url=return_to, status_code=status.HTTP_302_FOUND)
        return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)

    return _render_with_csrf(request, "login.html", {"return_to": return_to or ""})


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    return_to: Optional[str] = Form(default=None),
    csrf_token: Optional[str] = Form(default=None),
):
    if not verify_csrf_token(request, csrf_token):
        return _render_with_csrf(
            request,
            "login.html",
            {"error": "Security token mismatch. Please try again.", "email": email, "return_to": return_to or ""},
            response_status=400,
        )

    user, err = await authenticate_user(email, password)
    if not user:
        return _render_with_csrf(
            request,
            "login.html",
            {"error": err or "Invalid email or password.", "email": email, "return_to": return_to or ""},
            response_status=401,
        )

    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    _, raw_token = await create_session(user_id=user.id, ip_address=ip, user_agent=ua)

    target_url = "/account"
    if return_to and return_to.startswith("/"):
        target_url = return_to

    response = RedirectResponse(url=target_url, status_code=status.HTTP_302_FOUND)
    _set_auth_cookie(response, raw_token)
    return response


# ---------------------------------------------------------------------------
# REGISTER
# ---------------------------------------------------------------------------
@router.get("/register", response_class=HTMLResponse)
async def register_page(
    request: Request,
    return_to: Optional[str] = None,
    user: Optional[User] = Depends(get_optional_user),
):
    if user:
        return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)
    return _render_with_csrf(request, "register.html", {"return_to": return_to or ""})


@router.post("/register")
async def register_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    return_to: Optional[str] = Form(default=None),
    csrf_token: Optional[str] = Form(default=None),
):
    if not verify_csrf_token(request, csrf_token):
        return _render_with_csrf(
            request,
            "register.html",
            {"error": "Security token mismatch. Please try again.", "name": name, "email": email, "return_to": return_to or ""},
            response_status=400,
        )

    if password != confirm_password:
        return _render_with_csrf(
            request,
            "register.html",
            {"error": "Passwords do not match.", "name": name, "email": email, "return_to": return_to or ""},
            response_status=400,
        )

    try:
        user = await create_user(
            email=email,
            password=password,
            name=name,
        )
    except ValueError as e:
        return _render_with_csrf(
            request,
            "register.html",
            {"error": str(e), "name": name, "email": email, "return_to": return_to or ""},
            response_status=400,
        )

    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent")
    _, raw_token = await create_session(user_id=user.id, ip_address=ip, user_agent=ua)

    # Deliver verification email
    token = await create_email_verification_token(user.id)
    await send_verification_email(user.email, token)

    target_url = "/account"
    if return_to and return_to.startswith("/"):
        target_url = return_to

    response = RedirectResponse(url=target_url, status_code=status.HTTP_302_FOUND)
    _set_auth_cookie(response, raw_token)
    return response


# ---------------------------------------------------------------------------
# CONSENT
# ---------------------------------------------------------------------------
@router.get("/consent", response_class=HTMLResponse)
async def consent_page(
    request: Request,
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(...),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query(default="S256"),
    state: Optional[str] = Query(default=None),
    nonce: Optional[str] = Query(default=None),
    user: Optional[User] = Depends(get_optional_user),
):
    if not user:
        return RedirectResponse(
            url=f"/login?return_to={urllib.parse.quote(str(request.url.query))}",
            status_code=status.HTTP_302_FOUND,
        )

    client = await get_client_by_id(client_id)
    if not client or client.disabled:
        raise HTTPException(status_code=400, detail="Invalid client")

    scopes = [s.strip() for s in scope.split() if s.strip()]

    return _render_with_csrf(
        request,
        "consent.html",
        {
            "user": user,
            "client": client,
            "scopes": scopes,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state or "",
            "nonce": nonce or "",
        },
    )


@router.post("/consent")
async def consent_submit(
    request: Request,
    action: str = Form(...),  # "allow" or "deny"
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(default="S256"),
    state: Optional[str] = Form(default=None),
    nonce: Optional[str] = Form(default=None),
    csrf_token: Optional[str] = Form(default=None),
    user: User = Depends(require_session_user),
):
    if not verify_csrf_token(request, csrf_token):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    client = await get_client_by_id(client_id)
    if not client or redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid client or redirect URI")

    separator = "&" if "?" in redirect_uri else "?"
    if action == "deny":
        params = {"error": "access_denied", "error_description": "The user denied access."}
        if state:
            params["state"] = state
        return RedirectResponse(
            url=f"{redirect_uri}{separator}{urllib.parse.urlencode(params)}",
            status_code=status.HTTP_302_FOUND,
        )

    # Action is "allow"
    scopes = [s.strip() for s in scope.split() if s.strip()]
    raw_code = await create_authorization_code(
        user_id=user.id,
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
    )

    params = {"code": raw_code}
    if state:
        params["state"] = state

    return RedirectResponse(
        url=f"{redirect_uri}{separator}{urllib.parse.urlencode(params)}",
        status_code=status.HTTP_302_FOUND,
    )


# ---------------------------------------------------------------------------
# ACCOUNT
# ---------------------------------------------------------------------------
@router.get("/account", response_class=HTMLResponse)
async def account_page(
    request: Request,
    user: User = Depends(require_session_user),
):
    sessions = await list_user_sessions(user.id)
    return _render_with_csrf(
        request,
        "account.html",
        {
            "user": user,
            "sessions": sessions,
        },
    )


@router.post("/account/logout")
async def account_logout(
    request: Request,
    csrf_token: Optional[str] = Form(default=None),
    user: User = Depends(require_session_user),
):
    if not verify_csrf_token(request, csrf_token):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    from app.dependencies.auth import get_optional_session
    session = await get_optional_session(request)
    if session:
        await revoke_session(session.id)

    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    _clear_auth_cookie(response)
    return response


@router.post("/account/sessions/{session_id}/revoke")
async def revoke_session_action(
    request: Request,
    session_id: str,
    csrf_token: Optional[str] = Form(default=None),
    user: User = Depends(require_session_user),
):
    if not verify_csrf_token(request, csrf_token):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    await revoke_session(session_id=session_id, user_id=user.id)
    return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)


# ---------------------------------------------------------------------------
# FORGOT / RESET PASSWORD / VERIFY EMAIL
# ---------------------------------------------------------------------------
@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return _render_with_csrf(request, "forgot_password.html", {})


@router.post("/forgot-password")
async def forgot_password_submit(
    request: Request,
    email: str = Form(...),
    csrf_token: Optional[str] = Form(default=None),
):
    if not verify_csrf_token(request, csrf_token):
        return _render_with_csrf(request, "forgot_password.html", {"error": "Invalid CSRF token"}, 400)

    res = await create_password_reset_token(email)
    if res:
        u, token = res
        await send_password_reset_email(u.email, token)

    return _render_with_csrf(
        request,
        "forgot_password.html",
        {"success": "If an account with that email exists, password reset instructions have been sent."},
    )


@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str = Query(...)):
    return _render_with_csrf(request, "reset_password.html", {"token": token})


@router.post("/reset-password")
async def reset_password_submit(
    request: Request,
    token: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: Optional[str] = Form(default=None),
):
    if not verify_csrf_token(request, csrf_token):
        return _render_with_csrf(request, "reset_password.html", {"token": token, "error": "Invalid CSRF token"}, 400)

    if password != confirm_password:
        return _render_with_csrf(
            request,
            "reset_password.html",
            {"token": token, "error": "Passwords do not match."},
            400,
        )

    success, msg = await reset_password_with_token(token, password)
    if not success:
        return _render_with_csrf(request, "reset_password.html", {"token": token, "error": msg}, 400)

    return _render_with_csrf(request, "reset_password.html", {"success": msg})


@router.get("/verify-email", response_class=HTMLResponse)
async def verify_email_page(request: Request, token: str = Query(...)):
    success, msg = await verify_email_with_token(token)
    return _render_with_csrf(request, "verify_email.html", {"success": success, "message": msg})
