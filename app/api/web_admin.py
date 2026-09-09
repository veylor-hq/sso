"""Server-rendered Administrative Web UI routes."""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.api.admin import get_system_insights
from app.config import get_settings
from app.models.oauth_client import OAuthClient
from app.models.session import BrowserSession
from app.models.user import User
from app.security.csrf import CSRF_COOKIE_NAME, generate_csrf_token, verify_csrf_token
from app.security.random import constant_time_compare
from app.services.sessions import get_session_by_token
from app.services.users import get_user_by_id

router = APIRouter(prefix="/admin", include_in_schema=False)
templates = Jinja2Templates(directory="app/templates")

ADMIN_COOKIE_NAME = "veylor_admin_key"


async def check_admin_access(request: Request):
    """Verify admin access via master key cookie or active admin user session."""
    settings = get_settings()

    # 1. Master admin key cookie
    admin_key_cookie = request.cookies.get(ADMIN_COOKIE_NAME)
    if admin_key_cookie and constant_time_compare(admin_key_cookie, settings.ADMIN_API_KEY):
        return True, None

    # 2. Session-based user check
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_token:
        session = await get_session_by_token(session_token)
        if session:
            user = await get_user_by_id(session.user_id)
            if user and not user.disabled:
                admin_emails = [e.lower() for e in settings.ADMIN_EMAILS]
                if user.is_admin or user.email.lower() in admin_emails:
                    return True, user

    return False, None


def _render_admin(
    request: Request,
    template_name: str,
    context: dict,
    response_status: int = 200,
) -> HTMLResponse:
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
    if not request.cookies.get(CSRF_COOKIE_NAME):
        resp.set_cookie(CSRF_COOKIE_NAME, csrf_token, httponly=True, samesite="lax")
    return resp


@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, error: Optional[str] = None):
    is_admin, user = await check_admin_access(request)
    if is_admin:
        return RedirectResponse(url="/admin/insights", status_code=status.HTTP_302_FOUND)

    return _render_admin(request, "admin/login.html", {"error": error})


@router.post("/login")
async def admin_login_submit(
    request: Request,
    admin_key: str = Form(...),
):
    settings = get_settings()
    if not constant_time_compare(admin_key.strip(), settings.ADMIN_API_KEY):
        return _render_admin(
            request,
            "admin/login.html",
            {"error": "Invalid administrative passkey. Access denied."},
            response_status=401,
        )

    response = RedirectResponse(url="/admin/insights", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=ADMIN_COOKIE_NAME,
        value=settings.ADMIN_API_KEY,
        max_age=86400,  # 24 hours
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/admin",
    )
    return response


@router.get("/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key=ADMIN_COOKIE_NAME, path="/admin")
    return response


@router.get("", response_class=HTMLResponse)
async def admin_root(request: Request):
    is_admin, _ = await check_admin_access(request)
    if not is_admin:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/admin/insights", status_code=status.HTTP_302_FOUND)


@router.get("/insights", response_class=HTMLResponse)
async def admin_insights_page(request: Request):
    is_admin, admin_user = await check_admin_access(request)
    if not is_admin:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)

    insights = await get_system_insights()
    return _render_admin(
        request,
        "admin/insights.html",
        {
            "active_tab": "insights",
            "admin_user": admin_user,
            "insights": insights,
        },
    )


@router.get("/clients", response_class=HTMLResponse)
async def admin_clients_page(request: Request):
    is_admin, admin_user = await check_admin_access(request)
    if not is_admin:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)

    clients = await OAuthClient.find_all().sort("-created_at").to_list()
    clients_data = [
        {
            "client_id": c.client_id,
            "client_name": c.client_name,
            "client_type": c.client_type,
            "redirect_uris": c.redirect_uris,
            "allowed_scopes": c.allowed_scopes,
            "trusted": c.trusted,
            "disabled": c.disabled,
            "has_secret": bool(c.client_secret_hash),
        }
        for c in clients
    ]

    return _render_admin(
        request,
        "admin/clients.html",
        {
            "active_tab": "clients",
            "admin_user": admin_user,
            "clients": clients_data,
        },
    )


@router.get("/users", response_class=HTMLResponse)
async def admin_users_page(
    request: Request,
    search: Optional[str] = Query(None),
    app: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
):
    is_admin, admin_user = await check_admin_access(request)
    if not is_admin:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)

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

    total_users = await User.count()
    users = await User.find(criteria).sort("-created_at").limit(100).to_list()

    users_data = [
        {
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "email_verified": u.email_verified,
            "auth_provider": u.auth_provider,
            "is_admin": u.is_admin,
            "authorized_apps": u.authorized_apps or [],
            "disabled": u.disabled,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]

    return _render_admin(
        request,
        "admin/users.html",
        {
            "active_tab": "users",
            "admin_user": admin_user,
            "users": users_data,
            "total_users": total_users,
            "search": search,
            "current_app": app,
            "provider": provider,
        },
    )


@router.get("/sessions", response_class=HTMLResponse)
async def admin_sessions_page(request: Request):
    is_admin, admin_user = await check_admin_access(request)
    if not is_admin:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)

    sessions = await BrowserSession.find(BrowserSession.revoked_at == None).sort("-last_seen_at").limit(50).to_list()
    sessions_data = []
    for s in sessions:
        user = await User.find_one(User.id == s.user_id)
        sessions_data.append({
            "session_id": s.id,
            "user_id": s.user_id,
            "user_email": user.email if user else "unknown",
            "user_name": user.name if user else "Unknown",
            "ip_address": s.ip_address,
            "user_agent": s.user_agent,
            "created_at": s.created_at.isoformat(),
            "last_active_at": s.last_seen_at.isoformat(),
        })

    return _render_admin(
        request,
        "admin/sessions.html",
        {
            "active_tab": "sessions",
            "admin_user": admin_user,
            "sessions": sessions_data,
        },
    )
