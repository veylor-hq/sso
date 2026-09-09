"""API and View routers for Veylor SSO."""

from app.api.auth import router as auth_router
from app.api.oauth import router as oauth_router
from app.api.account import router as account_router
from app.api.admin import router as admin_router
from app.api.web import router as web_router
from app.api.web_admin import router as web_admin_router

__all__ = [
    "auth_router",
    "oauth_router",
    "account_router",
    "admin_router",
    "web_router",
    "web_admin_router",
]
