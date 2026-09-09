"""Main FastAPI application entrypoint for Veylor SSO."""

import logging
import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api import account_router, auth_router, admin_router, oauth_router, web_router
from app.config import get_settings
from app.database import close_db, init_db

import contextvars

request_id_ctx = contextvars.ContextVar("request_id", default="-")


class RequestIdFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, "request_id"):
            record.request_id = request_id_ctx.get()
        return super().format(record)


handler = logging.StreamHandler()
handler.setFormatter(
    RequestIdFormatter("%(asctime)s [%(levelname)s] %(name)s (req_id=%(request_id)s): %(message)s")
)
logging.root.handlers = [handler]
logging.root.setLevel(logging.INFO)
logger = logging.getLogger("veylor.sso")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Veylor SSO service...")
    await init_db()
    yield
    # Shutdown
    logger.info("Shutting down Veylor SSO service...")
    await close_db()


settings = get_settings()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Central Identity & OpenID Connect Provider for Veylor Ecosystem",
    lifespan=lifespan,
    docs_url="/docs" if settings.SSO_ENV != "production" else None,
    redoc_url="/redoc" if settings.SSO_ENV != "production" else None,
)

# 1. CORS Configuration (Explicit origins only, never wildcard with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Type", "Authorization"],
)


# 2. Security Headers & Request ID Logging Middleware
@app.middleware("http")
async def security_and_logging_middleware(request: Request, call_next):
    # Assign unique request ID
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    token = request_id_ctx.set(request_id)

    start_time = time.time()

    try:
        response: Response = await call_next(request)
    except Exception as exc:
        duration_ms = (time.time() - start_time) * 1000
        logger.error(
            "Unhandled server error at %s %s (took %.2fms): %s",
            request.method,
            request.url.path,
            duration_ms,
            str(exc),
            exc_info=settings.SSO_ENV != "production",
        )
        response = JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "server_error", "detail": "An internal server error occurred."},
        )
    finally:
        request_id_ctx.reset(token)

    duration_ms = (time.time() - start_time) * 1000

    # Strict security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Request-ID"] = request_id

    # Safe structured request logging (never log request bodies/tokens)
    if not request.url.path.startswith("/static"):
        logger.info(
            "%s %s -> status=%d latency=%.2fms",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            extra={"request_id": request_id},
        )

    return response


# 3. Include Routers
app.include_router(oauth_router)  # /.well-known/*, /authorize, /token, /userinfo
app.include_router(auth_router)   # /api/auth/*
app.include_router(account_router) # /api/account/*
app.include_router(admin_router)  # /api/admin/clients/*
app.include_router(web_router)    # /login, /register, /consent, /account, etc.


@app.get("/", include_in_schema=False)
async def root(request: Request):
    """Root redirect to account or login based on active session."""
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if cookie_token:
        return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for container orchestrators and monitoring."""
    return {"status": "ok", "service": "veylor-sso", "version": settings.VERSION}
