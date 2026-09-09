"""Test fixtures and database configuration for Veylor SSO."""

import os
import pytest
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

# Set test environment before importing application
os.environ["SSO_ENV"] = "test"
os.environ["SSO_ISSUER"] = "http://testserver"
os.environ["SIGNING_KEY_PATH"] = "keys/test_private_key.pem"
os.environ["REDIS_URL"] = ""  # Force in-memory fallback in tests
os.environ["ADMIN_API_KEY"] = "test_admin_secret_key"

from app.config import get_settings
from app.database import close_db, init_db
from app.main import app
from app.security.jwt import get_key_manager


@pytest.fixture(autouse=True)
async def setup_test_db():
    """Spin up an in-memory MongoDB client via mongomock-motor for each test."""
    mock_client = AsyncMongoMockClient()
    await init_db(client=mock_client, database_name="veylor_sso_test")
    # Load keys
    km = get_key_manager()
    km.load_or_generate_keys()

    yield

    await close_db()


@pytest.fixture
async def client():
    """Async HTTP client targeting the FastAPI test ASGI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
