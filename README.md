# Veylor SSO

**Veylor SSO** is the central identity and authentication service for the Veylor ecosystem, powering applications such as **eGarage**, **Veylor Relay**, **Veylor Pager**, and **Veylor Warden**.

It is a standards-compliant **OAuth 2.0** and **OpenID Connect (OIDC)** Provider implementing Authorization Code Flow with **PKCE (S256)**, server-side browser sessions for seamless Single Sign-On, asymmetric RS256 key rotation (JWKS), and a minimalist server-rendered authentication UI.

---

## Key Architectural Principles

1. **OAuth 2.0 & OpenID Connect Standards**: Conventional HTTP REST-style endpoints. No custom protocol, no GraphQL.
2. **Mandatory PKCE with S256**: No implicit flow, no resource owner password credentials grant.
3. **Exact Redirect URI Matching**: Strictly rejects wildcard or unlisted callback URLs to eliminate open redirects.
4. **Short-Lived, Single-Use Authorization Codes**: 60-second lifetime, stored hashed (SHA-256), marked used immediately upon exchange to detect and prevent replay attacks.
5. **Secure Browser Sessions (True SSO)**: Cryptographically random session tokens stored hashed in MongoDB. When an authenticated user opens eGarage and is redirected to `/authorize`, Veylor SSO identifies the existing session and completes the authorization without requiring the user to re-enter their password.
6. **Immutable User Identifier (`sub`)**: User IDs are opaque, immutable ULID identifiers (`usr_01JXXXXXXXXXXXX`). Email is never used as the OIDC `sub` claim.
7. **Argon2id Password Hashing**: State-of-the-art password hashing using `argon2-cffi` with RFC 9106 recommended parameters.
8. **Asymmetric Cryptography (JWKS)**: ID tokens and access tokens are signed using RS256 with key ID (`kid`). Public keys are exposed under `/.well-known/jwks.json`.

---

## Architecture & Project Structure

```
.
├── Dockerfile                  # Production-ready Python 3.12 container definition
├── docker-compose.yml          # Complete stack: SSO, MongoDB, Redis, Mailpit
├── pyproject.toml              # Poetry dependencies & project metadata
├── .env.example                # Template configuration file
├── app/
│   ├── main.py                 # FastAPI application, middleware, structured logging
│   ├── config.py               # Pydantic Settings configuration
│   ├── database.py             # Motor + Beanie ODM initialization and seed data
│   ├── models/                 # Beanie document models
│   │   ├── user.py             # User model with immutable 'usr_01J...' sub
│   │   ├── session.py          # Server-side browser session (hashed tokens)
│   │   ├── oauth_client.py     # OAuth client registry
│   │   ├── authorization_code.py # Short-lived auth codes with replay protection
│   │   ├── signing_key.py      # RSA public keys for JWKS
│   │   └── token_records.py    # Password reset & email verification tokens
│   ├── security/               # Security primitives
│   │   ├── passwords.py        # Argon2id hashing and verification
│   │   ├── jwt.py              # RS256 token issuance and JWKS generation
│   │   ├── pkce.py             # RFC 7636 PKCE S256 verifier & challenge
│   │   ├── random.py           # Opaque IDs and token hashing
│   │   ├── csrf.py             # CSRF protection for HTML forms
│   │   └── rate_limit.py       # Sliding-window rate limiting (Redis/memory)
│   ├── services/               # Business services
│   │   ├── authentication.py   # User authentication, resets, verifications
│   │   ├── sessions.py         # Browser session lifecycle
│   │   ├── oauth.py            # Authorization request validation & code exchange
│   │   ├── tokens.py           # OIDC ID tokens & access tokens
│   │   ├── users.py            # User identity management
│   │   └── email.py            # Transactional emails (Mailpit/SMTP)
│   ├── dependencies/           # FastAPI dependency injection
│   │   ├── auth.py             # Session and Bearer token dependencies
│   │   └── rate_limit.py       # Route rate limit guards
│   ├── api/                    # HTTP REST routers
│   │   ├── auth.py             # /api/auth/* (register, login, logout, me)
│   │   ├── oauth.py            # /.well-known/*, /authorize, /token, /userinfo
│   │   ├── account.py          # /api/account/* (profile, active sessions)
│   │   ├── admin.py            # /api/admin/clients/* (OAuth client management)
│   │   └── web.py              # Server-rendered Jinja2 UI routes
│   └── templates/              # Server-rendered authentication UI
│       ├── base.html           # Minimalist dark Veylor layout
│       ├── login.html          # Sign-in page
│       ├── register.html       # Account creation page
│       ├── consent.html        # Interactive OAuth consent screen
│       ├── account.html        # User account & active sessions overview
│       ├── forgot_password.html# Password recovery request
│       ├── reset_password.html # New password form
│       └── verify_email.html   # Email confirmation page
├── tests/                      # Pytest automated test suite
└── examples/
    └── egarage_client.py       # Complete Python/FastAPI client integration example
```

---

## Getting Started

### Prerequisites
- Docker and Docker Compose (v2.0+)
- Or Python 3.12+ with Poetry / pip

---

### Running with Docker Compose (Recommended)

Start the entire local environment (Veylor SSO, MongoDB, Redis, and Mailpit) with a single command:

```bash
docker compose up --build -d
```

Verify services are up:
```bash
docker compose ps
```

Services will be available at:
- **Veylor SSO Web UI & API**: [http://localhost:8000](http://localhost:8000)
- **OIDC Discovery**: [http://localhost:8000/.well-known/openid-configuration](http://localhost:8000/.well-known/openid-configuration)
- **JWKS Endpoint**: [http://localhost:8000/.well-known/jwks.json](http://localhost:8000/.well-known/jwks.json)
- **Mailpit Web UI** (captured emails): [http://localhost:8025](http://localhost:8025)
- **MongoDB**: `localhost:27017`
- **Redis**: `localhost:6379`

To view container logs:
```bash
docker compose logs -f sso
```

To stop the services:
```bash
docker compose down
```

---

### Running Locally without Docker

1. **Configure Environment**:
   ```bash
   cp .env.example .env
   ```

2. **Install Dependencies**:
   ```bash
   pip install poetry
   poetry install
   ```
   Or using pip in a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```

3. **Start MongoDB and Redis** (e.g. via local installation or lightweight docker containers):
   ```bash
   docker run -d --name mongo -p 27017:27017 mongo:7.0
   docker run -d --name redis -p 6379:6379 redis:7-alpine
   ```

4. **Run the Application**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

---

## Running Automated Tests

Run the test suite with `pytest`:

```bash
pytest -v
```

The test suite thoroughly verifies:
- User registration, case-insensitive duplicate email rejection, and Argon2id hashing
- Login with valid/invalid credentials and disabled account rejection
- Session creation, expiration, and revocation
- OpenID Connect discovery and JWKS structure
- Authorization Code Flow with PKCE (S256)
- Negative security cases:
  - Unknown client rejection
  - Disabled client rejection
  - Invalid redirect URI matching (strict exact matching)
  - Invalid requested scopes
  - Missing PKCE or insecure `plain` PKCE method
  - Authorization code replay detection (single-use guarantee)
  - Code exchange by wrong client or wrong redirect URI
  - Incorrect PKCE code verifier
- Cryptographic ID token verification:
  - Valid RS256 signature
  - Tampered/forged signature rejection
  - Mismatched issuer rejection
  - Mismatched audience rejection
  - Expired token rejection
- UserInfo endpoint token validation and immutable `sub` claim matching
- CSRF protection and security response headers

---

## Testing the SSO Experience

### Step 1: Create a Veylor Account
1. Open [http://localhost:8000/register](http://localhost:8000/register) in your browser.
2. Enter your name, email (e.g. `mechanic@egarage.uk`), and password.
3. Submit the form. You are signed in and redirected to your `/account` dashboard.
4. Open Mailpit at [http://localhost:8025](http://localhost:8025) to see the welcome verification email.

### Step 2: Test eGarage Integration
Run the included integration script:

```bash
python examples/egarage_client.py
```

Notice the generated authorization URL:
```
http://localhost:8000/authorize?response_type=code&client_id=egarage&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback&scope=openid+profile+email&state=...&nonce=...&code_challenge=...&code_challenge_method=S256
```

If you open this URL in the browser where you are signed into Veylor SSO:
1. Because eGarage is a trusted first-party client (`trusted=True`), Veylor SSO automatically issues the authorization code.
2. The browser is immediately redirected to `http://localhost:3000/auth/callback?code=...&state=...` **without asking for your password again**.
3. That is the core Single Sign-On experience.

---

## Managing OAuth Clients (Admin API)

OAuth clients are managed via the REST API using the configured `ADMIN_API_KEY`:

### List Clients
```bash
curl -H "X-Admin-API-Key: veylor_admin_secret_dev_change_me" \
     http://localhost:8000/api/admin/clients
```

### Register a New Client
```bash
curl -X POST http://localhost:8000/api/admin/clients \
     -H "Content-Type: application/json" \
     -H "X-Admin-API-Key: veylor_admin_secret_dev_change_me" \
     -d '{
       "client_id": "custom-app",
       "client_name": "Custom App",
       "client_type": "public",
       "redirect_uris": ["https://custom.veylor.dev/callback"],
       "allowed_scopes": ["openid", "profile", "email"],
       "trusted": false
     }'
```

---

## Production Deployment Checklist

1. Set `SSO_ENV=production`.
2. Set `SSO_ISSUER=https://sso.veylor.dev`.
3. Set `SESSION_COOKIE_SECURE=true` (requires HTTPS).
4. Set a strong `SECRET_KEY` (minimum 32 random characters).
5. Set a strong `ADMIN_API_KEY`.
6. Mount or inject persistent RSA signing keys via `SIGNING_KEY_PATH`.
7. Configure production SMTP credentials.
8. Ensure database and Redis are secured behind VPC firewalls with auth enabled.
