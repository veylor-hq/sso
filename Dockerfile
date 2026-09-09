FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install poetry or install directly via pip
COPY pyproject.toml ./
RUN pip install --upgrade pip setuptools wheel && \
    pip install \
    "fastapi>=0.115.0" \
    "uvicorn[standard]>=0.30.0" \
    "beanie>=1.26.0" \
    "motor>=3.6.0" \
    "pydantic>=2.8.0" \
    "pydantic-settings>=2.4.0" \
    "redis>=5.0.0" \
    "argon2-cffi>=23.1.0" \
    "cryptography>=43.0.0" \
    "pyjwt[crypto]>=2.9.0" \
    "jinja2>=3.1.4" \
    "python-multipart>=0.0.9" \
    "aiosmtplib>=3.0.0" \
    "ulid-py>=1.1.0" \
    "httpx>=0.27.0" \
    "email-validator>=2.2.0"

# Copy application source
COPY app/ ./app/
COPY keys/ ./keys/ 2>/dev/null || true

# Create non-root user
RUN useradd -m -u 1000 veylor && \
    mkdir -p /app/keys && \
    chown -R veylor:veylor /app

USER veylor

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
