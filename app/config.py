"""Configuration management using Pydantic Settings."""

from functools import lru_cache
from typing import List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application & Environment
    PROJECT_NAME: str = "Veylor SSO"
    VERSION: str = "0.1.0"
    SSO_ENV: str = Field(default="development", description="development, production, or test")
    SSO_ISSUER: str = Field(
        default="http://localhost:8000",
        description="Public issuer URL (e.g. https://sso.veylor.dev in production). Never hardcoded elsewhere.",
    )
    SECRET_KEY: str = Field(
        default="dev_insecure_secret_key_please_change_in_production_32chars",
        description="Secret key for cookie signing / CSRF / internal token HMAC",
    )

    # Database
    MONGODB_URL: str = Field(default="mongodb://localhost:27017")
    MONGODB_DATABASE: str = Field(default="veylor_sso")

    # Redis
    REDIS_URL: Optional[str] = Field(default="redis://localhost:6379/0")

    # Session Management
    SESSION_COOKIE_NAME: str = Field(default="veylor_session")
    SESSION_TTL_SECONDS: int = Field(default=2592000)  # 30 days
    SESSION_COOKIE_SECURE: bool = Field(default=False)  # set True in production
    SESSION_COOKIE_SAMESITE: str = Field(default="lax")  # "lax", "strict", "none"
    SESSION_COOKIE_DOMAIN: Optional[str] = None

    # OAuth 2.0 & OIDC
    ACCESS_TOKEN_TTL_SECONDS: int = Field(default=3600)  # 1 hour
    AUTHORIZATION_CODE_TTL_SECONDS: int = Field(default=60)  # 60 seconds (short-lived)
    ID_TOKEN_TTL_SECONDS: int = Field(default=3600)  # 1 hour
    SIGNING_KEY_PATH: str = Field(default="keys/private_key.pem")
    SIGNING_KEY_ID: str = Field(default="veylor-sso-key-1")

    # Security & CORS
    CORS_ORIGINS: Union[List[str], str] = Field(
        default=[
            "http://localhost:3000",
            "http://localhost:8000",
            "https://sso.veylor.dev",
            "https://egarageapp.uk",
        ]
    )

    # Admin API
    ADMIN_API_KEY: str = Field(default="veylor_admin_secret_dev_change_me")
    ADMIN_EMAILS: Union[List[str], str] = Field(
        default=["csigorek@gmail.com"]
    )

    # Google OAuth2
    GOOGLE_CLIENT_ID: str = Field(
        default="555399944627-qptrrs4eq4j6qqmao5lgpt6r47vhnpd8.apps.googleusercontent.com"
    )
    GOOGLE_CLIENT_IDS: Union[List[str], str] = Field(default_factory=list)
    GOOGLE_CLIENT_SECRET: Optional[str] = None

    # SMTP / Mailpit (dev defaults)
    SMTP_HOST: str = Field(default="localhost")
    SMTP_PORT: int = Field(default=1025)
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = Field(default=False)
    SMTP_STARTTLS: bool = Field(default=True)
    SMTP_FROM_EMAIL: str = Field(default="contact@veylor.dev")
    SMTP_FROM_NAME: str = Field(default="Veylor Systems")

    # Password Reset & Email Verification Token TTLs
    PASSWORD_RESET_TTL_SECONDS: int = Field(default=1800)  # 30 minutes
    EMAIL_VERIFICATION_TTL_SECONDS: int = Field(default=86400)  # 24 hours

    # Rate Limiting (requests per minute)
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 15
    RATE_LIMIT_AUTH_CODE_PER_MINUTE: int = 30
    RATE_LIMIT_TOKEN_PER_MINUTE: int = 60

    @field_validator("CORS_ORIGINS")
    @classmethod
    def assemble_cors_origins(cls, v: Union[List[str], str]) -> List[str]:
        if isinstance(v, str):
            clean = v.strip()
            if clean.startswith("[") and clean.endswith("]"):
                try:
                    import json
                    parsed = json.loads(clean)
                    if isinstance(parsed, list):
                        return [str(i).strip() for i in parsed if str(i).strip()]
                except Exception:
                    pass
            return [i.strip() for i in clean.split(",") if i.strip()]
        elif isinstance(v, (list, tuple)):
            return [str(i).strip() for i in v if str(i).strip()]
        return []

    @field_validator("ADMIN_EMAILS")
    @classmethod
    def assemble_admin_emails(cls, v: Union[List[str], str]) -> List[str]:
        if isinstance(v, str):
            clean = v.strip()
            if clean.startswith("[") and clean.endswith("]"):
                try:
                    import json
                    parsed = json.loads(clean)
                    if isinstance(parsed, list):
                        return [str(i).strip().lower() for i in parsed if str(i).strip()]
                except Exception:
                    pass
            return [i.strip().lower() for i in clean.split(",") if i.strip()]
        elif isinstance(v, (list, tuple)):
            return [str(i).strip().lower() for i in v if str(i).strip()]
        return []

    @field_validator("GOOGLE_CLIENT_IDS")
    @classmethod
    def assemble_google_client_ids(cls, v: Union[List[str], str]) -> List[str]:
        if isinstance(v, str):
            clean = v.strip()
            if clean.startswith("[") and clean.endswith("]"):
                try:
                    import json
                    parsed = json.loads(clean)
                    if isinstance(parsed, list):
                        return [str(i).strip() for i in parsed if str(i).strip()]
                except Exception:
                    pass
            return [i.strip() for i in clean.split(",") if i.strip()]
        elif isinstance(v, (list, tuple)):
            return [str(i).strip() for i in v if str(i).strip()]
        return []

    def get_allowed_google_client_ids(self) -> List[str]:
        ids = list(self.GOOGLE_CLIENT_IDS)
        if self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_ID not in ids:
            ids.append(self.GOOGLE_CLIENT_ID)
        return ids

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
