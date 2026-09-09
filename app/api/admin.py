"""Protected administrative API for managing OAuth clients."""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from app.dependencies.auth import require_admin_key
from app.models.oauth_client import OAuthClient

router = APIRouter(
    prefix="/api/admin/clients",
    tags=["Admin - OAuth Clients"],
    dependencies=[Depends(require_admin_key)],
)


class CreateClientRequest(BaseModel):
    client_id: str = Field(..., min_length=2, max_length=50)
    client_name: str = Field(..., min_length=2, max_length=100)
    client_type: str = Field(default="public")
    redirect_uris: List[str] = Field(..., min_length=1)
    allowed_scopes: List[str] = Field(default=["openid", "profile", "email"])
    trusted: bool = Field(default=False)


class UpdateClientRequest(BaseModel):
    client_name: Optional[str] = None
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
    created_at: str
    updated_at: str

    @classmethod
    def from_model(cls, client: OAuthClient) -> "ClientResponse":
        return cls(
            client_id=client.client_id,
            client_name=client.client_name,
            client_type=client.client_type,
            redirect_uris=client.redirect_uris,
            allowed_scopes=client.allowed_scopes,
            trusted=client.trusted,
            disabled=client.disabled,
            created_at=client.created_at.isoformat(),
            updated_at=client.updated_at.isoformat(),
        )


@router.get("", response_model=List[ClientResponse])
async def list_clients():
    """List all registered OAuth clients."""
    clients = await OAuthClient.find_all().to_list()
    return [ClientResponse.from_model(c) for c in clients]


@router.post("", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
async def create_client(payload: CreateClientRequest):
    """Register a new OAuth client."""
    existing = await OAuthClient.find_one(OAuthClient.client_id == payload.client_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Client '{payload.client_id}' already exists.",
        )

    now = datetime.now(timezone.utc)
    client = OAuthClient(
        client_id=payload.client_id,
        client_name=payload.client_name,
        client_type=payload.client_type,
        redirect_uris=payload.redirect_uris,
        allowed_scopes=payload.allowed_scopes,
        trusted=payload.trusted,
        disabled=False,
        created_at=now,
        updated_at=now,
    )
    await client.insert()
    return ClientResponse.from_model(client)


@router.get("/{client_id}", response_model=ClientResponse)
async def get_client(client_id: str):
    """Retrieve details for a specific OAuth client."""
    client = await OAuthClient.find_one(OAuthClient.client_id == client_id)
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    return ClientResponse.from_model(client)


@router.patch("/{client_id}", response_model=ClientResponse)
async def update_client(client_id: str, payload: UpdateClientRequest):
    """Update OAuth client attributes."""
    client = await OAuthClient.find_one(OAuthClient.client_id == client_id)
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    if payload.client_name is not None:
        client.client_name = payload.client_name
    if payload.redirect_uris is not None:
        client.redirect_uris = payload.redirect_uris
    if payload.allowed_scopes is not None:
        client.allowed_scopes = payload.allowed_scopes
    if payload.trusted is not None:
        client.trusted = payload.trusted
    if payload.disabled is not None:
        client.disabled = payload.disabled

    client.updated_at = datetime.now(timezone.utc)
    await client.save()
    return ClientResponse.from_model(client)
