"""Schemi per tenant, aziende, utenti e connettori."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.common import ORMModel

SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str = Field(pattern=SLUG_PATTERN)
    contact_email: EmailStr | None = None


class TenantRead(ORMModel):
    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    contact_email: str | None
    created_at: datetime


class CompanyCreate(BaseModel):
    legal_name: str = Field(min_length=2, max_length=512)
    slug: str = Field(pattern=SLUG_PATTERN)
    vat_number: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    sector: str | None = Field(default=None, max_length=128)
    size_band: str | None = Field(default=None, max_length=32)
    notes: str | None = None

    @field_validator("country")
    @classmethod
    def _upper(cls, value: str | None) -> str | None:
        return value.upper() if value else value


class CompanyUpdate(BaseModel):
    legal_name: str | None = Field(default=None, min_length=2, max_length=512)
    vat_number: str | None = None
    country: str | None = None
    sector: str | None = None
    size_band: str | None = None
    notes: str | None = None
    is_active: bool | None = None


class CompanyRead(ORMModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    legal_name: str
    slug: str
    vat_number: str | None
    country: str | None
    sector: str | None
    # Esposti perche' sono modificabili da `CompanyUpdate`: senza, la scheda
    # anagrafica non potrebbe mostrare i valori correnti prima di scriverli.
    size_band: str | None
    notes: str | None
    is_active: bool
    next_scan_due_at: datetime | None
    created_at: datetime


class UserRead(ORMModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    full_name: str | None
    is_active: bool
    mfa_enabled: bool
    last_login_at: datetime | None


class UserProfile(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    full_name: str | None
    roles: list[str]
    permissions: list[str]


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    profile: UserProfile


class ConnectorRead(ORMModel):
    id: uuid.UUID
    key: str
    display_name: str
    status: str
    requires_api_key: bool
    is_commercial: bool
    is_open_source: bool
    license_note: str | None
    last_check_at: datetime | None
    last_error: str | None


class CompanyPurge(BaseModel):
    """Conferma della cancellazione definitiva.

    Lo slug va ridigitato: una richiesta costruita per sbaglio (o un click di
    troppo) non deve poter cancellare i dati di un'azienda sbagliata.
    """

    confirm_slug: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=512)


class CompanyPurgeResult(BaseModel):
    company_id: uuid.UUID
    slug: str
    deleted_rows: dict[str, int]
    total_rows: int


class BrandingRead(ORMModel):
    brand_name: str | None
    brand_owner: str | None
    primary_color: str | None
    report_intro_it: str | None
    report_footer_it: str | None
    contact_block_it: str | None
    has_logo: bool = False
    logo_filename: str | None = None


class BrandingUpdate(BaseModel):
    brand_name: str | None = Field(default=None, max_length=128)
    brand_owner: str | None = Field(default=None, max_length=255)
    # Solo notazione esadecimale: il valore finisce in un attributo `style` dei
    # report, e un colore arbitrario permetterebbe di iniettare altre proprieta'.
    primary_color: str | None = Field(default=None, pattern=r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
    report_intro_it: str | None = Field(default=None, max_length=4000)
    report_footer_it: str | None = Field(default=None, max_length=4000)
    contact_block_it: str | None = Field(default=None, max_length=2000)
