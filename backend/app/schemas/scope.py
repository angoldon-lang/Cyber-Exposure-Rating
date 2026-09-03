"""Schemi per domini, autorizzazioni, perimetro e asset."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.enums import ScanProfileType, ScopeAction, ScopeEntryType, VerificationMethod
from app.schemas.common import ORMModel
from app.services.scope_guard import ScopeViolation, normalize_hostname


class DomainCreate(BaseModel):
    name: str = Field(min_length=3, max_length=253)
    is_primary: bool = False

    @field_validator("name")
    @classmethod
    def _valid_hostname(cls, value: str) -> str:
        try:
            return normalize_hostname(value)
        except ScopeViolation as exc:
            raise ValueError(exc.reason) from exc


class DomainRead(ORMModel):
    id: uuid.UUID
    company_id: uuid.UUID
    name: str
    is_primary: bool
    verification_status: str
    verification_method: str | None
    verified_at: datetime | None
    registrar: str | None
    registry_expiry_date: datetime | None
    dnssec_enabled: bool | None


class VerificationStart(BaseModel):
    method: VerificationMethod


class VerificationChallengeRead(BaseModel):
    domain: str
    method: str
    expires_at: datetime
    instructions_it: str
    record_name: str | None = None
    record_value: str | None = None
    file_url: str | None = None
    file_content: str | None = None


class VerificationSubmit(BaseModel):
    """Per `admin_email` il codice ricevuto; per gli altri metodi non serve."""

    token: str | None = Field(default=None, max_length=256)


class VerificationResult(BaseModel):
    verified: bool
    status: str
    method: str
    detail_it: str
    checked_at: datetime


class ManualApproval(BaseModel):
    approver_name: str = Field(min_length=2, max_length=255)
    document_reference: str = Field(min_length=2, max_length=512)
    notes: str | None = None


class ScopeEntryCreate(BaseModel):
    entry_type: ScopeEntryType
    value: str = Field(min_length=1, max_length=512)
    action: ScopeAction = ScopeAction.INCLUDE
    note: str | None = None

    @field_validator("value")
    @classmethod
    def _validate(cls, value: str, info) -> str:  # noqa: ANN001
        entry_type = info.data.get("entry_type")
        value = value.strip()
        if entry_type in {ScopeEntryType.IP_ADDRESS, ScopeEntryType.CIDR}:
            try:
                if entry_type == ScopeEntryType.CIDR:
                    network = ipaddress.ip_network(value, strict=False)
                    if network.num_addresses > 65536:
                        raise ValueError("la rete autorizzata non puo' superare /16 (65536 indirizzi)")
                else:
                    ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"valore di rete non valido: {exc}") from exc
            return value
        if entry_type in {ScopeEntryType.DOMAIN, ScopeEntryType.EMAIL_DOMAIN}:
            try:
                return normalize_hostname(value)
            except ScopeViolation as exc:
                raise ValueError(exc.reason) from exc
        if entry_type == ScopeEntryType.WILDCARD_DOMAIN:
            try:
                return f"*.{normalize_hostname(value.removeprefix('*.'))}"
            except ScopeViolation as exc:
                raise ValueError(exc.reason) from exc
        return value


class ScopeEntryRead(ORMModel):
    id: uuid.UUID
    entry_type: str
    value: str
    action: str
    is_active: bool
    note: str | None


class AuthorizationCreate(BaseModel):
    granting_subject_name: str = Field(min_length=2, max_length=255)
    granting_subject_role: str | None = Field(default=None, max_length=255)
    granting_subject_email: EmailStr | None = None
    valid_from: datetime
    expires_at: datetime
    allowed_profiles: list[ScanProfileType] = Field(min_length=1)
    exclusions: list[str] = Field(default_factory=list)
    document_reference: str | None = Field(default=None, max_length=512)
    notes: str | None = None
    scopes: list[ScopeEntryCreate] = Field(default_factory=list)

    @field_validator("expires_at")
    @classmethod
    def _after_start(cls, value: datetime, info) -> datetime:  # noqa: ANN001
        start = info.data.get("valid_from")
        if start and value <= start:
            raise ValueError("la data di scadenza deve essere successiva alla data di inizio")
        return value


class AuthorizationRead(ORMModel):
    id: uuid.UUID
    company_id: uuid.UUID
    status: str
    granting_subject_name: str
    granting_subject_role: str | None
    granted_at: datetime
    valid_from: datetime
    expires_at: datetime
    revoked_at: datetime | None
    allowed_profiles_json: list | None
    document_reference: str | None


class AuthorizationRevoke(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class AssetRead(ORMModel):
    id: uuid.UUID
    asset_key: str
    asset_type: str
    display_name: str
    ownership_status: str
    ownership_reason: str | None
    is_internet_facing: bool
    is_cdn_fronted: bool
    excluded_from_rating: bool
    first_seen_at: datetime
    last_seen_at: datetime
    disappeared_at: datetime | None
    technologies_json: list | None
