"""Schemi per domini, autorizzazioni, perimetro e asset."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, computed_field, field_validator

from app.models.enums import ScanProfileType, ScopeAction, ScopeEntryType, VerificationMethod
from app.schemas.common import ORMModel
from app.services.ip_perimeter import indirizzo_pubblico
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
        if entry_type == ScopeEntryType.EMAIL_ADDRESS:
            locale, _, dominio = value.partition("@")
            if not locale or not dominio:
                raise ValueError("indirizzo e-mail non valido: manca la chiocciola")
            try:
                return f"{locale.lower()}@{normalize_hostname(dominio)}"
            except ScopeViolation as exc:
                raise ValueError(f"dominio dell'indirizzo non valido: {exc.reason}") from exc
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


class IPAddressCreate(BaseModel):
    """Indirizzo IP da inserire nel perimetro.

    `authorized` traduce la decisione dell'analista: un indirizzo autorizzato
    diventa bersaglio ammissibile per la scansione attiva, uno non autorizzato
    resta soltanto inventario. Il valore predefinito e' la non autorizzazione:
    sondare un indirizzo e' un'azione che va scelta, non subita.
    """

    address: str = Field(min_length=2, max_length=45)
    authorized: bool = False
    note: str | None = Field(default=None, max_length=255)

    @field_validator("address")
    @classmethod
    def _pubblico(cls, value: str) -> str:
        value = value.strip()
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"indirizzo IP non valido: {exc}") from exc
        # La definizione di «pubblico» e' quella del ScopeGuard: accettare qui
        # un indirizzo che li' verrebbe rifiutato produrrebbe un perimetro che
        # non si puo' scansionare, senza che nulla lo spieghi.
        if not indirizzo_pubblico(value):
            raise ValueError("un indirizzo privato, di loopback, riservato o non "
                             "instradabile su Internet non e' esposizione esterna "
                             "e non puo' entrare nel perimetro")
        return str(ip)


class IPAddressRead(ORMModel):
    id: uuid.UUID
    address: str
    version: int
    ownership_status: str
    asn: int | None
    asn_org: str | None
    is_cdn: bool
    is_shared_hosting: bool
    cloud_provider: str | None
    reverse_dns: str | None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authorized(self) -> bool:
        """Autorizzato alla scansione attiva.

        L'autorizzazione non e' un campo a se': e' lo stato di proprieta'
        accertata, lo stesso che il ScopeGuard legge per ammettere un
        bersaglio. Duplicarlo in una colonna separata creerebbe due verita'
        che possono divergere.
        """
        return self.ownership_status == "verified_owned"


class IPAuthorizationUpdate(BaseModel):
    authorized: bool


class NetworkRangeCreate(BaseModel):
    cidr: str = Field(min_length=4, max_length=64)
    description: str | None = Field(default=None, max_length=255)
    authorized: bool = False

    @field_validator("cidr")
    @classmethod
    def _valida(cls, value: str) -> str:
        try:
            rete = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"rete non valida: {exc}") from exc
        if rete.num_addresses > 65536:
            raise ValueError("la rete autorizzata non puo' superare /16 (65536 indirizzi)")
        if not indirizzo_pubblico(str(rete.network_address)):
            raise ValueError("una rete privata o non instradabile su Internet non e' "
                             "esposizione esterna")
        return str(rete)


class NetworkRangeRead(ORMModel):
    id: uuid.UUID
    cidr: str
    description: str | None
    ownership_status: str
    asn: int | None


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
    ownership_confidence: float
    is_internet_facing: bool
    is_cdn_fronted: bool
    is_third_party_hosted: bool
    excluded_from_rating: bool
    exclusion_reason: str | None
    from_mock_scan: bool
    first_seen_at: datetime
    last_seen_at: datetime
    disappeared_at: datetime | None
    technologies_json: list | None
    # Senza questi due campi l'inventario dice *cosa* e' stato trovato ma non
    # *come*: un asset non verificabile e' un asset di cui non ci si puo'
    # fidare, e la fonte e' la prima cosa che un analista controlla.
    attributes_json: dict | None
    discovered_by_json: list | None


class AssetSummary(BaseModel):
    """Conteggi dell'inventario, indipendenti dalla pagina mostrata.

    Derivarli dagli elementi della pagina corrente darebbe numeri diversi a
    ogni filtro e a ogni scorrimento: sarebbero conteggi della vista, non
    dell'inventario.
    """

    total: int
    disappeared: int
    synthetic: int
    by_type: dict[str, int]
    by_ownership: dict[str, int]
    by_tool: dict[str, int]
