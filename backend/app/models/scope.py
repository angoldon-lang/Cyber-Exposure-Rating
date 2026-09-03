"""Perimetro, autorizzazioni e asset."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import GUID, Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, tenant_column
from app.models.enums import (
    AssetRelationshipType,
    AssetType,
    AuthorizationStatus,
    OwnershipStatus,
    ScopeAction,
    ScopeEntryType,
    VerificationStatus,
)


class Authorization(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Autorizzazione formale a eseguire controlli attivi (sezione 4).

    Nessun profilo verificato puo' partire senza una Authorization attiva,
    non scaduta e con il profilo richiesto tra quelli concessi.
    """

    __tablename__ = "authorizations"

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)

    status: Mapped[str] = mapped_column(String(32), default=AuthorizationStatus.DRAFT.value, nullable=False)
    granting_subject_name: Mapped[str] = mapped_column(String(255), nullable=False)
    granting_subject_role: Mapped[str | None] = mapped_column(String(255))
    granting_subject_email: Mapped[str | None] = mapped_column(String(320))
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(Text)

    allowed_profiles_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    exclusions_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    document_reference: Mapped[str | None] = mapped_column(String(512))
    document_hash: Mapped[str | None] = mapped_column(String(128))
    notes: Mapped[str | None] = mapped_column(Text)

    scopes: Mapped[list["Scope"]] = relationship(back_populates="authorization", cascade="all, delete-orphan")

    def is_valid_at(self, moment: datetime) -> bool:
        if self.status != AuthorizationStatus.ACTIVE.value:
            return False
        if self.revoked_at is not None:
            return False
        return self.valid_from <= moment <= self.expires_at


class Scope(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Voce di perimetro (include/exclude) legata a un'autorizzazione."""

    __tablename__ = "scopes"

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("authorizations.id", ondelete="CASCADE"), index=True)

    entry_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(16), default=ScopeAction.INCLUDE.value, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)

    authorization: Mapped[Authorization | None] = relationship(back_populates="scopes")


class Domain(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Dominio Internet dell'azienda, con stato di verifica della proprieta'."""

    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("tenant_id", "company_id", "name", name="uq_domain_tenant_company_name"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_status: Mapped[str] = mapped_column(
        String(32), default=VerificationStatus.UNVERIFIED.value, nullable=False)
    verification_method: Mapped[str | None] = mapped_column(String(32))
    verification_token: Mapped[str | None] = mapped_column(String(128))
    verification_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_by_user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"))
    verification_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_verification_error: Mapped[str | None] = mapped_column(Text)

    registrar: Mapped[str | None] = mapped_column(String(255))
    registry_expiry_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dnssec_enabled: Mapped[bool | None] = mapped_column(Boolean)

    company: Mapped["Company"] = relationship(back_populates="domains")  # noqa: F821

    @property
    def is_verified(self) -> bool:
        return self.verification_status == VerificationStatus.VERIFIED.value


class EmailDomain(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Dominio usato per la posta, con il risultato dei controlli SPF/DKIM/DMARC."""

    __tablename__ = "email_domains"
    __table_args__ = (UniqueConstraint("tenant_id", "company_id", "name", name="uq_emaildomain_tenant_company_name"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    domain_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("domains.id", ondelete="CASCADE"))

    name: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    provider_detected: Mapped[str | None] = mapped_column(String(128))
    provider_confidence: Mapped[str | None] = mapped_column(String(32))  # detected | probable
    secure_email_gateway: Mapped[str | None] = mapped_column(String(128))
    dkim_selectors_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    posture_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)


class IPAddress(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ip_addresses"
    __table_args__ = (UniqueConstraint("tenant_id", "company_id", "address", name="uq_ip_tenant_company_address"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)

    address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    ownership_status: Mapped[str] = mapped_column(
        String(32), default=OwnershipStatus.UNVERIFIED.value, nullable=False)
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("authorizations.id", ondelete="SET NULL"))
    asn: Mapped[int | None] = mapped_column(Integer)
    asn_org: Mapped[str | None] = mapped_column(String(255))
    is_cdn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_shared_hosting: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cloud_provider: Mapped[str | None] = mapped_column(String(64))
    reverse_dns: Mapped[str | None] = mapped_column(String(253))


class NetworkRange(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "network_ranges"
    __table_args__ = (UniqueConstraint("tenant_id", "company_id", "cidr", name="uq_netrange_tenant_company_cidr"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)

    cidr: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(255))
    ownership_status: Mapped[str] = mapped_column(
        String(32), default=OwnershipStatus.UNVERIFIED.value, nullable=False)
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("authorizations.id", ondelete="SET NULL"))
    asn: Mapped[int | None] = mapped_column(Integer)
    max_hosts_allowed: Mapped[int | None] = mapped_column(Integer)


class Brand(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "brands"
    __table_args__ = (UniqueConstraint("tenant_id", "company_id", "name", name="uq_brand_tenant_company_name"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    keywords_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    monitor_lookalikes: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Asset osservato. `asset_key` e' l'identita' stabile usata per il diff
    fra scansioni e per la deduplicazione delle evidenze."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("tenant_id", "company_id", "asset_key", name="uq_asset_tenant_company_key"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)

    asset_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    ownership_status: Mapped[str] = mapped_column(
        String(32), default=OwnershipStatus.UNVERIFIED.value, nullable=False, index=True)
    ownership_reason: Mapped[str | None] = mapped_column(Text)
    ownership_confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_cdn_fronted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_third_party_hosted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    excluded_from_rating: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exclusion_reason: Mapped[str | None] = mapped_column(Text)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    disappeared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    technologies_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    attributes_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)
    discovered_by_json: Mapped[list | None] = mapped_column(JSONType, default=list)

    def scores_toward_rating(self) -> bool:
        if self.excluded_from_rating:
            return False
        return self.ownership_status in {
            OwnershipStatus.VERIFIED_OWNED.value,
            OwnershipStatus.LIKELY_OWNED.value,
        }


class AssetRelationship(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source_asset_id", "target_asset_id", "relationship_type",
                         name="uq_assetrel_unique"),
    )

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    source_tool: Mapped[str | None] = mapped_column(String(64))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


__all__ = [
    "Asset", "AssetRelationship", "AssetRelationshipType", "AssetType", "Authorization",
    "Brand", "Domain", "EmailDomain", "IPAddress", "NetworkRange", "Scope",
    "ScopeEntryType", "ScopeAction",
]
