"""Entita' organizzative: tenant, aziende, utenti, ruoli, connettori."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import GUID, Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, tenant_column
from app.models.enums import ConnectorStatus, RoleName

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", GUID(), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", GUID(), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Cliente della piattaforma (es. AD Consulting/Defenix o un MSSP)."""

    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    contact_email: Mapped[str | None] = mapped_column(String(320))
    settings_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)

    companies: Mapped[list["Company"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    users: Mapped[list["User"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class Company(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Organizzazione valutata (ragione sociale)."""

    __tablename__ = "companies"
    __table_args__ = (UniqueConstraint("tenant_id", "slug", name="uq_company_tenant_slug"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    legal_name: Mapped[str] = mapped_column(String(512), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    vat_number: Mapped[str | None] = mapped_column(String(64))
    country: Mapped[str | None] = mapped_column(String(2))
    sector: Mapped[str | None] = mapped_column(String(128))
    size_band: Mapped[str | None] = mapped_column(String(32))
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    next_scan_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    tenant: Mapped[Tenant] = relationship(back_populates="companies")
    domains: Mapped[list["Domain"]] = relationship(back_populates="company", cascade="all, delete-orphan")  # noqa: F821
    scans: Mapped[list["Scan"]] = relationship(back_populates="company", cascade="all, delete-orphan")  # noqa: F821


class Role(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Ruolo RBAC. I nomi corrispondono ai ruoli dell'identity provider OIDC."""

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    permissions_json: Mapped[list | None] = mapped_column(JSONType, default=list)

    users: Mapped[list["User"]] = relationship(secondary=user_roles, back_populates="roles")

    @property
    def role_enum(self) -> RoleName | None:
        try:
            return RoleName(self.name)
        except ValueError:
            return None


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Utente. Con `auth_mode=oidc` l'autenticazione e' delegata a Keycloak e
    `hashed_password` resta nullo: il record locale conserva solo il mapping."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255))
    external_subject: Mapped[str | None] = mapped_column(String(255), index=True)
    hashed_password: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Restrizione opzionale a un sottoinsieme di aziende (es. Customer Viewer).
    company_scope_json: Mapped[list | None] = mapped_column(JSONType, default=list)

    tenant: Mapped[Tenant] = relationship(back_populates="users")
    roles: Mapped[list[Role]] = relationship(secondary=user_roles, back_populates="users", lazy="selectin")

    @property
    def role_names(self) -> list[str]:
        return [role.name for role in self.roles]


class Connector(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Integrazione esterna configurata (SpiderFoot, HIBP, Ransomware.live...)."""

    __tablename__ = "connectors"
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_connector_tenant_key"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=ConnectorStatus.DISABLED.value, nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(512))
    requires_api_key: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_commercial: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_open_source: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    license_note: Mapped[str | None] = mapped_column(Text)
    rate_limit_per_minute: Mapped[int | None] = mapped_column(Integer)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    config_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)


class APIKeyReference(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Riferimento a un segreto: NON contiene mai il valore della chiave.

    Il valore risiede nel secret manager (variabile d'ambiente, Vault, ecc.);
    qui si conservano solo metadati per rotazione e audit.
    """

    __tablename__ = "api_key_references"
    __table_args__ = (UniqueConstraint("tenant_id", "connector_key", "label",
                                       name="uq_apikey_tenant_connector_label"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    connector_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    secret_backend: Mapped[str] = mapped_column(String(32), default="env", nullable=False)
    secret_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    fingerprint: Mapped[str | None] = mapped_column(String(64))  # SHA-256 troncato, per rotazione
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotation_interval_days: Mapped[int | None] = mapped_column(Integer, default=180)


class RetentionPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Policy di conservazione per categoria di dato (sezione 19)."""

    __tablename__ = "retention_policies"
    __table_args__ = (UniqueConstraint("tenant_id", "data_category", name="uq_retention_tenant_category"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    data_category: Mapped[str] = mapped_column(String(64), nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    hard_delete: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    anonymize_instead: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    legal_basis: Mapped[str | None] = mapped_column(Text)
    last_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TenantBranding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Personalizzazione dei report e dell'interfaccia per un tenant.

    Il logo e' conservato nel database e non su disco: il container API gira
    con filesystem in sola lettura, e un file su volume andrebbe replicato e
    messo in backup separatamente rispetto ai dati che descrive.
    """

    __tablename__ = "tenant_branding"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True)

    brand_name: Mapped[str | None] = mapped_column(String(128))
    brand_owner: Mapped[str | None] = mapped_column(String(255))
    primary_color: Mapped[str | None] = mapped_column(String(9))
    # Testi liberi inseriti nei report: sanificati alla scrittura, mai
    # interpretati come markup nei template (autoescape di Jinja2).
    report_intro_it: Mapped[str | None] = mapped_column(Text)
    report_footer_it: Mapped[str | None] = mapped_column(Text)
    contact_block_it: Mapped[str | None] = mapped_column(Text)

    logo_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    logo_mime: Mapped[str | None] = mapped_column(String(64))
    logo_filename: Mapped[str | None] = mapped_column(String(255))

    tenant: Mapped[Tenant] = relationship()
