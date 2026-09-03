"""Base declarativa, tipi portabili e mixin comuni."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON


def utcnow() -> datetime:
    return datetime.now(UTC)


class GUID(TypeDecorator):
    """UUID portabile: nativo su PostgreSQL, CHAR(36) altrove (test SQLite)."""

    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PGUUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, uuid.UUID):
            value = uuid.UUID(str(value))
        return value if dialect.name == "postgresql" else str(value)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


JSONType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONType, list[Any]: JSONType}


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)


class TenantScopedMixin:
    """Ogni record del dominio porta il proprio `tenant_id` (sezione 10)."""

    @staticmethod
    def _tenant_fk() -> Mapped[uuid.UUID]:
        return mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"),
                             nullable=False, index=True)


def tenant_column() -> Mapped[uuid.UUID]:
    return mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"),
                         nullable=False, index=True)


def tenant_index(table_name: str, *columns: str) -> Index:
    return Index(f"ix_{table_name}_tenant_{'_'.join(columns)}", "tenant_id", *columns)
