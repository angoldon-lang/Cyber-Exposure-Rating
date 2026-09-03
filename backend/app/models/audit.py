"""Audit log applicativo (append-only)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import GUID, Base, JSONType, UUIDPrimaryKeyMixin


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """Registro immutabile: nessun UPDATE/DELETE applicativo.

    In PostgreSQL l'immutabilita' e' rafforzata da trigger + revoca dei
    privilegi UPDATE/DELETE al ruolo applicativo (vedi migrazione 0001).
    """

    __tablename__ = "audit_logs"

    tenant_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"))
    actor_email: Mapped[str | None] = mapped_column(String(320))
    actor_roles: Mapped[str | None] = mapped_column(String(512))
    actor_ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success", nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)
    # Hash a catena per rilevare manomissioni sulla sequenza.
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    record_hash: Mapped[str | None] = mapped_column(String(64))
