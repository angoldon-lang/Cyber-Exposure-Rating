"""Valori di configurazione degli strumenti, impostati dall'interfaccia."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import GUID, Base, UUIDPrimaryKeyMixin


class ToolSetting(UUIDPrimaryKeyMixin, Base):
    """Una variabile di configurazione, con il valore cifrato.

    Il valore non viene mai restituito dall'API: la schermata mostra soltanto
    se una variabile e' impostata, chi l'ha toccata e quando. Chi ha bisogno
    di rileggere una chiave la sostituisce.
    """

    __tablename__ = "tool_settings"

    variable: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    value_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"))
