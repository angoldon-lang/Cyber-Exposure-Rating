"""Schemi Pydantic condivisi."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int = 1
    page_size: int = 50

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.page_size))


class Message(BaseModel):
    message: str
    detail: str | None = None


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
    request_id: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database: str
    redis: str
    # Numero di worker che rispondono al ping. Senza worker attivi le scansioni
    # restano in coda a tempo indeterminato pur essendo state accodate: database
    # e broker da soli non bastano a dire che la piattaforma e' operativa.
    workers: int
    scan_mock_mode: bool
    checked_at: datetime


class AuditEntry(ORMModel):
    id: uuid.UUID
    occurred_at: datetime
    actor_email: str | None
    actor_roles: str | None
    action: str
    entity_type: str | None
    entity_id: str | None
    outcome: str
    message: str | None
    metadata_json: dict[str, Any] | None = Field(default=None, alias="metadata_json")
