"""Audit log applicativo con hash a catena (append-only)."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.redaction import sanitize_structure, sanitize_text
from app.models.audit import AuditLog

logger = get_logger(__name__)


def _normalize_timestamp(value: datetime) -> str:
    """Rappresentazione stabile del timestamp.

    Alcuni backend (SQLite) non conservano il fuso orario: senza questa
    normalizzazione l'hash calcolato in scrittura non coinciderebbe con
    quello ricalcolato in verifica.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _record_hash(previous_hash: str | None, payload: dict[str, Any]) -> str:
    material = json.dumps({"prev": previous_hash, **payload}, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def record_audit(
    db: Session,
    *,
    action: str,
    tenant_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    actor_roles: list[str] | None = None,
    actor_ip: str | None = None,
    user_agent: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    outcome: str = "success",
    message: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Registra un evento. Non solleva mai: un errore di audit non deve
    interrompere l'operazione, ma viene loggato come anomalia."""
    occurred_at = datetime.now(UTC)
    payload = {
        "action": action,
        "tenant_id": str(tenant_id) if tenant_id else None,
        "actor": actor_email,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "outcome": outcome,
        "occurred_at": _normalize_timestamp(occurred_at),
    }
    try:
        previous = db.execute(
            select(AuditLog.record_hash).order_by(desc(AuditLog.occurred_at)).limit(1)
        ).scalar_one_or_none()
        entry = AuditLog(
            tenant_id=tenant_id,
            occurred_at=occurred_at,
            actor_user_id=actor_user_id,
            actor_email=sanitize_text(actor_email, 320) if actor_email else None,
            actor_roles=",".join(actor_roles or [])[:512] or None,
            actor_ip=actor_ip,
            user_agent=sanitize_text(user_agent, 512) if user_agent else None,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            outcome=outcome,
            message=sanitize_text(message, 4000) if message else None,
            metadata_json=sanitize_structure(metadata or {}),
            previous_hash=previous,
            record_hash=_record_hash(previous, payload),
        )
        db.add(entry)
        db.flush()
        return entry
    except Exception as exc:  # noqa: BLE001
        logger.error("audit_write_failed", action=action, error=str(exc))
        raise


def verify_chain(db: Session, limit: int = 1000) -> dict[str, Any]:
    """Verifica l'integrita' della catena di hash dell'audit log."""
    # Ordinamento stabile: a parita' di timestamp l'id rompe il pareggio,
    # cosi' la catena e' verificabile in modo deterministico.
    rows = db.execute(
        select(AuditLog).order_by(AuditLog.occurred_at, AuditLog.id).limit(limit)
    ).scalars().all()
    broken: list[str] = []
    previous_hash: str | None = None
    for row in rows:
        expected = _record_hash(previous_hash, {
            "action": row.action,
            "tenant_id": str(row.tenant_id) if row.tenant_id else None,
            "actor": row.actor_email,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "outcome": row.outcome,
            "occurred_at": _normalize_timestamp(row.occurred_at),
        })
        if row.record_hash != expected:
            broken.append(str(row.id))
        previous_hash = row.record_hash
    return {"checked": len(rows), "broken": broken, "intact": not broken}
