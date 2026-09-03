"""Sessione database, base declarativa e supporto Row Level Security."""
from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings


def _engine_kwargs() -> dict[str, Any]:
    if settings.database_url.startswith("sqlite"):
        # Usato solo dai test: SQLite non supporta pool_size/RLS.
        return {"connect_args": {"check_same_thread": False}}
    return {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_pre_ping": True,
    }


engine = create_engine(settings.database_url, echo=settings.db_echo, future=True, **_engine_kwargs())

if settings.database_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:  # pragma: no cover
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def get_db() -> Generator[Session, None, None]:
    """Dependency FastAPI: una sessione per richiesta."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Sessione transazionale per worker e script."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def set_tenant_context(db: Session, tenant_id: str | None) -> None:
    """Imposta la GUC usata dalle policy PostgreSQL Row Level Security.

    Difesa in profondita': la segregazione e' garantita anche a livello
    applicativo dai filtri `tenant_id` in `TenantScopedRepository`.
    """
    if not settings.enable_row_level_security:
        return
    if settings.database_url.startswith("sqlite"):
        return
    db.execute(text("SELECT set_config('defenix.tenant_id', :tid, true)"),
               {"tid": str(tenant_id) if tenant_id else ""})
