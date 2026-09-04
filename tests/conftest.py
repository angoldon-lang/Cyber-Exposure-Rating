"""Fixture condivise.

Nessun test contatta sistemi reali su Internet: si usano esclusivamente
dati sintetici, fixture registrate e un database SQLite in memoria.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

# La configurazione va impostata PRIMA di importare l'applicazione.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SCAN_MOCK_MODE", "true")
os.environ.setdefault("ENABLE_ROW_LEVEL_SECURITY", "false")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production-use")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("EVIDENCE_STORAGE_PATH", "/tmp/defenix-test/evidence")
os.environ.setdefault("REPORT_STORAGE_PATH", "/tmp/defenix-test/reports")


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
@pytest.fixture
def db_session():
    """Sessione su database SQLite in memoria, isolata per test."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.models import Base

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def tenant(db_session):
    from app.models.organization import Tenant

    row = Tenant(name="Tenant di test", slug=f"test-{uuid.uuid4().hex[:8]}")
    db_session.add(row)
    db_session.flush()
    return row


@pytest.fixture
def company(db_session, tenant):
    from app.models.organization import Company

    row = Company(tenant_id=tenant.id, legal_name="ACME Test S.p.A.",
                  slug=f"acme-{uuid.uuid4().hex[:8]}", country="IT")
    db_session.add(row)
    db_session.flush()
    return row


# --------------------------------------------------------------------------
# Motori
# --------------------------------------------------------------------------
@pytest.fixture
def scoring_engine():
    from app.services.scoring import ScoringEngine

    return ScoringEngine()


@pytest.fixture
def confidence_engine():
    from app.services.confidence import ConfidenceEngine

    return ConfidenceEngine()


@pytest.fixture
def make_finding():
    """Costruisce un ScorableFinding con valori predefiniti ragionevoli."""
    from app.services.scoring import ScorableFinding

    counter = {"n": 0}

    def factory(**overrides):
        counter["n"] += 1
        defaults = {
            "finding_id": f"F-{counter['n']:03d}",
            "finding_type": "dmarc_missing",
            "category": "email_dns_security",
            "severity": "high",
            "confidence_class": "confirmed",
            "ownership_status": "verified_owned",
            "asset_key": "mail:acme-test.example",
        }
        defaults.update(overrides)
        return ScorableFinding(**defaults)

    return factory


@pytest.fixture
def scope_guard():
    from app.services.scope_guard import ScopeEntry, ScopeGuard

    return ScopeGuard([
        ScopeEntry("wildcard_domain", "*.acme-test.example"),
        ScopeEntry("domain", "acme-test.example"),
        ScopeEntry("cidr", "203.0.113.0/24"),
        ScopeEntry("wildcard_domain", "*.legacy.acme-test.example", "exclude"),
    ], allow_documentation_ranges=True)


@pytest.fixture
def adapter_context(scope_guard):
    from adapters.base import AdapterContext

    return AdapterContext(
        scan_id="test-scan", tenant_id="test-tenant", company_id="test-company",
        company_name="ACME Test S.p.A.", profile="verified_standard",
        scope_guard=scope_guard, domains=["acme-test.example"],
        verified_domains=["acme-test.example"],
        ip_addresses=["203.0.113.10"], mock_mode=True,
        connector_config={"hibp": {"mock_enabled": True},
                          "synthetic": {"severity_bias": 0.5}})


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def past():
    def factory(days: int) -> datetime:
        return datetime.now(UTC) - timedelta(days=days)

    return factory
