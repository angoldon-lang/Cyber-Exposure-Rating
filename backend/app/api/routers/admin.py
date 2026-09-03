"""Amministrazione: tenant, utenti, connettori, audit log e assets."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, select

from app.api.deps import CompanyDep, CurrentUser, CurrentUserDep, DbDep, require_permission
from app.core.config import load_yaml_config
from app.core.rbac import Permission
from app.models.audit import AuditLog
from app.models.organization import Connector, Tenant
from app.models.scope import Asset
from app.schemas.common import AuditEntry, Page
from app.schemas.organization import ConnectorRead, TenantCreate, TenantRead
from app.schemas.scope import AssetRead
from app.services.audit import verify_chain

router = APIRouter(tags=["admin"])


@router.get("/tenants", response_model=list[TenantRead])
def list_tenants(db: DbDep,
                 _: CurrentUser = Depends(require_permission(Permission.PLATFORM_MANAGE)),
                 ) -> list[TenantRead]:
    rows = db.execute(select(Tenant).order_by(Tenant.name)).scalars().all()
    return [TenantRead.model_validate(r) for r in rows]


@router.post("/tenants", response_model=TenantRead, status_code=status.HTTP_201_CREATED)
def create_tenant(payload: TenantCreate, db: DbDep,
                  _: CurrentUser = Depends(require_permission(Permission.PLATFORM_MANAGE)),
                  ) -> TenantRead:
    if db.execute(select(Tenant).where(Tenant.slug == payload.slug)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, f"Slug «{payload.slug}» gia' in uso")
    tenant = Tenant(**payload.model_dump())
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return TenantRead.model_validate(tenant)


@router.get("/connectors", response_model=list[ConnectorRead])
def list_connectors(db: DbDep,
                    current: CurrentUser = Depends(
                        require_permission(Permission.CONNECTOR_READ))) -> list[ConnectorRead]:
    """Stato dei connettori configurati, con distinzione open source / commerciale."""
    rows = db.execute(
        select(Connector).where(Connector.tenant_id == current.tenant_id)
        .order_by(Connector.display_name)).scalars().all()
    return [ConnectorRead.model_validate(r) for r in rows]


@router.get("/coverage-matrix")
def coverage_matrix(profile: str = "public_passive") -> list[dict]:
    """Matrice di copertura e costi: quali fonti sono gratuite, quali no."""
    from adapters.registry import ProfileNotFoundError, coverage_matrix as build_matrix

    try:
        entries = build_matrix(profile)
    except ProfileNotFoundError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    tools = load_yaml_config("tool_profiles").get("tools", {})
    for entry in entries:
        definition = tools.get(entry["tool"], {})
        entry["license"] = definition.get("license")
        entry["license_risk"] = definition.get("license_risk")
        entry["repository"] = definition.get("repository")
        entry["notes"] = definition.get("notes")
        entry["is_open_source"] = not definition.get("commercial", False)
    return entries


@router.get("/audit", response_model=Page[AuditEntry])
def list_audit(db: DbDep, current: CurrentUser = Depends(require_permission(Permission.AUDIT_READ)),
               action: str | None = None, entity_type: str | None = None,
               page: int = 1, page_size: int = Query(default=100, le=500)) -> Page[AuditEntry]:
    conditions = [AuditLog.tenant_id == current.tenant_id]
    if action:
        conditions.append(AuditLog.action == action)
    if entity_type:
        conditions.append(AuditLog.entity_type == entity_type)
    total = db.execute(select(func.count()).select_from(AuditLog).where(*conditions)).scalar_one()
    rows = db.execute(
        select(AuditLog).where(*conditions).order_by(desc(AuditLog.occurred_at))
        .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return Page[AuditEntry](items=[AuditEntry.model_validate(r) for r in rows],
                            total=total, page=page, page_size=page_size)


@router.get("/audit/integrity")
def audit_integrity(db: DbDep,
                    _: CurrentUser = Depends(require_permission(Permission.AUDIT_READ))) -> dict:
    """Verifica la catena di hash dell'audit log."""
    result = verify_chain(db)
    return {**result, "checked_at": datetime.now(UTC).isoformat()}


@router.get("/companies/{company_id}/assets", response_model=Page[AssetRead])
def list_assets(company: CompanyDep, db: DbDep, asset_type: str | None = None,
                ownership_status: str | None = None, include_disappeared: bool = True,
                page: int = 1, page_size: int = Query(default=100, le=500)) -> Page[AssetRead]:
    conditions = [Asset.company_id == company.id]
    if asset_type:
        conditions.append(Asset.asset_type == asset_type)
    if ownership_status:
        conditions.append(Asset.ownership_status == ownership_status)
    if not include_disappeared:
        conditions.append(Asset.disappeared_at.is_(None))
    total = db.execute(select(func.count()).select_from(Asset).where(*conditions)).scalar_one()
    rows = db.execute(
        select(Asset).where(*conditions).order_by(Asset.asset_type, Asset.asset_key)
        .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return Page[AssetRead](items=[AssetRead.model_validate(r) for r in rows],
                           total=total, page=page, page_size=page_size)


@router.get("/remediation-catalog")
def remediation_catalog() -> list[dict]:
    """Catalogo completo delle remediation disponibili."""
    return load_yaml_config("remediation_catalog").get("remediations", [])
