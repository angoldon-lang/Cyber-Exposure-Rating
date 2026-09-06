"""Amministrazione: tenant, utenti, connettori, audit log e assets."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile, status
from sqlalchemy import desc, func, select

from app.api.deps import (
    CompanyDep,
    CurrentUser,
    CurrentUserDep,
    DbDep,
    RequestContextDep,
    require_permission,
)
from app.core.config import load_yaml_config
from app.core.rbac import Permission
from app.models.audit import AuditLog
from app.core.redaction import mask_email, sanitize_text
from app.models.enums import AuditAction
from app.models.organization import Connector, Tenant, TenantBranding
from app.models.scope import Asset
from app.schemas.common import AuditEntry, Page
from app.schemas.organization import (
    BrandingRead,
    BrandingUpdate,
    ConnectorRead,
    TenantCreate,
    TenantRead,
)
from app.schemas.scope import AssetRead, AssetSummary
from app.services.audit import record_audit, verify_chain

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


@router.get("/tool-status")
def tool_status(current: CurrentUserDep) -> list[dict]:
    """Cosa manca a ciascuno strumento per funzionare.

    Non restituisce segreti: dice quale variabile impostare, se la fonte
    costi qualcosa e dove procurarsi l'eventuale chiave. Il valore delle
    chiavi resta nelle variabili d'ambiente, come per il resto della
    piattaforma.
    """
    from app.services.tool_status import stato_strumenti

    del current  # basta un'utenza autenticata: nessun dato riservato
    return stato_strumenti()


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


def _asset_leggibile(riga: Asset, unmask: bool) -> AssetRead:
    """Converte un asset rispettando il mascheramento dei dati personali.

    `display_name` era gia' mascherato all'origine, ma `asset_key` no: per un
    indirizzo e-mail la chiave e' l'indirizzo in chiaro, ed e' quella che
    l'inventario mostra come identita' dell'asset. Senza questo passaggio la
    lista degli asset restituirebbe l'indirizzo completo a chiunque possa
    leggerla, vanificando il mascheramento applicato ovunque altro.
    """
    lettura = AssetRead.model_validate(riga)
    if riga.asset_type == "email_address" and not unmask:
        lettura = lettura.model_copy(update={"asset_key": mask_email(riga.asset_key)})
    return lettura


@router.get("/companies/{company_id}/assets/summary", response_model=AssetSummary)
def assets_summary(company: CompanyDep, db: DbDep) -> AssetSummary:
    """Composizione dell'inventario: per tipo, per proprieta' e per strumento."""
    righe = db.execute(select(Asset).where(Asset.company_id == company.id)).scalars().all()
    per_tipo: dict[str, int] = {}
    per_proprieta: dict[str, int] = {}
    per_strumento: dict[str, int] = {}
    for riga in righe:
        per_tipo[riga.asset_type] = per_tipo.get(riga.asset_type, 0) + 1
        per_proprieta[riga.ownership_status] = per_proprieta.get(riga.ownership_status, 0) + 1
        for strumento in riga.discovered_by_json or []:
            per_strumento[str(strumento)] = per_strumento.get(str(strumento), 0) + 1
    return AssetSummary(
        total=len(righe),
        disappeared=sum(1 for r in righe if r.disappeared_at is not None),
        synthetic=sum(1 for r in righe if r.from_mock_scan),
        by_type=dict(sorted(per_tipo.items(), key=lambda v: -v[1])),
        by_ownership=dict(sorted(per_proprieta.items(), key=lambda v: -v[1])),
        by_tool=dict(sorted(per_strumento.items(), key=lambda v: -v[1])))


@router.get("/companies/{company_id}/assets", response_model=Page[AssetRead])
def list_assets(company: CompanyDep, db: DbDep, current: CurrentUserDep,
                asset_type: str | None = None, ownership_status: str | None = None,
                include_disappeared: bool = True, include_synthetic: bool = True,
                discovered_by: str | None = None,
                q: str | None = None, page: int = 1,
                page_size: int = Query(default=100, le=500)) -> Page[AssetRead]:
    unmask = current.has(Permission.PII_UNMASK)
    conditions = [Asset.company_id == company.id]
    if asset_type:
        conditions.append(Asset.asset_type == asset_type)
    if ownership_status:
        conditions.append(Asset.ownership_status == ownership_status)
    if not include_disappeared:
        conditions.append(Asset.disappeared_at.is_(None))
    if not include_synthetic:
        conditions.append(Asset.from_mock_scan.is_(False))
    if q:
        # La ricerca corre su `display_name` e non su `asset_key`: per gli
        # indirizzi e-mail la chiave e' in chiaro e il nome mostrato e'
        # mascherato. Cercare sulla chiave permetterebbe di confermare un
        # indirizzo completo a chi non ha il permesso di vederlo.
        termine = f"%{q.strip().lower()}%"
        conditions.append(func.lower(Asset.display_name).like(termine))
    ordinamento = (Asset.asset_type, Asset.asset_key)
    if discovered_by:
        # Lo strumento di scoperta sta in una colonna JSON e il confronto in
        # SQL non e' portabile fra SQLite e PostgreSQL: il filtro resta in
        # Python, e per questo va applicato PRIMA di impaginare. Applicarlo
        # dopo darebbe pagine parzialmente vuote e un totale che non
        # corrisponde a cio' che si vede.
        tutte = db.execute(select(Asset).where(*conditions)
                           .order_by(*ordinamento)).scalars().all()
        filtrate = [r for r in tutte if discovered_by in (r.discovered_by_json or [])]
        inizio = (page - 1) * page_size
        return Page[AssetRead](
            items=[_asset_leggibile(r, unmask) for r in filtrate[inizio:inizio + page_size]],
            total=len(filtrate), page=page, page_size=page_size)

    total = db.execute(select(func.count()).select_from(Asset).where(*conditions)).scalar_one()
    rows = db.execute(
        select(Asset).where(*conditions).order_by(*ordinamento)
        .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return Page[AssetRead](items=[_asset_leggibile(r, unmask) for r in rows],
                           total=total, page=page, page_size=page_size)


@router.get("/remediation-catalog")
def remediation_catalog() -> list[dict]:
    """Catalogo completo delle remediation disponibili."""
    return load_yaml_config("remediation_catalog").get("remediations", [])


# --------------------------------------------------------------------------
# Personalizzazione dei report
# --------------------------------------------------------------------------
# Formati ammessi per il logo. Nessun SVG: e' un documento XML che puo'
# contenere script e riferimenti esterni, e finirebbe dentro report distribuiti
# a terzi.
LOGO_MIME_AMMESSI = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff"}
LOGO_MAX_BYTES = 2 * 1024 * 1024


def _branding(db, tenant_id) -> TenantBranding:  # noqa: ANN001
    riga = db.execute(
        select(TenantBranding).where(TenantBranding.tenant_id == tenant_id)).scalar_one_or_none()
    if riga is None:
        riga = TenantBranding(tenant_id=tenant_id)
        db.add(riga)
        db.flush()
    return riga


def _leggibile(riga: TenantBranding) -> BrandingRead:
    letto = BrandingRead.model_validate(riga)
    letto.has_logo = riga.logo_bytes is not None
    return letto


@router.get("/branding", response_model=BrandingRead)
def get_branding(db: DbDep, current: CurrentUserDep) -> BrandingRead:
    """Personalizzazione del tenant corrente. Valori vuoti = predefiniti."""
    return _leggibile(_branding(db, current.tenant_id))


@router.put("/branding", response_model=BrandingRead)
def update_branding(payload: BrandingUpdate, db: DbDep, context: RequestContextDep,
                    current: CurrentUser = Depends(require_permission(Permission.TENANT_MANAGE)),
                    ) -> BrandingRead:
    riga = _branding(db, current.tenant_id)
    for campo, valore in payload.model_dump(exclude_unset=True).items():
        # I testi liberi finiscono nei report: si sanificano alla scrittura, e
        # i template usano comunque l'autoescape di Jinja2.
        setattr(riga, campo, sanitize_text(valore, 4000) if isinstance(valore, str) else valore)
    record_audit(db, action=AuditAction.UPDATE.value, tenant_id=current.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="tenant_branding", entity_id=str(riga.id),
                 message="personalizzazione aggiornata", **context)
    db.commit()
    db.refresh(riga)
    return _leggibile(riga)


@router.post("/branding/logo", response_model=BrandingRead)
async def upload_logo(db: DbDep, context: RequestContextDep,
                      file: UploadFile = File(...),  # noqa: B008
                      current: CurrentUser = Depends(require_permission(Permission.TENANT_MANAGE)),
                      ) -> BrandingRead:
    """Carica il logo usato nei report.

    Il tipo dichiarato dal client non fa fede: si verifica la firma iniziale
    del file. Un contenuto arbitrario ribattezzato `.png` finirebbe altrimenti
    dentro documenti distribuiti a terzi.
    """
    contenuto = await file.read(LOGO_MAX_BYTES + 1)
    if len(contenuto) > LOGO_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Logo troppo grande: massimo {LOGO_MAX_BYTES // 1024} KB")
    if not contenuto:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File vuoto")

    tipo = next((mime for mime, firma in LOGO_MIME_AMMESSI.items()
                 if contenuto.startswith(firma)), None)
    if tipo is None:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Formato non riconosciuto: sono ammessi PNG e JPEG. "
            "Gli SVG non sono accettati perche' possono contenere script.")

    riga = _branding(db, current.tenant_id)
    riga.logo_bytes = contenuto
    riga.logo_mime = tipo
    riga.logo_filename = sanitize_text(file.filename or "logo", 255)
    record_audit(db, action=AuditAction.UPDATE.value, tenant_id=current.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="tenant_branding", entity_id=str(riga.id),
                 message=f"logo caricato ({tipo}, {len(contenuto)} byte)", **context)
    db.commit()
    db.refresh(riga)
    return _leggibile(riga)


@router.get("/branding/logo")
def get_logo(db: DbDep, current: CurrentUserDep) -> Response:
    riga = db.execute(
        select(TenantBranding).where(
            TenantBranding.tenant_id == current.tenant_id)).scalar_one_or_none()
    if riga is None or riga.logo_bytes is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nessun logo caricato")
    return Response(content=riga.logo_bytes, media_type=riga.logo_mime or "image/png",
                    headers={"Cache-Control": "private, max-age=300"})


@router.delete("/branding/logo", status_code=status.HTTP_204_NO_CONTENT,
               response_model=None, response_class=Response)
def delete_logo(db: DbDep, context: RequestContextDep,
                current: CurrentUser = Depends(require_permission(Permission.TENANT_MANAGE)),
                ) -> None:
    riga = _branding(db, current.tenant_id)
    riga.logo_bytes = None
    riga.logo_mime = None
    riga.logo_filename = None
    record_audit(db, action=AuditAction.UPDATE.value, tenant_id=current.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="tenant_branding", entity_id=str(riga.id),
                 message="logo rimosso", **context)
    db.commit()


@router.delete("/companies/{company_id}/assets/synthetic")
def delete_synthetic_assets(company: CompanyDep, db: DbDep, context: RequestContextDep,
                            current: CurrentUser = Depends(
                                require_permission(Permission.COMPANY_WRITE)),
                            ) -> dict[str, int]:
    """Rimuove gli asset osservati solo in modalita' dimostrativa.

    Servono a provare la piattaforma prima di avere dati reali, e poi
    restano: dopo la prima scansione vera non hanno piu' ragione di stare
    nell'inventario. Gli asset osservati anche da una scansione reale non
    sono toccati, perche' la marcatura viene azzerata alla prima osservazione
    reale.
    """
    righe = db.execute(
        select(Asset).where(Asset.company_id == company.id,
                            Asset.from_mock_scan.is_(True))).scalars().all()
    for riga in righe:
        db.delete(riga)
    record_audit(db, action=AuditAction.DELETE.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="asset", entity_id=str(company.id),
                 message=f"rimossi {len(righe)} asset osservati solo in modalita' dimostrativa",
                 metadata={"deleted": len(righe)}, **context)
    db.commit()
    return {"deleted": len(righe)}
