"""Avvio, monitoraggio e confronto delle scansioni."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.deps import (
    CompanyDep,
    CurrentUser,
    CurrentUserDep,
    DbDep,
    RequestContextDep,
    require_permission,
)
from app.core.config import settings
from app.core.rbac import PROFILE_PERMISSION, Permission
from app.core.redaction import sanitize_text
from app.models.enums import AuditAction, ScanStatus, ScopeAction, ScopeEntryType
from app.models.organization import Company
from app.models.scanning import Finding, Scan, ToolRun
from app.models.scope import Authorization, Domain, IPAddress, NetworkRange, Scope
from app.models.scoring import Score
from app.schemas.common import Page
from app.schemas.scanning import (
    ScanAuthorizationPreview,
    ScanComparison,
    ScanCreate,
    ScanDetail,
    ScanRead,
    ToolRunRead,
)
from app.services.audit import record_audit
from app.services.authorization import (
    AuthorizationView,
    DomainView,
    ScopeView,
    check_scan_authorization,
)
from app.services.diff import (
    AssetSnapshot,
    FindingSnapshot,
    apply_score_delta,
    diff_assets,
    diff_findings,
)

router = APIRouter(tags=["scans"])


# ---------------------------------------------------------------------------
def _gather_scope(db: Session, company: Company) -> dict:
    domains = db.execute(select(Domain).where(Domain.company_id == company.id)).scalars().all()
    authorizations = db.execute(
        select(Authorization).where(Authorization.company_id == company.id)).scalars().all()
    scopes = db.execute(select(Scope).where(Scope.company_id == company.id)).scalars().all()
    ips = db.execute(select(IPAddress).where(IPAddress.company_id == company.id)).scalars().all()
    networks = db.execute(
        select(NetworkRange).where(NetworkRange.company_id == company.id)).scalars().all()
    return {"domains": domains, "authorizations": authorizations, "scopes": scopes,
            "ips": ips, "networks": networks}


def _authorization_check(db: Session, company: Company, profile: str):  # noqa: ANN201
    from adapters.registry import profile_definition

    data = _gather_scope(db, company)
    return check_scan_authorization(
        profile=profile,
        domains=[DomainView(d.name, d.verification_status) for d in data["domains"]],
        authorizations=[
            AuthorizationView(str(a.id), a.status, a.valid_from, a.expires_at, a.revoked_at,
                              a.allowed_profiles_json or [])
            for a in data["authorizations"]],
        scopes=[ScopeView(s.entry_type, s.value, s.action, s.is_active) for s in data["scopes"]],
        profile_definition=profile_definition(profile)), data


# ---------------------------------------------------------------------------
@router.get("/companies/{company_id}/scans", response_model=Page[ScanRead])
def list_scans(company: CompanyDep, db: DbDep, page: int = 1, page_size: int = 25) -> Page[ScanRead]:
    total = db.execute(
        select(func.count()).select_from(Scan).where(Scan.company_id == company.id)).scalar_one()
    rows = db.execute(
        select(Scan).where(Scan.company_id == company.id).order_by(desc(Scan.created_at))
        .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return Page[ScanRead](items=[ScanRead.model_validate(r) for r in rows],
                          total=total, page=page, page_size=page_size)


@router.get("/companies/{company_id}/scans/authorization-preview",
            response_model=ScanAuthorizationPreview)
def authorization_preview(company: CompanyDep, db: DbDep, profile: str = "public_passive",
                          ) -> ScanAuthorizationPreview:
    """Verifica le precondizioni senza avviare nulla: usato dall'interfaccia
    per spiegare all'utente cosa manca prima di poter lanciare la scansione."""
    from adapters.registry import ProfileNotFoundError, profile_definition, tools_for_profile

    try:
        definition = profile_definition(profile)
    except ProfileNotFoundError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    check, _ = _authorization_check(db, company, profile)
    return ScanAuthorizationPreview(
        profile=profile, allowed=check.allowed, reasons=check.reasons,
        authorization_id=check.authorization_id, expires_at=check.expires_at,
        tools_planned=tools_for_profile(profile),
        forbidden_actions=definition.get("forbidden_actions", []))


@router.post("/companies/{company_id}/scans", response_model=ScanRead,
             status_code=status.HTTP_202_ACCEPTED)
def start_scan(payload: ScanCreate, company: CompanyDep, db: DbDep, context: RequestContextDep,
               current: CurrentUserDep) -> ScanRead:
    """Avvia una scansione.

    Il gate di autorizzazione e' applicato QUI: nessun percorso alternativo
    puo' creare uno Scan in stato eseguibile.
    """
    from adapters.registry import ProfileNotFoundError, profile_definition

    profile = payload.profile.value
    required_permission = PROFILE_PERMISSION.get(profile, Permission.SCAN_START_EXTENDED)
    if not current.has(required_permission):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"Permesso mancante per il profilo «{profile}»: {required_permission}")
    try:
        profile_definition(profile)
    except ProfileNotFoundError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    check, data = _authorization_check(db, company, profile)
    if not check.allowed:
        record_audit(db, action=AuditAction.SCAN_BLOCKED.value, tenant_id=company.tenant_id,
                     actor_user_id=current.id, actor_email=current.email, outcome="failure",
                     entity_type="company", entity_id=str(company.id),
                     message="avvio scansione rifiutato dal gate di autorizzazione",
                     metadata={"profile": profile, "reasons": check.reasons}, **context)
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, {
            "error": "Scansione non autorizzata", "profile": profile, "reasons": check.reasons})

    previous = db.execute(
        select(Scan).where(Scan.company_id == company.id,
                           Scan.status.in_([ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value]))
        .order_by(desc(Scan.finished_at)).limit(1)).scalar_one_or_none()

    running = db.execute(
        select(Scan).where(Scan.company_id == company.id,
                           Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.QUEUED.value,
                                            ScanStatus.RUNNING.value]))).scalars().first()
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Una scansione e' gia' in corso per questa azienda")

    verified = [d.name for d in data["domains"] if d.verification_status == "verified"]
    scan = Scan(
        tenant_id=company.tenant_id, company_id=company.id, profile_key=profile,
        authorization_id=uuid.UUID(check.authorization_id) if check.authorization_id else None,
        status=ScanStatus.QUEUED.value, requested_by_user_id=current.id,
        mock_mode=settings.scan_mock_mode, started_at=datetime.now(UTC),
        previous_scan_id=previous.id if previous else None,
        scope_snapshot_json={
            "domains": [d.name for d in data["domains"]],
            "verified_domains": verified,
            "ip_addresses": [i.address for i in data["ips"]],
            "authorized_ips": [i.address for i in data["ips"]
                               if i.ownership_status == "verified_owned"],
            "network_ranges": [n.cidr for n in data["networks"]],
            "excluded": [s.value for s in data["scopes"] if s.action == "exclude"],
            "email_addresses": [s.value for s in data["scopes"]
                                if s.entry_type == ScopeEntryType.EMAIL_ADDRESS.value
                                and s.action == ScopeAction.INCLUDE.value and s.is_active],
            "dkim_selectors": payload.dkim_selectors,
            "authorization_id": check.authorization_id,
        })
    db.add(scan)
    db.flush()

    record_audit(db, action=AuditAction.SCAN_START.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="scan", entity_id=str(scan.id),
                 message=f"scansione avviata con profilo {profile}",
                 metadata={"profile": profile, "domains": len(data["domains"]),
                           "verified_domains": len(verified),
                           "authorization_id": check.authorization_id}, **context)
    db.commit()
    db.refresh(scan)

    # L'header e-mail non viene mai persistito integralmente: passa al worker
    # gia' sanitizzato e viene scartato al termine dell'analisi.
    email_header = sanitize_text(payload.email_header, 200_000) if payload.email_header else None
    _enqueue(scan, email_header)
    return ScanRead.model_validate(scan)


def _enqueue(scan: Scan, email_header: str | None) -> None:
    """Accoda la scansione su Celery.

    Se il broker non risponde, la scansione viene marcata come fallita con il
    motivo. In precedenza restava `queued` a tempo indeterminato: nessun worker
    l'avrebbe mai presa in carico, ma l'interfaccia continuava a mostrarla in
    attesa, senza alcun modo di accorgersi che l'accodamento non era avvenuto.
    """
    from app.core.db import session_scope
    from app.core.logging import get_logger

    logger = get_logger(__name__)
    try:
        from app.workers.tasks import run_scan_task

        async_result = run_scan_task.delay(str(scan.id), email_header)
        with session_scope() as db:
            row = db.get(Scan, scan.id)
            if row is not None:
                row.celery_task_id = async_result.id
    except Exception as exc:  # noqa: BLE001
        logger.error("scan_enqueue_failed", scan_id=str(scan.id), error=str(exc))
        with session_scope() as db:
            row = db.get(Scan, scan.id)
            if row is not None:
                row.status = ScanStatus.FAILED.value
                row.finished_at = datetime.now(UTC)
                row.error_message = (
                    "Accodamento non riuscito: il broker delle code non e' "
                    f"raggiungibile ({exc}). Verificare che i servizi redis e "
                    "worker siano attivi, poi riavviare la scansione.")


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: uuid.UUID, db: DbDep, current: CurrentUserDep) -> ScanDetail:
    scan = db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.tenant_id == current.tenant_id)
    ).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scansione non trovata")
    if not current.company_allowed(scan.company_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scansione non trovata")
    runs = db.execute(
        select(ToolRun).where(ToolRun.scan_id == scan.id).order_by(ToolRun.created_at)
    ).scalars().all()
    detail = ScanDetail.model_validate(scan)
    detail.tool_runs = [ToolRunRead.model_validate(r) for r in runs]
    return detail


@router.post("/scans/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(scan_id: uuid.UUID, db: DbDep, context: RequestContextDep,
                current: CurrentUser = Depends(require_permission(Permission.SCAN_CANCEL)),
                ) -> ScanRead:
    scan = db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.tenant_id == current.tenant_id)
    ).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scansione non trovata")
    if scan.is_terminal:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La scansione e' gia' conclusa")
    scan.status = ScanStatus.CANCELLED.value
    scan.finished_at = datetime.now(UTC)
    record_audit(db, action=AuditAction.UPDATE.value, tenant_id=scan.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="scan", entity_id=str(scan.id),
                 message="scansione annullata dall'operatore", **context)
    db.commit()
    db.refresh(scan)
    return ScanRead.model_validate(scan)


@router.get("/scans/{scan_id}/comparison", response_model=ScanComparison)
def compare_with_previous(scan_id: uuid.UUID, db: DbDep, current: CurrentUserDep,
                          against: uuid.UUID | None = None) -> ScanComparison:
    """Confronta la scansione con la precedente (o con quella indicata)."""
    scan = db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.tenant_id == current.tenant_id)
    ).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scansione non trovata")

    baseline_id = against or scan.previous_scan_id
    current_score = db.execute(select(Score).where(Score.scan_id == scan.id)).scalar_one_or_none()
    if current_score is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "La scansione non ha ancora un punteggio calcolato")

    current_findings = _snapshots(db, scan.id)
    baseline_findings: list[FindingSnapshot] = []
    baseline_score: Score | None = None
    if baseline_id:
        baseline_findings = _snapshots(db, baseline_id)
        baseline_score = db.execute(
            select(Score).where(Score.scan_id == baseline_id)).scalar_one_or_none()

    diff = diff_findings(baseline_findings, current_findings)
    diff = diff_assets(_asset_snapshots(db, baseline_id) if baseline_id else [],
                       _asset_snapshots(db, scan.id), diff)
    diff = apply_score_delta(
        diff,
        previous_score=baseline_score.overall_score if baseline_score else None,
        current_score=current_score.overall_score,
        previous_class=baseline_score.rating_class if baseline_score else None,
        current_class=current_score.rating_class,
        previous_confidence=(baseline_score.confidence.confidence_value
                             if baseline_score and baseline_score.confidence else None),
        current_confidence=(current_score.confidence.confidence_value
                            if current_score.confidence else None))

    return ScanComparison(
        previous_scan_id=str(baseline_id) if baseline_id else None,
        current_scan_id=str(scan.id), previous_score=diff.previous_score,
        current_score=diff.current_score or current_score.overall_score,
        score_delta=diff.score_delta, previous_class=diff.previous_class,
        current_class=diff.current_class or current_score.rating_class,
        confidence_delta=diff.confidence_delta, new_findings=diff.new_findings,
        resolved_findings=diff.resolved_findings, pending_closure=diff.pending_closure,
        reopened_findings=diff.reopened_findings, new_assets=diff.new_assets,
        disappeared_assets=diff.disappeared_assets, summary_it=diff.summary_it())


def _snapshots(db: Session, scan_id: uuid.UUID) -> list[FindingSnapshot]:
    rows = db.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
    return [FindingSnapshot(
        fingerprint=r.fingerprint, reference_code=r.reference_code, title=r.title,
        category=r.category, severity=r.severity, asset_key=str(r.asset_id or ""),
        finding_type=r.finding_type, first_seen_at=r.first_seen_at,
        last_seen_at=r.last_seen_at, resolved_at=r.resolved_at,
        missing_confirmations=r.missing_confirmations) for r in rows]


def _asset_snapshots(db: Session, scan_id: uuid.UUID) -> list[AssetSnapshot]:
    from app.models.scope import Asset

    scan = db.get(Scan, scan_id)
    if scan is None:
        return []
    rows = db.execute(
        select(Asset).where(Asset.company_id == scan.company_id)).scalars().all()
    return [AssetSnapshot(asset_key=r.asset_key, asset_type=r.asset_type,
                          ownership_status=r.ownership_status,
                          first_seen_at=r.first_seen_at, last_seen_at=r.last_seen_at)
            for r in rows
            if scan.finished_at is None or r.last_seen_at <= scan.finished_at]
