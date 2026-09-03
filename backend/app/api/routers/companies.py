"""Gestione aziende, domini, verifica della proprieta' e autorizzazioni."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select

from app.api.deps import (
    CompanyDep,
    CurrentUser,
    CurrentUserDep,
    DbDep,
    RequestContextDep,
    require_permission,
)
from app.core.rbac import Permission
from app.models.enums import (
    AuditAction,
    AuthorizationStatus,
    ScopeAction,
    VerificationMethod,
    VerificationStatus,
)
from app.models.organization import Company
from app.models.scope import Authorization, Domain, Scope
from app.schemas.common import Page
from app.schemas.organization import CompanyCreate, CompanyRead, CompanyUpdate
from app.schemas.scope import (
    AuthorizationCreate,
    AuthorizationRead,
    AuthorizationRevoke,
    DomainCreate,
    DomainRead,
    ManualApproval,
    ScopeEntryCreate,
    ScopeEntryRead,
    VerificationChallengeRead,
    VerificationResult,
    VerificationStart,
    VerificationSubmit,
)
from app.services import verification as verification_service
from app.services.audit import record_audit

router = APIRouter(prefix="/companies", tags=["companies"])


# --------------------------------------------------------------------------
# Aziende
# --------------------------------------------------------------------------
@router.get("", response_model=Page[CompanyRead])
def list_companies(db: DbDep, current: CurrentUserDep, page: int = 1, page_size: int = 50,
                   search: str | None = None) -> Page[CompanyRead]:
    query = select(Company).where(Company.tenant_id == current.tenant_id)
    if search:
        query = query.where(Company.legal_name.ilike(f"%{search[:100]}%"))
    scope = current.user.company_scope_json or []
    if scope:
        query = query.where(Company.id.in_([uuid.UUID(str(item)) for item in scope]))
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = db.execute(
        query.order_by(Company.legal_name).offset((page - 1) * page_size).limit(page_size)
    ).scalars().all()
    return Page[CompanyRead](items=[CompanyRead.model_validate(r) for r in rows],
                             total=total, page=page, page_size=page_size)


@router.post("", response_model=CompanyRead, status_code=status.HTTP_201_CREATED)
def create_company(payload: CompanyCreate, db: DbDep, context: RequestContextDep,
                   current: CurrentUser = Depends(require_permission(Permission.COMPANY_WRITE)),
                   ) -> CompanyRead:
    existing = db.execute(
        select(Company).where(Company.tenant_id == current.tenant_id,
                              Company.slug == payload.slug)).scalar_one_or_none()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Esiste gia' un'azienda con slug «{payload.slug}» in questo tenant")
    company = Company(tenant_id=current.tenant_id, **payload.model_dump())
    db.add(company)
    db.flush()
    record_audit(db, action=AuditAction.CREATE.value, tenant_id=current.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="company", entity_id=str(company.id),
                 message=f"azienda creata: {company.legal_name}", **context)
    db.commit()
    db.refresh(company)
    return CompanyRead.model_validate(company)


@router.get("/{company_id}", response_model=CompanyRead)
def get_company_detail(company: CompanyDep) -> CompanyRead:
    return CompanyRead.model_validate(company)


@router.patch("/{company_id}", response_model=CompanyRead)
def update_company(payload: CompanyUpdate, company: CompanyDep, db: DbDep,
                   context: RequestContextDep,
                   current: CurrentUser = Depends(require_permission(Permission.COMPANY_WRITE)),
                   ) -> CompanyRead:
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(company, field, value)
    record_audit(db, action=AuditAction.UPDATE.value, tenant_id=current.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="company", entity_id=str(company.id),
                 metadata={"fields": sorted(changes)}, **context)
    db.commit()
    db.refresh(company)
    return CompanyRead.model_validate(company)


# --------------------------------------------------------------------------
# Domini
# --------------------------------------------------------------------------
@router.get("/{company_id}/domains", response_model=list[DomainRead])
def list_domains(company: CompanyDep, db: DbDep) -> list[DomainRead]:
    rows = db.execute(
        select(Domain).where(Domain.company_id == company.id).order_by(
            Domain.is_primary.desc(), Domain.name)).scalars().all()
    return [DomainRead.model_validate(r) for r in rows]


@router.post("/{company_id}/domains", response_model=DomainRead,
             status_code=status.HTTP_201_CREATED)
def add_domain(payload: DomainCreate, company: CompanyDep, db: DbDep, context: RequestContextDep,
               current: CurrentUser = Depends(require_permission(Permission.DOMAIN_WRITE)),
               ) -> DomainRead:
    existing = db.execute(
        select(Domain).where(Domain.company_id == company.id,
                             Domain.name == payload.name)).scalar_one_or_none()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Dominio gia' registrato per questa azienda")
    if payload.is_primary:
        for other in db.execute(select(Domain).where(Domain.company_id == company.id)).scalars():
            other.is_primary = False
    domain = Domain(tenant_id=company.tenant_id, company_id=company.id,
                    name=payload.name, is_primary=payload.is_primary)
    db.add(domain)
    db.flush()
    record_audit(db, action=AuditAction.CREATE.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="domain", entity_id=str(domain.id),
                 message=f"dominio aggiunto: {domain.name}", **context)
    db.commit()
    db.refresh(domain)
    return DomainRead.model_validate(domain)


def _get_domain(db, company: Company, domain_id: uuid.UUID) -> Domain:  # noqa: ANN001
    domain = db.execute(
        select(Domain).where(Domain.id == domain_id, Domain.company_id == company.id)
    ).scalar_one_or_none()
    if domain is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dominio non trovato")
    return domain


@router.post("/{company_id}/domains/{domain_id}/verification",
             response_model=VerificationChallengeRead)
def start_verification(domain_id: uuid.UUID, payload: VerificationStart, company: CompanyDep,
                       db: DbDep, context: RequestContextDep,
                       current: CurrentUser = Depends(require_permission(Permission.DOMAIN_VERIFY)),
                       ) -> VerificationChallengeRead:
    """Genera la sfida di verifica della proprieta' del dominio."""
    domain = _get_domain(db, company, domain_id)
    challenge = verification_service.create_challenge(domain.name, payload.method.value)
    domain.verification_method = challenge.method
    domain.verification_token = challenge.token
    domain.verification_status = VerificationStatus.PENDING.value
    domain.verification_requested_at = datetime.now(UTC)
    domain.verification_expires_at = challenge.expires_at
    domain.verification_attempts = 0
    record_audit(db, action=AuditAction.VERIFICATION_ATTEMPT.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="domain", entity_id=str(domain.id),
                 message=f"sfida di verifica generata ({challenge.method})", **context)
    db.commit()
    return VerificationChallengeRead(
        domain=challenge.domain, method=challenge.method, expires_at=challenge.expires_at,
        instructions_it=challenge.instructions_it, record_name=challenge.record_name,
        record_value=challenge.record_value, file_url=challenge.file_url,
        file_content=challenge.file_content)


@router.post("/{company_id}/domains/{domain_id}/verification/check",
             response_model=VerificationResult)
def check_verification(domain_id: uuid.UUID, payload: VerificationSubmit, company: CompanyDep,
                       db: DbDep, context: RequestContextDep,
                       current: CurrentUser = Depends(require_permission(Permission.DOMAIN_VERIFY)),
                       ) -> VerificationResult:
    domain = _get_domain(db, company, domain_id)
    if not domain.verification_method or not domain.verification_token:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Nessuna verifica avviata per questo dominio")
    if verification_service.is_challenge_expired(domain.verification_expires_at):
        domain.verification_status = VerificationStatus.EXPIRED.value
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "La sfida di verifica e' scaduta: generarne una nuova")

    domain.verification_attempts += 1
    outcome = verification_service.run_verification(
        domain.name, domain.verification_method, domain.verification_token, payload.token)
    domain.verification_status = verification_service.next_status(outcome, domain.verification_attempts)
    domain.last_verification_error = None if outcome.verified else outcome.detail_it
    if outcome.verified:
        domain.verified_at = outcome.checked_at
        domain.verified_by_user_id = current.id

    record_audit(db, action=AuditAction.VERIFICATION_ATTEMPT.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="domain", entity_id=str(domain.id),
                 outcome="success" if outcome.verified else "failure",
                 message=outcome.detail_it,
                 metadata={"method": outcome.method, "attempts": domain.verification_attempts},
                 **context)
    db.commit()
    return VerificationResult(verified=outcome.verified, status=domain.verification_status,
                              method=outcome.method, detail_it=outcome.detail_it,
                              checked_at=outcome.checked_at)


@router.post("/{company_id}/domains/{domain_id}/verification/approve",
             response_model=VerificationResult)
def approve_manually(domain_id: uuid.UUID, payload: ManualApproval, company: CompanyDep,
                     db: DbDep, context: RequestContextDep,
                     current: CurrentUser = Depends(require_permission(Permission.PLATFORM_MANAGE)),
                     ) -> VerificationResult:
    """Approvazione manuale: riservata al Platform Administrator e sempre
    tracciata con nome dell'approvatore e riferimento del documento."""
    domain = _get_domain(db, company, domain_id)
    now = datetime.now(UTC)
    domain.verification_status = VerificationStatus.VERIFIED.value
    domain.verification_method = VerificationMethod.MANUAL_APPROVAL.value
    domain.verified_at = now
    domain.verified_by_user_id = current.id
    record_audit(db, action=AuditAction.VERIFICATION_ATTEMPT.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="domain", entity_id=str(domain.id),
                 message=f"approvazione manuale da parte di {payload.approver_name}",
                 metadata={"document_reference": payload.document_reference,
                           "notes": payload.notes}, **context)
    db.commit()
    return VerificationResult(verified=True, status=domain.verification_status,
                              method=VerificationMethod.MANUAL_APPROVAL.value,
                              detail_it=f"approvato manualmente da {payload.approver_name}",
                              checked_at=now)


# --------------------------------------------------------------------------
# Autorizzazioni e perimetro
# --------------------------------------------------------------------------
@router.get("/{company_id}/authorizations", response_model=list[AuthorizationRead])
def list_authorizations(company: CompanyDep, db: DbDep,
                        _: CurrentUser = Depends(require_permission(Permission.AUTHORIZATION_READ)),
                        ) -> list[AuthorizationRead]:
    rows = db.execute(
        select(Authorization).where(Authorization.company_id == company.id)
        .order_by(Authorization.expires_at.desc())).scalars().all()
    return [AuthorizationRead.model_validate(r) for r in rows]


@router.post("/{company_id}/authorizations", response_model=AuthorizationRead,
             status_code=status.HTTP_201_CREATED)
def create_authorization(payload: AuthorizationCreate, company: CompanyDep, db: DbDep,
                         context: RequestContextDep,
                         current: CurrentUser = Depends(
                             require_permission(Permission.AUTHORIZATION_WRITE)),
                         ) -> AuthorizationRead:
    """Registra un'autorizzazione esplicita all'esecuzione di controlli attivi."""
    authorization = Authorization(
        tenant_id=company.tenant_id, company_id=company.id,
        status=AuthorizationStatus.ACTIVE.value,
        granting_subject_name=payload.granting_subject_name,
        granting_subject_role=payload.granting_subject_role,
        granting_subject_email=payload.granting_subject_email,
        granted_by_user_id=current.id, granted_at=datetime.now(UTC),
        valid_from=payload.valid_from, expires_at=payload.expires_at,
        allowed_profiles_json=[p.value for p in payload.allowed_profiles],
        exclusions_json=payload.exclusions,
        document_reference=payload.document_reference, notes=payload.notes)
    db.add(authorization)
    db.flush()

    for entry in payload.scopes:
        db.add(Scope(tenant_id=company.tenant_id, company_id=company.id,
                     authorization_id=authorization.id, entry_type=entry.entry_type.value,
                     value=entry.value, action=entry.action.value, note=entry.note))
    for excluded in payload.exclusions:
        db.add(Scope(tenant_id=company.tenant_id, company_id=company.id,
                     authorization_id=authorization.id, entry_type="domain",
                     value=str(excluded), action=ScopeAction.EXCLUDE.value,
                     note="esclusione dichiarata nell'autorizzazione"))

    record_audit(db, action=AuditAction.AUTHORIZATION_GRANT.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="authorization", entity_id=str(authorization.id),
                 message=(f"autorizzazione concessa da {payload.granting_subject_name} "
                          f"fino al {payload.expires_at.date().isoformat()}"),
                 metadata={"profiles": [p.value for p in payload.allowed_profiles],
                           "scopes": len(payload.scopes),
                           "document_reference": payload.document_reference}, **context)
    db.commit()
    db.refresh(authorization)
    return AuthorizationRead.model_validate(authorization)


@router.post("/{company_id}/authorizations/{authorization_id}/revoke",
             response_model=AuthorizationRead)
def revoke_authorization(authorization_id: uuid.UUID, payload: AuthorizationRevoke,
                         company: CompanyDep, db: DbDep, context: RequestContextDep,
                         current: CurrentUser = Depends(
                             require_permission(Permission.AUTHORIZATION_WRITE)),
                         ) -> AuthorizationRead:
    authorization = db.execute(
        select(Authorization).where(Authorization.id == authorization_id,
                                    Authorization.company_id == company.id)).scalar_one_or_none()
    if authorization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Autorizzazione non trovata")
    authorization.status = AuthorizationStatus.REVOKED.value
    authorization.revoked_at = datetime.now(UTC)
    authorization.revocation_reason = payload.reason
    record_audit(db, action=AuditAction.AUTHORIZATION_REVOKE.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="authorization", entity_id=str(authorization.id),
                 message=payload.reason, **context)
    db.commit()
    db.refresh(authorization)
    return AuthorizationRead.model_validate(authorization)


@router.get("/{company_id}/scopes", response_model=list[ScopeEntryRead])
def list_scopes(company: CompanyDep, db: DbDep) -> list[ScopeEntryRead]:
    rows = db.execute(
        select(Scope).where(Scope.company_id == company.id).order_by(Scope.action, Scope.value)
    ).scalars().all()
    return [ScopeEntryRead.model_validate(r) for r in rows]


@router.post("/{company_id}/scopes", response_model=ScopeEntryRead,
             status_code=status.HTTP_201_CREATED)
def add_scope(payload: ScopeEntryCreate, company: CompanyDep, db: DbDep,
              context: RequestContextDep,
              current: CurrentUser = Depends(require_permission(Permission.AUTHORIZATION_WRITE)),
              ) -> ScopeEntryRead:
    entry = Scope(tenant_id=company.tenant_id, company_id=company.id,
                  entry_type=payload.entry_type.value, value=payload.value,
                  action=payload.action.value, note=payload.note)
    db.add(entry)
    db.flush()
    record_audit(db, action=AuditAction.CREATE.value, tenant_id=company.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="scope", entity_id=str(entry.id),
                 message=f"{payload.action.value} {payload.entry_type.value} {payload.value}",
                 **context)
    db.commit()
    db.refresh(entry)
    return ScopeEntryRead.model_validate(entry)
