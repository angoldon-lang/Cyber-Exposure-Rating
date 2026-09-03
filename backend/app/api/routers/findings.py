"""Consultazione e revisione dei finding (workflow di sezione 17)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from app.api.deps import CurrentUser, CurrentUserDep, DbDep, RequestContextDep, require_permission
from app.core.rbac import Permission
from app.models.enums import AuditAction, FindingWorkflowState
from app.models.scanning import Finding, Scan
from app.schemas.common import Page
from app.schemas.scanning import (
    FindingRead,
    FindingReview,
    RemediationItemRead,
    ReviewProgress,
)
from app.services.audit import record_audit
from app.services.remediation import build_plan, quick_wins
from app.services.review import InvalidTransitionError, apply_review_action, review_progress

router = APIRouter(tags=["findings"])


def _load_scan(db, scan_id: uuid.UUID, current: CurrentUser) -> Scan:  # noqa: ANN001
    scan = db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.tenant_id == current.tenant_id)
    ).scalar_one_or_none()
    if scan is None or not current.company_allowed(scan.company_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scansione non trovata")
    return scan


@router.get("/scans/{scan_id}/findings", response_model=Page[FindingRead])
def list_findings(scan_id: uuid.UUID, db: DbDep, current: CurrentUserDep,
                  severity: str | None = None, category: str | None = None,
                  workflow_state: str | None = None, only_scoring: bool = False,
                  page: int = 1, page_size: int = Query(default=100, le=500)) -> Page[FindingRead]:
    scan = _load_scan(db, scan_id, current)
    conditions = [Finding.scan_id == scan.id, Finding.tenant_id == current.tenant_id]
    if severity:
        conditions.append(Finding.severity == severity)
    if category:
        conditions.append(Finding.category == category)
    if workflow_state:
        conditions.append(Finding.workflow_state == workflow_state)
    if only_scoring:
        conditions.append(Finding.applied_deduction > 0)

    total = db.execute(select(func.count()).select_from(Finding).where(*conditions)).scalar_one()
    rows = db.execute(
        select(Finding).where(*conditions)
        .order_by(Finding.severity, Finding.reference_code)
        .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return Page[FindingRead](items=[FindingRead.model_validate(r) for r in rows],
                             total=total, page=page, page_size=page_size)


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: uuid.UUID, db: DbDep, current: CurrentUserDep) -> FindingRead:
    finding = db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.tenant_id == current.tenant_id)
    ).scalar_one_or_none()
    if finding is None or not current.company_allowed(finding.company_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding non trovato")
    return FindingRead.model_validate(finding)


@router.post("/findings/{finding_id}/review", response_model=FindingRead)
def review_finding(finding_id: uuid.UUID, payload: FindingReview, db: DbDep,
                   context: RequestContextDep,
                   current: CurrentUser = Depends(require_permission(Permission.FINDING_REVIEW)),
                   ) -> FindingRead:
    """Applica un'azione di revisione. Ogni modifica manuale finisce in audit."""
    finding = db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.tenant_id == current.tenant_id)
    ).scalar_one_or_none()
    if finding is None or not current.company_allowed(finding.company_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding non trovato")

    if payload.action == "confirm" and not current.has(Permission.FINDING_APPROVE):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "La conferma definitiva richiede il permesso finding:approve")

    previous_state = {
        "workflow_state": finding.workflow_state,
        "analyst_validation": finding.analyst_validation,
        "severity": finding.severity,
        "confidence_class": finding.confidence_class,
        "excluded_from_rating": finding.excluded_from_rating,
    }
    try:
        decision = apply_review_action(
            payload.action, current_state=finding.workflow_state,
            current_confidence=finding.confidence_class, reason=payload.reason,
            new_severity=payload.new_severity, new_confidence=payload.new_confidence)
    except InvalidTransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    finding.analyst_validation = decision.analyst_validation
    finding.workflow_state = decision.workflow_state
    finding.excluded_from_rating = decision.excluded_from_rating
    finding.retest_requested = decision.retest_requested
    if decision.confidence_class:
        finding.confidence_class = decision.confidence_class
    if decision.severity:
        finding.severity = decision.severity
    finding.reviewed_by_user_id = current.id
    finding.reviewed_at = datetime.now(UTC)
    finding.review_notes = payload.reason
    if decision.excluded_from_rating:
        finding.exclusion_reason = payload.reason
    if payload.action == "reopen":
        finding.resolved_at = None
        finding.reopened_at = datetime.now(UTC)

    record_audit(db, action=AuditAction.FINDING_REVIEW.value, tenant_id=finding.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="finding", entity_id=str(finding.id),
                 message=f"azione di revisione «{payload.action}» su {finding.reference_code}",
                 metadata={"action": payload.action, "reason": payload.reason,
                           "before": previous_state,
                           "after": {"workflow_state": finding.workflow_state,
                                     "analyst_validation": finding.analyst_validation,
                                     "severity": finding.severity,
                                     "confidence_class": finding.confidence_class,
                                     "excluded_from_rating": finding.excluded_from_rating}},
                 **context)
    db.commit()
    db.refresh(finding)
    return FindingRead.model_validate(finding)


@router.get("/scans/{scan_id}/review-progress", response_model=ReviewProgress)
def get_review_progress(scan_id: uuid.UUID, db: DbDep, current: CurrentUserDep) -> ReviewProgress:
    scan = _load_scan(db, scan_id, current)
    rows = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    progress = review_progress([
        {"severity": r.severity, "analyst_validation": r.analyst_validation,
         "excluded_from_rating": r.excluded_from_rating} for r in rows])
    return ReviewProgress(**{k: v for k, v in progress.items() if k != "computed_at"})


@router.get("/scans/{scan_id}/remediation-plan", response_model=list[RemediationItemRead])
def remediation_plan(scan_id: uuid.UUID, db: DbDep, current: CurrentUserDep,
                     only_quick_wins: bool = False) -> list[RemediationItemRead]:
    """Piano di remediation prioritizzato per la scansione."""
    scan = _load_scan(db, scan_id, current)
    rows = db.execute(
        select(Finding).where(Finding.scan_id == scan.id,
                              Finding.excluded_from_rating.is_(False))).scalars().all()
    plan = build_plan([
        {"finding_type": r.finding_type, "reference_code": r.reference_code,
         "asset_key": r.detail or r.reference_code, "severity": r.severity,
         "applied_rules": r.applied_rules_json or []} for r in rows])
    selected = quick_wins(plan) if only_quick_wins else plan
    return [RemediationItemRead(**item.as_dict()) for item in selected]


@router.post("/scans/{scan_id}/findings/bulk-approve", response_model=ReviewProgress)
def bulk_approve(scan_id: uuid.UUID, db: DbDep, context: RequestContextDep,
                 current: CurrentUser = Depends(require_permission(Permission.FINDING_APPROVE)),
                 max_severity: str = "medium") -> ReviewProgress:
    """Approva massivamente i finding fino alla severita' indicata.

    I finding critici e alti restano SEMPRE esclusi: richiedono una revisione
    individuale prima della pubblicazione del report definitivo.
    """
    from app.models.enums import SEVERITY_RANK

    if SEVERITY_RANK.get(max_severity, 99) >= SEVERITY_RANK["high"]:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "L'approvazione massiva non e' ammessa per i finding di severita' alta o critica: "
            "richiedono una revisione individuale")
    scan = _load_scan(db, scan_id, current)
    rows = db.execute(
        select(Finding).where(Finding.scan_id == scan.id,
                              Finding.analyst_validation == "not_reviewed")).scalars().all()
    approved = 0
    for finding in rows:
        if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(max_severity, 0):
            continue
        finding.analyst_validation = "validated"
        finding.workflow_state = FindingWorkflowState.APPROVED.value
        finding.reviewed_by_user_id = current.id
        finding.reviewed_at = datetime.now(UTC)
        approved += 1

    record_audit(db, action=AuditAction.FINDING_REVIEW.value, tenant_id=scan.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="scan", entity_id=str(scan.id),
                 message=f"approvazione massiva di {approved} finding fino a severita' {max_severity}",
                 metadata={"approved": approved, "max_severity": max_severity}, **context)
    db.commit()

    rows = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    progress = review_progress([
        {"severity": r.severity, "analyst_validation": r.analyst_validation,
         "excluded_from_rating": r.excluded_from_rating} for r in rows])
    return ReviewProgress(**{k: v for k, v in progress.items() if k != "computed_at"})
