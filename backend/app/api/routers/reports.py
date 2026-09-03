"""Generazione, download e approvazione dei report."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import desc, select

from app.api.deps import CurrentUser, CurrentUserDep, DbDep, RequestContextDep, require_permission
from app.core.rbac import Permission
from app.models.enums import AuditAction, ReportStatus
from app.models.reporting import Report, ReportVersion
from app.models.scanning import Finding, Scan
from app.schemas.scanning import ReportCreate, ReportRead
from app.services.audit import record_audit
from app.services.report_builder import build_report_context
from app.services.review import ReviewRequiredError, assert_report_publishable
from reporting import service as report_service

router = APIRouter(tags=["reports"])

MIME_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "json": "application/json",
    "csv": "text/csv; charset=utf-8",
    "html": "text/html; charset=utf-8",
}


def _load_scan(db, scan_id: uuid.UUID, current: CurrentUser) -> Scan:  # noqa: ANN001
    scan = db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.tenant_id == current.tenant_id)
    ).scalar_one_or_none()
    if scan is None or not current.company_allowed(scan.company_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scansione non trovata")
    return scan


@router.get("/scans/{scan_id}/reports", response_model=list[ReportRead])
def list_reports(scan_id: uuid.UUID, db: DbDep, current: CurrentUserDep) -> list[ReportRead]:
    scan = _load_scan(db, scan_id, current)
    rows = db.execute(
        select(Report).where(Report.scan_id == scan.id).order_by(desc(Report.created_at))
    ).scalars().all()
    return [ReportRead.model_validate(r) for r in rows]


@router.post("/scans/{scan_id}/reports", response_model=ReportRead,
             status_code=status.HTTP_201_CREATED)
def generate_report(scan_id: uuid.UUID, payload: ReportCreate, db: DbDep,
                    context: RequestContextDep,
                    current: CurrentUser = Depends(
                        require_permission(Permission.REPORT_GENERATE))) -> ReportRead:
    """Genera il report nei formati richiesti.

    Un report DEFINITIVO non puo' essere emesso se restano finding critici o
    alti non validati da un analista (sezione 12).
    """
    scan = _load_scan(db, scan_id, current)
    findings = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    try:
        assert_report_publishable(
            [{"severity": f.severity, "analyst_validation": f.analyst_validation,
              "excluded_from_rating": f.excluded_from_rating,
              "reference_code": f.reference_code} for f in findings],
            is_final=payload.is_final)
    except ReviewRequiredError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    comparison = None
    if scan.previous_scan_id:
        from app.api.routers.scans import compare_with_previous

        try:
            comparison = compare_with_previous(scan.id, db, current).model_dump()
        except HTTPException:
            comparison = None

    unmask = current.has(Permission.PII_UNMASK)
    try:
        report_context = build_report_context(db, scan, language=payload.language,
                                              unmask_pii=unmask, comparison=comparison)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    report = Report(
        tenant_id=scan.tenant_id, company_id=scan.company_id, scan_id=scan.id,
        report_type=payload.report_type.value, language=payload.language,
        status=ReportStatus.GENERATING.value,
        title=(f"Defenix Exposure Rating - {scan.company.legal_name} - "
               f"{datetime.now(UTC):%d/%m/%Y}"),
        requires_review_before_publication=payload.is_final,
        generated_by_user_id=current.id)
    db.add(report)
    db.flush()

    include_technical = payload.report_type.value in {"technical", "combined"}
    produced = report_service.generate(
        report_context, [f.value for f in payload.formats], include_technical=include_technical)
    if not produced:
        report.status = ReportStatus.FAILED.value
        report.error_message = "nessun formato generato correttamente"
        db.commit()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            "Generazione del report non riuscita")

    version = 1 + db.execute(
        select(ReportVersion).where(ReportVersion.report_id == report.id)).scalars().all().__len__()
    for generated in produced:
        file_ref = report_service.store(generated, str(scan.id), version)
        db.add(ReportVersion(
            tenant_id=scan.tenant_id, report_id=report.id, version=version,
            format=generated.format, file_ref=file_ref, file_sha256=generated.sha256,
            file_bytes=generated.size, generated_at=datetime.now(UTC),
            content_summary_json={"findings": len(report_context.findings),
                                  "rating_class": report_context.rating_class,
                                  "overall_score": report_context.overall_score,
                                  "is_provisional": report_context.is_provisional}))
    report.status = ReportStatus.READY.value

    record_audit(db, action=AuditAction.REPORT_GENERATE.value, tenant_id=scan.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="report", entity_id=str(report.id),
                 message=f"report generato ({', '.join(g.format for g in produced)})",
                 metadata={"formats": [g.format for g in produced], "is_final": payload.is_final,
                           "language": payload.language, "pii_unmasked": unmask}, **context)
    db.commit()
    db.refresh(report)
    return ReportRead.model_validate(report)


@router.get("/reports/{report_id}/download/{fmt}")
def download_report(report_id: uuid.UUID, fmt: str, db: DbDep, context: RequestContextDep,
                    current: CurrentUser = Depends(
                        require_permission(Permission.REPORT_READ))) -> FileResponse:
    report = db.execute(
        select(Report).where(Report.id == report_id,
                             Report.tenant_id == current.tenant_id)).scalar_one_or_none()
    if report is None or not current.company_allowed(report.company_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report non trovato")

    version = db.execute(
        select(ReportVersion).where(ReportVersion.report_id == report.id,
                                    ReportVersion.format == fmt)
        .order_by(desc(ReportVersion.version)).limit(1)).scalar_one_or_none()
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            f"Formato «{fmt}» non disponibile per questo report")

    path = Path(version.file_ref)
    if not path.is_file():
        raise HTTPException(status.HTTP_410_GONE,
                            "Il file del report non e' piu' disponibile nello storage")

    record_audit(db, action=AuditAction.READ_SENSITIVE.value, tenant_id=report.tenant_id,
                 actor_user_id=current.id, actor_email=current.email,
                 entity_type="report", entity_id=str(report.id),
                 message=f"download del report in formato {fmt}", **context)
    db.commit()
    return FileResponse(path, media_type=MIME_TYPES.get(fmt, "application/octet-stream"),
                        filename=path.name)


@router.post("/reports/{report_id}/approve", response_model=ReportRead)
def approve_report(report_id: uuid.UUID, db: DbDep, context: RequestContextDep,
                   current: CurrentUser = Depends(
                       require_permission(Permission.REPORT_APPROVE))) -> ReportRead:
    report = db.execute(
        select(Report).where(Report.id == report_id,
                             Report.tenant_id == current.tenant_id)).scalar_one_or_none()
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report non trovato")
    if report.status != ReportStatus.READY.value:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"Il report non e' approvabile nello stato «{report.status}»")

    findings = db.execute(select(Finding).where(Finding.scan_id == report.scan_id)).scalars().all()
    try:
        assert_report_publishable(
            [{"severity": f.severity, "analyst_validation": f.analyst_validation,
              "excluded_from_rating": f.excluded_from_rating,
              "reference_code": f.reference_code} for f in findings], is_final=True)
    except ReviewRequiredError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    report.status = ReportStatus.APPROVED.value
    report.approved_by_user_id = current.id
    report.approved_at = datetime.now(UTC)
    record_audit(db, action=AuditAction.REPORT_APPROVE.value, tenant_id=report.tenant_id,
                 actor_user_id=current.id, actor_email=current.email, actor_roles=current.roles,
                 entity_type="report", entity_id=str(report.id),
                 message="report approvato per la pubblicazione", **context)
    db.commit()
    db.refresh(report)
    return ReportRead.model_validate(report)
