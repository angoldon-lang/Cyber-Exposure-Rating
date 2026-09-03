"""Dashboard per azienda e vista Portfolio multi-azienda."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.deps import CompanyDep, CurrentUserDep, DbDep
from app.api.routers.health import DISCLAIMER_IT
from app.models.enums import AnalystValidation, ScanStatus
from app.models.organization import Company
from app.models.scanning import Finding, Scan
from app.models.scope import Asset, Domain, EmailDomain
from app.models.scoring import Score
from app.schemas.scanning import DashboardCompanyCard, DashboardOverview, PortfolioView
from app.services.confidence import PROVISIONAL_NOTICE_IT
from app.services.review import review_progress

router = APIRouter(tags=["dashboard"])

TREND_POINTS = 12


def _latest_score(db: Session, company_id: uuid.UUID) -> tuple[Score | None, Scan | None]:
    row = db.execute(
        select(Score, Scan).join(Scan, Score.scan_id == Scan.id)
        .where(Score.company_id == company_id)
        .order_by(desc(Score.computed_at)).limit(1)).first()
    return (row[0], row[1]) if row else (None, None)


def _previous_score(db: Session, company_id: uuid.UUID, current: Score) -> Score | None:
    return db.execute(
        select(Score).where(Score.company_id == company_id, Score.id != current.id)
        .order_by(desc(Score.computed_at)).limit(1)).scalar_one_or_none()


@router.get("/companies/{company_id}/dashboard", response_model=DashboardOverview)
def company_dashboard(company: CompanyDep, db: DbDep) -> DashboardOverview:
    score, scan = _latest_score(db, company.id)
    findings = (db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
                if scan else [])

    severity_counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    assets = db.execute(select(Asset).where(Asset.company_id == company.id)).scalars().all()
    asset_counts = {
        "total": len(assets),
        "domains": sum(1 for a in assets if a.asset_type == "domain"),
        "subdomains": sum(1 for a in assets if a.asset_type == "subdomain"),
        "ip_addresses": sum(1 for a in assets if a.asset_type == "ip_address"),
        "web_services": sum(1 for a in assets if a.asset_type == "web_service"),
        "network_services": sum(1 for a in assets if a.asset_type == "network_service"),
        "mail_services": sum(1 for a in assets if a.asset_type == "mail_service"),
        "verified_owned": sum(1 for a in assets if a.ownership_status == "verified_owned"),
        "third_party": sum(1 for a in assets if a.ownership_status == "third_party"),
        "new_last_scan": sum(1 for a in assets
                             if scan and scan.started_at and a.first_seen_at >= scan.started_at),
        "disappeared": sum(1 for a in assets if a.disappeared_at is not None),
    }

    email_domain = db.execute(
        select(EmailDomain).where(EmailDomain.company_id == company.id).limit(1)
    ).scalar_one_or_none()
    email_posture = dict(email_domain.posture_json or {}) if email_domain else {}
    email_posture.update({
        "findings": sum(1 for f in findings if f.category == "email_dns_security"),
        "spoofing_risk": any(f.finding_type == "spoofing_possible" for f in findings),
    })

    darkweb = {
        "ransomware_publications": sum(1 for f in findings
                                       if f.finding_type == "ransomware_leak_publication"),
        "stealer_logs": sum(1 for f in findings if f.finding_type == "stealer_log_credentials"),
        "breaches": sum(1 for f in findings if f.finding_type.startswith("breach_credentials")),
        "lookalike_domains": sum(1 for f in findings
                                 if f.finding_type.startswith("lookalike_domain")),
        "darkweb_mentions": sum(1 for f in findings if f.finding_type == "darkweb_mention"),
    }

    trend = [
        {"scan_id": str(row.scan_id), "score": row.overall_score, "rating_class": row.rating_class,
         "confidence": row.confidence.confidence_value if row.confidence else None,
         "computed_at": row.computed_at.isoformat()}
        for row in db.execute(
            select(Score).where(Score.company_id == company.id)
            .order_by(Score.computed_at).limit(TREND_POINTS)).scalars().all()
    ]

    progress = review_progress([
        {"severity": f.severity, "analyst_validation": f.analyst_validation,
         "excluded_from_rating": f.excluded_from_rating} for f in findings])

    confidence_value = score.confidence.confidence_value if score and score.confidence else None
    return DashboardOverview(
        company_id=str(company.id), company_name=company.legal_name,
        overall_score=score.overall_score if score else None,
        rating_class=score.rating_class if score else None,
        rating_label_it=_class_label(score.rating_class) if score else None,
        confidence=confidence_value,
        confidence_label_it=score.confidence.label_it if score and score.confidence else None,
        is_provisional=bool(score and score.is_provisional),
        provisional_notice=PROVISIONAL_NOTICE_IT if (score and score.is_provisional) else None,
        categories=[{"key": c.category_key, "label_it": c.label_it, "weight": c.weight,
                     "score": c.score, "total_deduction": c.total_deduction,
                     "finding_count": c.finding_count, "critical_count": c.critical_count,
                     "high_count": c.high_count}
                    for c in (score.categories if score else [])],
        severity_counts=severity_counts, trend=trend, assets=asset_counts,
        email_posture=email_posture, darkweb=darkweb,
        review_progress={k: v for k, v in progress.items() if k != "computed_at"},
        last_scan={"id": str(scan.id), "profile": scan.profile_key, "status": scan.status,
                   "started_at": scan.started_at.isoformat() if scan.started_at else None,
                   "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                   "mock_mode": scan.mock_mode} if scan else None,
        open_remediations=sum(1 for f in findings
                              if f.resolved_at is None and not f.excluded_from_rating
                              and f.applied_deduction > 0),
        scope_disclaimer_it=DISCLAIMER_IT)


def _class_label(rating_class: str) -> str:
    from app.core.config import load_yaml_config

    for entry in load_yaml_config("scoring")["classes"]:
        if entry["code"] == rating_class:
            return str(entry["label_it"])
    return ""


@router.get("/portfolio", response_model=PortfolioView)
def portfolio(db: DbDep, current: CurrentUserDep) -> PortfolioView:
    """Vista multi-azienda per AD Consulting/Defenix."""
    query = select(Company).where(Company.tenant_id == current.tenant_id,
                                  Company.is_active.is_(True))
    scope = current.user.company_scope_json or []
    if scope:
        query = query.where(Company.id.in_([uuid.UUID(str(item)) for item in scope]))
    companies = db.execute(query.order_by(Company.legal_name)).scalars().all()

    cards: list[DashboardCompanyCard] = []
    scores: list[float] = []
    total_critical = 0

    for company in companies:
        score, scan = _latest_score(db, company.id)
        previous = _previous_score(db, company.id, score) if score else None
        critical = high = open_remediations = 0
        if scan:
            counts = db.execute(
                select(Finding.severity, func.count())
                .where(Finding.scan_id == scan.id, Finding.excluded_from_rating.is_(False))
                .group_by(Finding.severity)).all()
            mapping = {severity: count for severity, count in counts}
            critical = mapping.get("critical", 0)
            high = mapping.get("high", 0)
            open_remediations = db.execute(
                select(func.count()).select_from(Finding)
                .where(Finding.scan_id == scan.id, Finding.resolved_at.is_(None),
                       Finding.applied_deduction > 0)).scalar_one()
        if score:
            scores.append(score.overall_score)
        total_critical += critical

        cards.append(DashboardCompanyCard(
            company_id=str(company.id), company_name=company.legal_name,
            overall_score=score.overall_score if score else None,
            rating_class=score.rating_class if score else None,
            confidence=score.confidence.confidence_value if score and score.confidence else None,
            is_provisional=bool(score and score.is_provisional),
            score_delta=(round(score.overall_score - previous.overall_score, 2)
                         if score and previous else None),
            critical_findings=critical, high_findings=high,
            open_remediations=open_remediations,
            last_scan_at=scan.finished_at if scan else None,
            next_scan_due_at=company.next_scan_due_at,
            scan_status=scan.status if scan else None))

    return PortfolioView(
        companies=cards, total_companies=len(cards),
        average_score=round(sum(scores) / len(scores), 1) if scores else None,
        companies_below_c=sum(1 for c in cards if c.rating_class in {"D", "E"}),
        total_critical_findings=total_critical, generated_at=datetime.now(UTC))


@router.get("/scans/{scan_id}/score")
def get_score(scan_id: uuid.UUID, db: DbDep, current: CurrentUserDep) -> dict:
    """Punteggio completo con tracciabilita' del calcolo."""
    score = db.execute(
        select(Score).where(Score.scan_id == scan_id,
                            Score.tenant_id == current.tenant_id)).scalar_one_or_none()
    if score is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "Punteggio non disponibile per questa scansione")
    return {
        "scan_id": str(score.scan_id),
        "overall_score": score.overall_score,
        "rating_class": score.rating_class,
        "rating_label_it": _class_label(score.rating_class),
        "raw_weighted_score": score.raw_weighted_score,
        "cap_applied": score.cap_applied,
        "applied_caps": score.applied_caps_json or [],
        "is_provisional": score.is_provisional,
        "provisional_reason": score.provisional_reason,
        "scoring_config_version": score.scoring_config_version,
        "computed_at": score.computed_at.isoformat(),
        "categories": [
            {"key": c.category_key, "label_it": c.label_it, "label_en": c.label_en,
             "weight": c.weight, "score": c.score, "total_deduction": c.total_deduction,
             "finding_count": c.finding_count, "critical_count": c.critical_count,
             "high_count": c.high_count, "deductions": c.deduction_breakdown_json or []}
            for c in score.categories],
        "confidence": {
            "value": score.confidence.confidence_value,
            "label_it": score.confidence.label_it,
            "is_publishable": score.confidence.is_publishable,
            "factors": score.confidence.factors_json,
            "penalties": score.confidence.penalties_json,
            "coverage_matrix": score.confidence.coverage_matrix_json,
        } if score.confidence else None,
        "calculation_trace": score.calculation_trace_json,
    }
