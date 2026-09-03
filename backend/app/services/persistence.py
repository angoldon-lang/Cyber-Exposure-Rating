"""Persistenza dei risultati di una scansione.

Separata dalla pipeline: la pipeline calcola, questo modulo scrive.
Cosi' la pipeline resta testabile senza database.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import FindingWorkflowState
from app.models.scanning import Evidence, Finding, Remediation, Scan, ToolRun
from app.models.scope import Asset
from app.models.scoring import ConfidenceScore, Score, ScoreCategory
from app.services.remediation import catalog, remediation_for_finding
from app.workers.pipeline import ScanOutcome, store_raw_output

logger = get_logger(__name__)


def sync_remediation_catalog(db: Session) -> int:
    """Allinea la tabella `remediations` al catalogo YAML versionato."""
    written = 0
    for catalog_id, entry in catalog().items():
        row = db.execute(
            select(Remediation).where(Remediation.catalog_id == catalog_id)).scalar_one_or_none()
        if row is None:
            row = Remediation(catalog_id=catalog_id)
            db.add(row)
            written += 1
        row.title_it = str(entry["title_it"])
        row.title_en = entry.get("title_en")
        row.area = str(entry["area"])
        row.priority = str(entry["priority"])
        row.effort = str(entry["effort"])
        row.skills_json = list(entry.get("skills", []))
        row.risk_mitigated_it = str(entry.get("risk_mitigated_it", "")).strip()
        row.immediate_action_it = str(entry.get("immediate_action_it", "")).strip()
        row.structural_solution_it = str(entry.get("structural_solution_it", "")).strip()
        row.verification_it = str(entry.get("verification_it", "")).strip()
        row.references_json = list(entry.get("references", []))
        row.commercial_services_json = list(entry.get("commercial_services", []))
    db.flush()
    return written


def persist_outcome(db: Session, scan: Scan, outcome: ScanOutcome) -> Score:
    """Scrive asset, tool run, evidenze, finding e punteggi."""
    now = datetime.now(UTC)
    sync_remediation_catalog(db)
    remediation_ids = {
        row.catalog_id: row.id
        for row in db.execute(select(Remediation)).scalars().all()
    }

    asset_ids = _persist_assets(db, scan, outcome, now)
    tool_run_ids = _persist_tool_runs(db, scan, outcome)
    _persist_evidences(db, scan, outcome, asset_ids, tool_run_ids, now)
    _persist_findings(db, scan, outcome, asset_ids, remediation_ids, now)
    score = _persist_score(db, scan, outcome, now)

    scan.status = outcome.status
    scan.progress_percent = 100
    scan.current_stage = "completed"
    scan.finished_at = now
    scan.stats_json = outcome.stats
    scan.scoring_config_version = outcome.scoring.config_version
    db.flush()
    return score


# ---------------------------------------------------------------------------
def _persist_assets(db: Session, scan: Scan, outcome: ScanOutcome,
                    now: datetime) -> dict[str, uuid.UUID]:
    """Aggiorna gli asset esistenti e crea i nuovi, mantenendo `first_seen`."""
    existing = {
        row.asset_key: row
        for row in db.execute(
            select(Asset).where(Asset.company_id == scan.company_id)).scalars().all()
    }
    seen: set[str] = set()
    ids: dict[str, uuid.UUID] = {}

    for resolved in outcome.normalization.assets:
        seen.add(resolved.asset_key)
        row = existing.get(resolved.asset_key)
        if row is None:
            row = Asset(tenant_id=scan.tenant_id, company_id=scan.company_id,
                        asset_key=resolved.asset_key, asset_type=resolved.asset_type,
                        display_name=resolved.display_name, first_seen_at=now)
            db.add(row)
        row.display_name = resolved.display_name
        row.asset_type = resolved.asset_type
        row.ownership_status = resolved.ownership.status
        row.ownership_reason = resolved.ownership.reason
        row.ownership_confidence = resolved.ownership.confidence
        row.is_cdn_fronted = resolved.ownership.is_cdn_fronted
        row.is_third_party_hosted = resolved.ownership.is_third_party_hosted
        row.is_internet_facing = resolved.is_internet_facing
        row.technologies_json = resolved.technologies
        row.attributes_json = resolved.attributes
        row.discovered_by_json = resolved.discovered_by
        row.last_seen_at = now
        row.disappeared_at = None
        db.flush()
        ids[resolved.asset_key] = row.id

    # Un asset non piu' osservato viene marcato, NON cancellato.
    for asset_key, row in existing.items():
        if asset_key not in seen and row.disappeared_at is None:
            row.disappeared_at = now
    db.flush()
    return ids


def _persist_tool_runs(db: Session, scan: Scan, outcome: ScanOutcome) -> dict[str, uuid.UUID]:
    ids: dict[str, uuid.UUID] = {}
    for record in outcome.tool_runs:
        raw_reference: str | None = None
        raw_payload = outcome.raw_outputs.get(record["tool_key"])
        if raw_payload:
            try:
                raw_reference, _ = store_raw_output(str(scan.id), record["tool_key"], raw_payload)
            except OSError as exc:  # pragma: no cover
                logger.warning("raw_output_store_failed", tool=record["tool_key"], error=str(exc))
        run = ToolRun(
            tenant_id=scan.tenant_id, scan_id=scan.id, tool_key=record["tool_key"],
            tool_version=record.get("tool_version"), status=record["status"],
            target_count=record.get("target_count", 0),
            evidence_count=record.get("evidence_count", 0),
            duration_seconds=record.get("duration_seconds"),
            exit_code=record.get("exit_code"), error_message=record.get("error_message"),
            coverage_impact=record.get("coverage_impact", 0.0),
            was_mocked=record.get("was_mocked", False),
            config_snapshot_json=record.get("config_snapshot", {}),
            raw_output_ref=raw_reference, raw_output_sha256=record.get("raw_output_sha256"),
            raw_output_bytes=record.get("raw_output_bytes"),
            started_at=scan.started_at, finished_at=datetime.now(UTC))
        db.add(run)
        db.flush()
        ids[record["tool_key"]] = run.id
    return ids


def _persist_evidences(db: Session, scan: Scan, outcome: ScanOutcome,
                       asset_ids: dict[str, uuid.UUID], tool_run_ids: dict[str, uuid.UUID],
                       now: datetime) -> None:
    for evidence in outcome.normalization.evidences:
        asset_key = evidence.asset_key or evidence.target
        db.add(Evidence(
            tenant_id=scan.tenant_id, company_id=scan.company_id, scan_id=scan.id,
            tool_run_id=tool_run_ids.get(evidence.tool),
            asset_id=asset_ids.get(asset_key),
            tool=evidence.tool, tool_version=evidence.tool_version,
            target=evidence.target[:512], observed_at=evidence.observed_at,
            data_source=evidence.data_source, source_url=evidence.source_url,
            raw_evidence_ref=evidence.raw_evidence_ref,
            finding_type=evidence.finding_type, title=evidence.title,
            description=evidence.description, category=evidence.category,
            severity=evidence.severity, confidence_class=evidence.confidence_class,
            ownership_status=evidence.ownership_status, detail=evidence.detail,
            fingerprint=evidence.fingerprint, cve_id=evidence.cve_id,
            cvss_score=evidence.cvss_score, cvss_vector=evidence.cvss_vector,
            epss_score=evidence.epss_score, cisa_kev=evidence.cisa_kev,
            first_seen_at=evidence.observed_at, last_seen_at=evidence.observed_at,
            event_date=evidence.event_date, attributes_json=evidence.attributes,
            sanitized=True))
    db.flush()


def _persist_findings(db: Session, scan: Scan, outcome: ScanOutcome,
                      asset_ids: dict[str, uuid.UUID],
                      remediation_ids: dict[str, uuid.UUID], now: datetime) -> None:
    """Crea i finding della scansione, ereditando lo storico per fingerprint."""
    history = {
        row.fingerprint: row
        for row in db.execute(
            select(Finding).where(Finding.company_id == scan.company_id,
                                  Finding.scan_id != scan.id)
            .order_by(Finding.created_at.desc())).scalars().all()
    }
    deductions_by_finding: dict[str, list[dict[str, Any]]] = {}
    for category in outcome.scoring.categories:
        for deduction in category.deductions:
            deductions_by_finding.setdefault(deduction.finding_id, []).append(deduction.as_dict())

    for correlated in outcome.normalization.findings:
        previous = history.get(correlated.fingerprint)
        applied = deductions_by_finding.get(correlated.reference_code, [])
        remediation = remediation_for_finding(
            correlated.finding_type, [str(d["rule_id"]) for d in applied])
        db.add(Finding(
            tenant_id=scan.tenant_id, company_id=scan.company_id, scan_id=scan.id,
            asset_id=asset_ids.get(correlated.asset_key),
            remediation_id=remediation_ids.get(str(remediation["id"])) if remediation else None,
            reference_code=correlated.reference_code, fingerprint=correlated.fingerprint,
            finding_type=correlated.finding_type, title=correlated.title,
            description=correlated.description, category=correlated.category,
            severity=correlated.severity, confidence_class=correlated.confidence_class,
            ownership_status=correlated.ownership_status, detail=correlated.detail,
            workflow_state=FindingWorkflowState.SCORED.value,
            cve_id=correlated.cve_id, cvss_score=correlated.cvss_score,
            epss_score=correlated.epss_score, cisa_kev=correlated.cisa_kev,
            internet_facing=correlated.internet_facing,
            # `first_seen` viene ereditato: e' la data della PRIMA rilevazione.
            first_seen_at=previous.first_seen_at if previous else correlated.first_seen_at,
            last_seen_at=correlated.last_seen_at, event_date=correlated.event_date,
            reopened_at=now if (previous and previous.resolved_at) else None,
            applied_rules_json=applied,
            applied_deduction=sum(float(d["effective"]) for d in applied),
            evidence_ids_json=correlated.evidence_fingerprints,
            sources_json=correlated.sources, attributes_json=correlated.attributes))
    db.flush()


def _persist_score(db: Session, scan: Scan, outcome: ScanOutcome, now: datetime) -> Score:
    from app.services.confidence import PROVISIONAL_NOTICE_IT

    provisional = not outcome.confidence.is_publishable
    score = Score(
        tenant_id=scan.tenant_id, company_id=scan.company_id, scan_id=scan.id,
        overall_score=outcome.scoring.overall_score,
        rating_class=outcome.scoring.rating_class,
        raw_weighted_score=outcome.scoring.raw_weighted_score,
        cap_applied=outcome.scoring.cap_applied,
        applied_caps_json=[c.as_dict() for c in outcome.scoring.applied_caps],
        scoring_config_version=outcome.scoring.config_version,
        is_provisional=provisional,
        provisional_reason=PROVISIONAL_NOTICE_IT if provisional else None,
        computed_at=now, calculation_trace_json=outcome.scoring.trace)
    db.add(score)
    db.flush()

    for category in outcome.scoring.categories:
        db.add(ScoreCategory(
            tenant_id=scan.tenant_id, score_id=score.id, category_key=category.key,
            label_it=category.label_it, label_en=category.label_en, weight=category.weight,
            score=category.score, total_deduction=category.total_deduction,
            finding_count=category.finding_count, critical_count=category.critical_count,
            high_count=category.high_count,
            deduction_breakdown_json=[d.as_dict() for d in category.deductions]))

    db.add(ConfidenceScore(
        tenant_id=scan.tenant_id, score_id=score.id, scan_id=scan.id,
        confidence_value=outcome.confidence.value, label_it=outcome.confidence.label_it,
        label_en=outcome.confidence.label_en, is_publishable=outcome.confidence.is_publishable,
        factors_json=outcome.confidence.factors, penalties_json=outcome.confidence.penalties,
        coverage_matrix_json=outcome.confidence.coverage_matrix, computed_at=now))
    db.flush()
    return score


def evidence_storage_ready() -> bool:
    try:
        settings.evidence_storage_path.mkdir(parents=True, exist_ok=True)
        return True
    except OSError:
        return False
