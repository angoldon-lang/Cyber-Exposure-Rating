"""Schemi per scansioni, finding, punteggi e report."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.enums import ReportFormat, ReportType, ScanProfileType
from app.schemas.common import ORMModel


class ScanCreate(BaseModel):
    profile: ScanProfileType = ScanProfileType.PUBLIC_PASSIVE
    dkim_selectors: list[str] = Field(default_factory=list, max_length=20)
    # Header e-mail opzionale: viene sanitizzato e non conservato integralmente.
    email_header: str | None = Field(default=None, max_length=200_000)
    notes: str | None = None


class ToolRunRead(ORMModel):
    id: uuid.UUID
    tool_key: str
    tool_version: str | None
    status: str
    target_count: int
    evidence_count: int
    duration_seconds: float | None
    error_message: str | None
    coverage_impact: float
    was_mocked: bool


class ScanRead(ORMModel):
    id: uuid.UUID
    company_id: uuid.UUID
    profile_key: str
    status: str
    progress_percent: int
    current_stage: str | None
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    mock_mode: bool
    scoring_config_version: str | None
    stats_json: dict[str, Any] | None
    previous_scan_id: uuid.UUID | None
    created_at: datetime


class ScanDetail(ScanRead):
    tool_runs: list[ToolRunRead] = Field(default_factory=list)


class ScanAuthorizationPreview(BaseModel):
    """Esito del gate di autorizzazione, senza avviare la scansione."""

    profile: str
    allowed: bool
    reasons: list[str]
    authorization_id: str | None = None
    expires_at: datetime | None = None
    tools_planned: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)


class ScoreCategoryRead(ORMModel):
    category_key: str
    label_it: str
    label_en: str | None
    weight: float
    score: float
    total_deduction: float
    finding_count: int
    critical_count: int
    high_count: int


class ConfidenceRead(ORMModel):
    confidence_value: float
    label_it: str
    label_en: str | None
    is_publishable: bool
    factors_json: dict[str, Any] | None
    penalties_json: list | None
    coverage_matrix_json: list | None


class ScoreRead(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    overall_score: float
    rating_class: str
    raw_weighted_score: float
    cap_applied: bool
    applied_caps_json: list | None
    scoring_config_version: str
    is_provisional: bool
    provisional_reason: str | None
    computed_at: datetime
    categories: list[ScoreCategoryRead] = Field(default_factory=list)
    confidence: ConfidenceRead | None = None


class FindingRead(ORMModel):
    id: uuid.UUID
    reference_code: str
    finding_type: str
    title: str
    description: str | None
    category: str
    severity: str
    confidence_class: str
    ownership_status: str
    detail: str | None
    workflow_state: str
    analyst_validation: str
    excluded_from_rating: bool
    retest_requested: bool
    cve_id: str | None
    cvss_score: float | None
    epss_score: float | None
    cisa_kev: bool
    internet_facing: bool
    first_seen_at: datetime
    last_seen_at: datetime
    event_date: datetime | None
    resolved_at: datetime | None
    applied_deduction: float
    sources_json: list | None
    asset_id: uuid.UUID | None
    # Senza il nome dell'asset il rilievo non e' verificabile: `asset_id` da solo
    # e' un identificativo opaco. `attributes_json` porta i dettagli osservati
    # (porta, header, versione rilevata) che servono a riprodurre la verifica.
    asset_display: str | None = None
    attributes_json: dict | None = None
    evidence_summary: str | None = None
    # Identificativo di catalogo e titolo dell'intervento collegato: senza,
    # dal rilievo non si raggiunge la remediation e resta al lettore ricordare
    # quale voce del piano lo riguarda.
    remediation_catalog_id: str | None = None
    remediation_title_it: str | None = None


class FindingReview(BaseModel):
    action: Literal["confirm", "reclassify", "false_positive", "accept_risk",
                    "exclude_from_rating", "request_retest", "reopen"]
    reason: str | None = Field(default=None, max_length=4000)
    new_severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    new_confidence: Literal["confirmed", "probable", "inferred", "informational"] | None = None


class ReviewProgress(BaseModel):
    total: int
    reviewed: int
    pending: int
    critical_high_total: int
    critical_high_reviewed: int
    critical_high_pending: int
    ready_for_final_report: bool
    progress_percent: float


class RemediationItemRead(BaseModel):
    catalog_id: str
    title_it: str
    area: str
    priority: str
    effort: str
    skills: list[str]
    risk_mitigated_it: str
    immediate_action_it: str
    structural_solution_it: str
    verification_it: str
    references: list[str]
    commercial_services: list[str]
    finding_codes: list[str]
    max_severity: str
    affected_asset_count: int
    is_quick_win: bool


class ReportCreate(BaseModel):
    report_type: ReportType = ReportType.COMBINED
    language: Literal["it", "en"] = "it"
    formats: list[ReportFormat] = Field(default=[ReportFormat.PDF, ReportFormat.DOCX])
    is_final: bool = True


class ReportVersionRead(ORMModel):
    id: uuid.UUID
    version: int
    format: str
    file_sha256: str | None
    file_bytes: int | None
    generated_at: datetime


class ReportRead(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    report_type: str
    language: str
    status: str
    title: str
    approved_at: datetime | None
    error_message: str | None
    created_at: datetime
    versions: list[ReportVersionRead] = Field(default_factory=list)


class ScanComparison(BaseModel):
    previous_scan_id: str | None
    current_scan_id: str
    previous_score: float | None
    current_score: float
    score_delta: float | None
    previous_class: str | None
    current_class: str
    confidence_delta: float | None
    new_findings: list[dict[str, Any]]
    resolved_findings: list[dict[str, Any]]
    pending_closure: list[dict[str, Any]]
    reopened_findings: list[dict[str, Any]]
    new_assets: list[dict[str, Any]]
    disappeared_assets: list[dict[str, Any]]
    summary_it: str


class DashboardCompanyCard(BaseModel):
    company_id: str
    company_name: str
    overall_score: float | None
    rating_class: str | None
    confidence: float | None
    is_provisional: bool
    score_delta: float | None
    critical_findings: int
    high_findings: int
    open_remediations: int
    last_scan_at: datetime | None
    next_scan_due_at: datetime | None
    scan_status: str | None


class PortfolioView(BaseModel):
    companies: list[DashboardCompanyCard]
    total_companies: int
    average_score: float | None
    companies_below_c: int
    total_critical_findings: int
    generated_at: datetime


class DashboardOverview(BaseModel):
    company_id: str
    company_name: str
    overall_score: float | None
    rating_class: str | None
    rating_label_it: str | None
    confidence: float | None
    confidence_label_it: str | None
    is_provisional: bool
    provisional_notice: str | None
    categories: list[dict[str, Any]]
    severity_counts: dict[str, int]
    trend: list[dict[str, Any]]
    assets: dict[str, int]
    email_posture: dict[str, Any]
    darkweb: dict[str, Any]
    # Strumenti non eseguiti, con il motivo. Senza questo elenco un'area vuota
    # e' indistinguibile da un'area controllata e risultata pulita: il rating
    # e' alto in entrambi i casi, ma significano cose opposte.
    coverage_gaps: list[dict[str, Any]] = []
    # Quanti indirizzi IP pubblici sono stati individuati, quanti sono
    # autorizzati alla scansione attiva e quanti appartengono a
    # infrastruttura condivisa di terzi. Un port scanning senza risultati
    # perche' nessun indirizzo e' autorizzato non e' un port scanning pulito.
    ip_perimeter: dict[str, Any] = {}
    review_progress: dict[str, Any]
    last_scan: dict[str, Any] | None
    open_remediations: int
    scope_disclaimer_it: str
