"""Scansioni, esecuzioni dei tool, evidenze, finding e vulnerabilita'."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import GUID, Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, tenant_column
from app.models.enums import (
    AnalystValidation,
    ConfidenceClass,
    FindingWorkflowState,
    OwnershipStatus,
    ScanStatus,
    Severity,
    ToolRunStatus,
)


class ScanProfile(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Profilo di scansione persistito (rispecchia config/tool_profiles.yaml)."""

    __tablename__ = "scan_profiles"

    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    label_it: Mapped[str] = mapped_column(String(128), nullable=False)
    label_en: Mapped[str] = mapped_column(String(128), nullable=False)
    requires_verification: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_authorization: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_explicit_scope_whitelist: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allowed_tools_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    forbidden_actions_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    description_it: Mapped[str | None] = mapped_column(Text)


class Scan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    profile_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("authorizations.id", ondelete="SET NULL"))

    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.PENDING.value, nullable=False, index=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_stage: Mapped[str | None] = mapped_column(String(64))

    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"))
    celery_task_id: Mapped[str | None] = mapped_column(String(128), index=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Snapshot immutabile del perimetro e della configurazione al momento del lancio.
    scope_snapshot_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)
    scoring_config_version: Mapped[str | None] = mapped_column(String(32))
    tool_config_version: Mapped[str | None] = mapped_column(String(32))
    mock_mode: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    error_message: Mapped[str | None] = mapped_column(Text)
    stats_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)
    previous_scan_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="SET NULL"))

    company: Mapped["Company"] = relationship(back_populates="scans")  # noqa: F821
    tool_runs: Mapped[list["ToolRun"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    evidences: Mapped[list["Evidence"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    @property
    def is_terminal(self) -> bool:
        return self.status in {ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value,
                               ScanStatus.FAILED.value, ScanStatus.CANCELLED.value}


class ToolRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Esecuzione di un singolo adapter. Il fallimento di un ToolRun non
    interrompe la scansione: riduce la copertura e quindi la confidence."""

    __tablename__ = "tool_runs"

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    tool_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_version: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default=ToolRunStatus.PENDING.value, nullable=False)
    target_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    timeout_seconds: Mapped[int | None] = mapped_column(Integer)
    exit_code: Mapped[int | None] = mapped_column(Integer)

    error_message: Mapped[str | None] = mapped_column(Text)
    # Quanto pesa questo fallimento sulla copertura complessiva (0.0 - 1.0).
    coverage_impact: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    was_mocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    config_snapshot_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)
    raw_output_ref: Mapped[str | None] = mapped_column(String(512))
    raw_output_sha256: Mapped[str | None] = mapped_column(String(64))
    raw_output_bytes: Mapped[int | None] = mapped_column(Integer)

    scan: Mapped[Scan] = relationship(back_populates="tool_runs")


class Evidence(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Evidenza normalizzata (sezione 11). Immutabile una volta scritta."""

    __tablename__ = "evidences"

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("tool_runs.id", ondelete="SET NULL"))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("assets.id", ondelete="SET NULL"), index=True)

    tool: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_version: Mapped[str | None] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    data_source: Mapped[str] = mapped_column(String(128), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024))
    raw_evidence_ref: Mapped[str | None] = mapped_column(String(512))

    finding_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default=Severity.INFO.value, nullable=False)
    confidence_class: Mapped[str] = mapped_column(
        String(32), default=ConfidenceClass.INFERRED.value, nullable=False, index=True)
    ownership_status: Mapped[str] = mapped_column(
        String(32), default=OwnershipStatus.UNVERIFIED.value, nullable=False)

    detail: Mapped[str | None] = mapped_column(String(512))
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    epss_score: Mapped[float | None] = mapped_column(Float)
    cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # data dell'evento (breach, post)

    attributes_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)
    sanitized: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="evidences")


class Vulnerability(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Cache locale dell'intelligence su una CVE (NVD/EUVD + KEV + EPSS)."""

    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_v4_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(16))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    in_cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cpe_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    references_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    source: Mapped[str | None] = mapped_column(String(64))
    last_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Remediation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Voce del catalogo remediation (config/remediation_catalog.yaml)."""

    __tablename__ = "remediations"

    catalog_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    title_it: Mapped[str] = mapped_column(String(512), nullable=False)
    title_en: Mapped[str | None] = mapped_column(String(512))
    area: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(8), nullable=False)
    effort: Mapped[str] = mapped_column(String(8), nullable=False)
    skills_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    risk_mitigated_it: Mapped[str | None] = mapped_column(Text)
    immediate_action_it: Mapped[str | None] = mapped_column(Text)
    structural_solution_it: Mapped[str | None] = mapped_column(Text)
    verification_it: Mapped[str | None] = mapped_column(Text)
    references_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    # Separato dalla raccomandazione tecnica (sezione 18).
    commercial_services_json: Mapped[list | None] = mapped_column(JSONType, default=list)


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Finding correlato e deduplicato: l'unita' su cui opera lo scoring
    e su cui lavora il revisore."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "scan_id", "fingerprint", name="uq_finding_scan_fingerprint"),
    )

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    remediation_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("remediations.id", ondelete="SET NULL"))

    reference_code: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence_class: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    ownership_status: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[str | None] = mapped_column(String(512))

    workflow_state: Mapped[str] = mapped_column(
        String(32), default=FindingWorkflowState.DETECTED.value, nullable=False, index=True)
    analyst_validation: Mapped[str] = mapped_column(
        String(32), default=AnalystValidation.NOT_REVIEWED.value, nullable=False, index=True)
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_notes: Mapped[str | None] = mapped_column(Text)
    excluded_from_rating: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exclusion_reason: Mapped[str | None] = mapped_column(Text)
    retest_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Una sparizione non chiude il finding: richiede una seconda conferma (sezione 14).
    missing_confirmations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Tracciamento dello scoring: quali regole hanno colpito e con quale detrazione.
    applied_rules_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    applied_deduction: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence_ids_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    sources_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    attributes_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="findings")

    @property
    def is_active_for_rating(self) -> bool:
        if self.excluded_from_rating:
            return False
        if self.analyst_validation in {
            AnalystValidation.REJECTED_FALSE_POSITIVE.value,
            AnalystValidation.ACCEPTED_RISK.value,
            AnalystValidation.EXCLUDED_FROM_RATING.value,
        }:
            return False
        return self.confidence_class not in {
            ConfidenceClass.FALSE_POSITIVE.value,
            ConfidenceClass.RESOLVED.value,
            ConfidenceClass.ACCEPTED_RISK.value,
        }
