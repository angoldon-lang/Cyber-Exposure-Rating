"""Report e loro versioni."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import GUID, Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, tenant_column
from app.models.enums import ReportStatus, ReportType


class Report(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "reports"

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    report_type: Mapped[str] = mapped_column(String(32), default=ReportType.COMBINED.value, nullable=False)
    language: Mapped[str] = mapped_column(String(2), default="it", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=ReportStatus.DRAFT.value, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)

    requires_review_before_publication: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    generated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"))
    error_message: Mapped[str | None] = mapped_column(Text)

    versions: Mapped[list["ReportVersion"]] = relationship(
        back_populates="report", cascade="all, delete-orphan", lazy="selectin")


class ReportVersion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "report_versions"
    __table_args__ = (UniqueConstraint("report_id", "version", "format", name="uq_reportversion_unique"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    report_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)

    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    file_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    file_sha256: Mapped[str | None] = mapped_column(String(64))
    file_bytes: Mapped[int | None] = mapped_column(Integer)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    content_summary_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)

    report: Mapped[Report] = relationship(back_populates="versions")
