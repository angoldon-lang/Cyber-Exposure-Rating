"""Punteggi, categorie e confidence score persistiti."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import GUID, Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, tenant_column


class Score(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Risultato complessivo dello scoring per una scansione."""

    __tablename__ = "scores"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_score_scan"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    overall_score: Mapped[float] = mapped_column(Float, nullable=False)
    rating_class: Mapped[str] = mapped_column(String(2), nullable=False, index=True)
    # Punteggio prima dell'applicazione dei rating cap (tracciabilita').
    raw_weighted_score: Mapped[float] = mapped_column(Float, nullable=False)
    cap_applied: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    applied_caps_json: Mapped[list | None] = mapped_column(JSONType, default=list)

    scoring_config_version: Mapped[str] = mapped_column(String(32), nullable=False)
    is_provisional: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    provisional_reason: Mapped[str | None] = mapped_column(Text)

    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    calculation_trace_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)

    categories: Mapped[list["ScoreCategory"]] = relationship(
        back_populates="parent_score", cascade="all, delete-orphan", lazy="selectin")
    confidence: Mapped["ConfidenceScore | None"] = relationship(
        back_populates="parent_score", cascade="all, delete-orphan", uselist=False,
        lazy="selectin")


class ScoreCategory(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Punteggio di una delle cinque aree tematiche."""

    __tablename__ = "score_categories"
    __table_args__ = (UniqueConstraint("score_id", "category_key", name="uq_scorecat_score_category"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    score_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scores.id", ondelete="CASCADE"), nullable=False, index=True)

    category_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    label_it: Mapped[str] = mapped_column(String(128), nullable=False)
    label_en: Mapped[str | None] = mapped_column(String(128))
    weight: Mapped[float] = mapped_column(Float, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    total_deduction: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    deduction_breakdown_json: Mapped[list | None] = mapped_column(JSONType, default=list)

    # La colonna `score` sopra e' il punteggio dell'area: la relazione verso
    # l'entita' Score ha un nome distinto per evitare la collisione.
    parent_score: Mapped[Score] = relationship(back_populates="categories")


class ConfidenceScore(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Indice di affidabilita' e copertura dell'analisi (sezione 13).

    NON modifica il rating: ne dichiara la solidita'. Sotto la soglia
    configurata il rating viene presentato come provvisorio.
    """

    __tablename__ = "confidence_scores"
    __table_args__ = (UniqueConstraint("score_id", name="uq_confidence_score"),)

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    score_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scores.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    confidence_value: Mapped[float] = mapped_column(Float, nullable=False)
    label_it: Mapped[str] = mapped_column(String(64), nullable=False)
    label_en: Mapped[str | None] = mapped_column(String(64))
    is_publishable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    factors_json: Mapped[dict | None] = mapped_column(JSONType, default=dict)
    penalties_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    coverage_matrix_json: Mapped[list | None] = mapped_column(JSONType, default=list)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    parent_score: Mapped[Score] = relationship(back_populates="confidence")
