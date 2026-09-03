"""Confronto fra scansioni e gestione temporale dei finding (sezione 14).

Regola fondamentale: la SPARIZIONE di un finding non ne comporta la chiusura
automatica. Serve una seconda verifica (o la validazione di un analista) prima
di considerarlo risolto: un tool che fallisce non deve migliorare il rating.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable, Sequence

# Numero di scansioni consecutive senza il finding prima della chiusura automatica.
MISSING_CONFIRMATIONS_REQUIRED = 2


@dataclass
class FindingSnapshot:
    fingerprint: str
    reference_code: str
    title: str
    category: str
    severity: str
    asset_key: str
    finding_type: str
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None = None
    missing_confirmations: int = 0


@dataclass
class AssetSnapshot:
    asset_key: str
    asset_type: str
    ownership_status: str
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class ScanDiff:
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = field(default_factory=list)
    pending_closure: list[dict[str, Any]] = field(default_factory=list)
    reopened_findings: list[dict[str, Any]] = field(default_factory=list)
    persisting_findings: list[dict[str, Any]] = field(default_factory=list)
    new_assets: list[dict[str, Any]] = field(default_factory=list)
    disappeared_assets: list[dict[str, Any]] = field(default_factory=list)
    score_delta: float | None = None
    previous_score: float | None = None
    current_score: float | None = None
    previous_class: str | None = None
    current_class: str | None = None
    confidence_delta: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "pending_closure": self.pending_closure,
            "reopened_findings": self.reopened_findings,
            "persisting_count": len(self.persisting_findings),
            "new_assets": self.new_assets,
            "disappeared_assets": self.disappeared_assets,
            "score_delta": self.score_delta,
            "previous_score": self.previous_score,
            "current_score": self.current_score,
            "previous_class": self.previous_class,
            "current_class": self.current_class,
            "confidence_delta": self.confidence_delta,
            "summary_it": self.summary_it(),
        }

    def summary_it(self) -> str:
        if self.previous_score is None:
            return "Prima scansione: nessun confronto disponibile."
        delta = self.score_delta or 0.0
        direction = ("in miglioramento" if delta > 0 else
                     "in peggioramento" if delta < 0 else "stabile")
        return (
            f"Rating {direction} di {abs(delta):.1f} punti rispetto alla scansione precedente "
            f"({self.previous_score:.1f} -> {self.current_score:.1f}). "
            f"Nuovi rilievi: {len(self.new_findings)}; risolti: {len(self.resolved_findings)}; "
            f"in attesa di conferma della chiusura: {len(self.pending_closure)}. "
            f"Nuovi asset: {len(self.new_assets)}; asset non piu' osservati: "
            f"{len(self.disappeared_assets)}."
        )


def diff_findings(previous: Sequence[FindingSnapshot], current: Sequence[FindingSnapshot],
                  *, now: datetime | None = None) -> ScanDiff:
    now = now or datetime.now(UTC)
    diff = ScanDiff()
    previous_by_fp = {f.fingerprint: f for f in previous}
    current_by_fp = {f.fingerprint: f for f in current}

    for fingerprint, finding in current_by_fp.items():
        earlier = previous_by_fp.get(fingerprint)
        entry = {"fingerprint": fingerprint, "reference_code": finding.reference_code,
                 "title": finding.title, "severity": finding.severity,
                 "category": finding.category, "asset_key": finding.asset_key}
        if earlier is None:
            diff.new_findings.append(entry)
        elif earlier.resolved_at is not None:
            # Riapertura: il problema era stato chiuso e si ripresenta.
            diff.reopened_findings.append({**entry,
                                           "previously_resolved_at": earlier.resolved_at.isoformat()})
        else:
            diff.persisting_findings.append(entry)

    for fingerprint, finding in previous_by_fp.items():
        if fingerprint in current_by_fp or finding.resolved_at is not None:
            continue
        confirmations = finding.missing_confirmations + 1
        entry = {"fingerprint": fingerprint, "reference_code": finding.reference_code,
                 "title": finding.title, "severity": finding.severity,
                 "category": finding.category, "asset_key": finding.asset_key,
                 "missing_confirmations": confirmations,
                 "required_confirmations": MISSING_CONFIRMATIONS_REQUIRED}
        if confirmations >= MISSING_CONFIRMATIONS_REQUIRED:
            diff.resolved_findings.append({**entry, "resolved_at": now.isoformat()})
        else:
            # Una sola assenza non basta: potrebbe essere un tool fallito.
            entry["note_it"] = ("il rilievo non e' stato osservato in questa scansione: "
                                "serve una seconda verifica prima della chiusura")
            diff.pending_closure.append(entry)
    return diff


def diff_assets(previous: Sequence[AssetSnapshot], current: Sequence[AssetSnapshot],
                diff: ScanDiff | None = None) -> ScanDiff:
    diff = diff or ScanDiff()
    previous_keys = {a.asset_key: a for a in previous}
    current_keys = {a.asset_key: a for a in current}

    for key, asset in current_keys.items():
        if key not in previous_keys:
            diff.new_assets.append({"asset_key": key, "asset_type": asset.asset_type,
                                    "ownership_status": asset.ownership_status})
    for key, asset in previous_keys.items():
        if key not in current_keys:
            diff.disappeared_assets.append({
                "asset_key": key, "asset_type": asset.asset_type,
                "last_seen_at": asset.last_seen_at.isoformat(),
                "note_it": ("asset non piu' osservato: verificare se e' stato dismesso "
                            "o se la rilevazione e' incompleta")})
    return diff


def apply_score_delta(diff: ScanDiff, *, previous_score: float | None, current_score: float,
                      previous_class: str | None, current_class: str,
                      previous_confidence: float | None = None,
                      current_confidence: float | None = None) -> ScanDiff:
    diff.previous_score = previous_score
    diff.current_score = current_score
    diff.previous_class = previous_class
    diff.current_class = current_class
    if previous_score is not None:
        diff.score_delta = round(current_score - previous_score, 2)
    if previous_confidence is not None and current_confidence is not None:
        diff.confidence_delta = round(current_confidence - previous_confidence, 2)
    return diff


def compute_temporal_flags(findings: Iterable[FindingSnapshot], *,
                           now: datetime | None = None) -> dict[str, Any]:
    """Metriche temporali usate dalla dashboard e dal report."""
    now = now or datetime.now(UTC)
    ages: list[float] = []
    recent = 0
    for finding in findings:
        reference = finding.first_seen_at
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=UTC)
        age = (now - reference).days
        ages.append(age)
        if age <= 30:
            recent += 1
    return {
        "average_age_days": round(sum(ages) / len(ages), 1) if ages else 0.0,
        "oldest_age_days": max(ages) if ages else 0,
        "appeared_last_30_days": recent,
    }
