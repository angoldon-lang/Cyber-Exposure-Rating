"""Normalizzazione, correlazione e deduplicazione delle evidenze.

Trasforma le evidenze grezze prodotte dagli adapter in:
  * asset con ownership determinata;
  * evidenze normalizzate persistibili;
  * finding deduplicati (l'unita' su cui operano scoring e revisione).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable, Sequence

from adapters.base import AdapterResult, DiscoveredAsset, NormalizedEvidence
from app.core.logging import get_logger
from app.models.enums import CONFIDENCE_RANK, SEVERITY_RANK, ConfidenceClass, OwnershipStatus
from app.services.ownership import OwnershipContext, OwnershipDecision, classify_asset

logger = get_logger(__name__)


@dataclass
class ResolvedAsset:
    asset_key: str
    asset_type: str
    display_name: str
    ownership: OwnershipDecision
    discovered_by: list[str] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    is_internet_facing: bool = True

    @property
    def scores_toward_rating(self) -> bool:
        return self.ownership.status in {OwnershipStatus.VERIFIED_OWNED.value,
                                         OwnershipStatus.LIKELY_OWNED.value}


@dataclass
class CorrelatedFinding:
    """Finding deduplicato: piu' evidenze dello stesso problema convergono qui."""

    fingerprint: str
    finding_type: str
    title: str
    description: str
    category: str
    severity: str
    confidence_class: str
    ownership_status: str
    asset_key: str
    detail: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    cisa_kev: bool = False
    internet_facing: bool = True
    event_date: datetime | None = None
    first_seen_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    sources: list[str] = field(default_factory=list)
    evidence_fingerprints: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    reference_code: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint, "reference_code": self.reference_code,
            "finding_type": self.finding_type, "title": self.title,
            "description": self.description, "category": self.category,
            "severity": self.severity, "confidence_class": self.confidence_class,
            "ownership_status": self.ownership_status, "asset_key": self.asset_key,
            "detail": self.detail, "cve_id": self.cve_id, "cvss_score": self.cvss_score,
            "epss_score": self.epss_score, "cisa_kev": self.cisa_kev,
            "internet_facing": self.internet_facing,
            "event_date": self.event_date.isoformat() if self.event_date else None,
            "sources": self.sources, "evidence_count": len(self.evidence_fingerprints),
        }


@dataclass
class NormalizationOutput:
    assets: list[ResolvedAsset]
    evidences: list[NormalizedEvidence]
    findings: list[CorrelatedFinding]
    stats: dict[str, Any]


CATEGORY_PREFIX: dict[str, str] = {
    "attack_surface": "AS",
    "technical_vulnerabilities": "VU",
    "web_security": "WEB",
    "email_dns_security": "EML",
    "darkweb_breach": "DW",
}


class NormalizationService:
    """Pipeline: `Detected -> Normalized -> Correlated`."""

    def __init__(self, ownership_context: OwnershipContext) -> None:
        self.ownership_context = ownership_context

    # ------------------------------------------------------------------
    def run(self, results: Sequence[AdapterResult], *,
            now: datetime | None = None) -> NormalizationOutput:
        now = now or datetime.now(UTC)
        assets = self._resolve_assets(chain_assets(results))
        evidences = [e for result in results for e in result.evidences]
        findings = self._correlate(evidences, assets, now)
        return NormalizationOutput(
            assets=list(assets.values()), evidences=evidences, findings=findings,
            stats={
                "adapters": len(results),
                "assets_discovered": len(assets),
                "assets_scoring": sum(1 for a in assets.values() if a.scores_toward_rating),
                "evidences_raw": len(evidences),
                "findings_after_dedup": len(findings),
                "dedup_ratio": round(1 - (len(findings) / len(evidences)), 3) if evidences else 0.0,
            })

    # ------------------------------------------------------------------
    def _resolve_assets(self, discovered: Iterable[DiscoveredAsset]) -> dict[str, ResolvedAsset]:
        """Unisce gli asset scoperti da piu' tool e ne determina l'ownership."""
        merged: dict[str, ResolvedAsset] = {}
        for item in discovered:
            existing = merged.get(item.asset_key)
            if existing is None:
                decision = classify_asset(item.asset_key, item.asset_type, self.ownership_context)
                merged[item.asset_key] = ResolvedAsset(
                    asset_key=item.asset_key, asset_type=item.asset_type,
                    display_name=item.display_name, ownership=decision,
                    discovered_by=[item.discovered_by],
                    technologies=list(item.technologies), attributes=dict(item.attributes),
                    relationships=list(item.relationships),
                    is_internet_facing=item.is_internet_facing)
                continue
            if item.discovered_by not in existing.discovered_by:
                existing.discovered_by.append(item.discovered_by)
            existing.attributes.update(item.attributes)
            existing.relationships.extend(item.relationships)
            known = {(t.get("name"), t.get("version")) for t in existing.technologies}
            for technology in item.technologies:
                if (technology.get("name"), technology.get("version")) not in known:
                    existing.technologies.append(technology)
        return merged

    # ------------------------------------------------------------------
    def _correlate(self, evidences: Sequence[NormalizedEvidence],
                   assets: dict[str, ResolvedAsset],
                   now: datetime) -> list[CorrelatedFinding]:
        """Raggruppa le evidenze per fingerprint e ne fonde gli attributi.

        Quando piu' tool rilevano lo stesso problema si tiene la classificazione
        PIU' FORTE (severita' e confidence massime), ma il finding resta uno:
        e' cosi' che si evita la doppia penalizzazione nello scoring.
        """
        buckets: dict[str, list[NormalizedEvidence]] = defaultdict(list)
        for evidence in evidences:
            buckets[evidence.fingerprint].append(evidence)

        findings: list[CorrelatedFinding] = []
        counters: dict[str, int] = defaultdict(int)

        for fingerprint in sorted(buckets):
            group = buckets[fingerprint]
            best = max(group, key=lambda e: (SEVERITY_RANK.get(e.severity, 0),
                                             CONFIDENCE_RANK.get(e.confidence_class, 0)))
            asset_key = best.asset_key or best.target
            asset = assets.get(asset_key)
            ownership = (asset.ownership.status if asset
                         else classify_asset(asset_key, "domain", self.ownership_context).status)

            severity = max((e.severity for e in group), key=lambda s: SEVERITY_RANK.get(s, 0))
            confidence = max((e.confidence_class for e in group),
                             key=lambda c: CONFIDENCE_RANK.get(c, 0))
            cvss = max((e.cvss_score for e in group if e.cvss_score is not None), default=None)
            epss = max((e.epss_score for e in group if e.epss_score is not None), default=None)
            event_dates = [e.event_date for e in group if e.event_date]

            category = best.category
            counters[category] += 1
            reference_code = f"{CATEGORY_PREFIX.get(category, 'GEN')}-{counters[category]:03d}"

            merged_attributes: dict[str, Any] = {}
            for evidence in group:
                merged_attributes.update(evidence.attributes or {})

            findings.append(CorrelatedFinding(
                fingerprint=fingerprint, reference_code=reference_code,
                finding_type=best.finding_type, title=best.title,
                description=best.description or "", category=category,
                severity=severity, confidence_class=confidence, ownership_status=ownership,
                asset_key=asset_key, detail=best.detail,
                cve_id=best.cve_id, cvss_score=cvss, epss_score=epss,
                cisa_kev=any(e.cisa_kev for e in group),
                internet_facing=asset.is_internet_facing if asset else True,
                event_date=min(event_dates) if event_dates else None,
                first_seen_at=min(e.observed_at for e in group),
                last_seen_at=max(e.observed_at for e in group),
                sources=sorted({e.tool for e in group}),
                evidence_fingerprints=[e.fingerprint for e in group],
                attributes=merged_attributes))
        return findings


def chain_assets(results: Sequence[AdapterResult]) -> list[DiscoveredAsset]:
    return [asset for result in results for asset in result.assets]


def collect_technologies(assets: Iterable[ResolvedAsset]) -> list[dict[str, Any]]:
    """Estrae le tecnologie osservate per l'arricchimento con la vuln intelligence."""
    observations: list[dict[str, Any]] = []
    for asset in assets:
        if not asset.scores_toward_rating:
            continue
        for technology in asset.technologies:
            observations.append({
                "name": technology.get("name"),
                "version": technology.get("version"),
                "source": technology.get("source", "httpx-tech-detect"),
                "asset_key": asset.asset_key,
                "confidence": float(technology.get("confidence", 0.85)),
            })
    return observations


def content_fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(p.lower() for p in parts).encode("utf-8")).hexdigest()


def evidence_is_publishable(evidence: NormalizedEvidence) -> bool:
    """Le evidenze puramente informative non entrano nel calcolo del rating."""
    return evidence.confidence_class not in {ConfidenceClass.FALSE_POSITIVE.value,
                                             ConfidenceClass.RESOLVED.value}
