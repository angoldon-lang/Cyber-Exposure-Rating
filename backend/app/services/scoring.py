"""Motore di scoring deterministico.

Proprieta' garantite:
  * DETERMINISTICO: stessi finding + stessa configurazione => stesso punteggio;
  * TRACCIABILE: ogni detrazione e' motivata da una regola con un id;
  * CONFIGURABILE: nessun valore numerico e' codificato qui, tutto in YAML;
  * SEPARATO DALL'AI: nessun modello linguistico partecipa al calcolo.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable, Sequence

from app.core.config import load_yaml_config
from app.core.logging import get_logger
from app.models.enums import (
    CONFIDENCE_RANK,
    OWNERSHIP_RANK,
    AnalystValidation,
    ConfidenceClass,
    OwnershipStatus,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Input del motore: una vista minimale e immutabile di un finding.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScorableFinding:
    finding_id: str
    finding_type: str
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
    last_seen_at: datetime | None = None
    analyst_validation: str = AnalystValidation.NOT_REVIEWED.value
    excluded_from_rating: bool = False

    @property
    def is_scorable(self) -> bool:
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


@dataclass
class AppliedDeduction:
    rule_id: str
    finding_id: str
    category: str
    base_deduction: float
    confidence_multiplier: float
    ownership_multiplier: float
    decay_factor: float
    effective_deduction: float
    capped_by: str | None = None
    dedup_key: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "finding_id": self.finding_id, "category": self.category,
            "base": round(self.base_deduction, 3),
            "confidence_multiplier": self.confidence_multiplier,
            "ownership_multiplier": self.ownership_multiplier,
            "decay_factor": round(self.decay_factor, 3),
            "effective": round(self.effective_deduction, 3),
            "capped_by": self.capped_by, "dedup_key": self.dedup_key,
        }


@dataclass
class CategoryResult:
    key: str
    label_it: str
    label_en: str
    weight: float
    score: float
    total_deduction: float
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    deductions: list[AppliedDeduction] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "label_it": self.label_it, "label_en": self.label_en,
            "weight": self.weight, "score": round(self.score, 2),
            "total_deduction": round(self.total_deduction, 2),
            "finding_count": self.finding_count, "critical_count": self.critical_count,
            "high_count": self.high_count,
            "deductions": [d.as_dict() for d in self.deductions],
        }


@dataclass
class AppliedCap:
    cap_id: str
    max_score: float
    reason_it: str
    finding_id: str

    def as_dict(self) -> dict[str, Any]:
        return {"cap_id": self.cap_id, "max_score": self.max_score,
                "reason_it": self.reason_it, "finding_id": self.finding_id}


@dataclass
class ScoringResult:
    overall_score: float
    raw_weighted_score: float
    rating_class: str
    rating_label_it: str
    categories: list[CategoryResult]
    applied_caps: list[AppliedCap]
    config_version: str
    computed_at: datetime
    trace: dict[str, Any]

    @property
    def cap_applied(self) -> bool:
        return bool(self.applied_caps)

    def as_dict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "raw_weighted_score": round(self.raw_weighted_score, 2),
            "rating_class": self.rating_class,
            "rating_label_it": self.rating_label_it,
            "cap_applied": self.cap_applied,
            "applied_caps": [c.as_dict() for c in self.applied_caps],
            "categories": [c.as_dict() for c in self.categories],
            "config_version": self.config_version,
            "computed_at": self.computed_at.isoformat(),
            "trace": self.trace,
        }


# ---------------------------------------------------------------------------
class ScoringEngine:
    """Calcola il rating a partire dai finding e dalla configurazione YAML."""

    def __init__(self, config: dict[str, Any] | None = None,
                 caps_config: dict[str, Any] | None = None) -> None:
        self.config = config or load_yaml_config("scoring")
        self.caps_config = caps_config or load_yaml_config("rating_caps")
        self._validate()

    # -------------------------- validazione ------------------------------
    def _validate(self) -> None:
        weights = [c["weight"] for c in self.config["categories"].values()]
        total = sum(weights)
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(f"La somma dei pesi delle categorie deve essere 1.0, trovato {total}")
        known = set(self.config["categories"])
        for rule in self.config["rules"]:
            if rule["category"] not in known:
                raise ValueError(f"Regola {rule['id']}: categoria sconosciuta {rule['category']}")

    @property
    def version(self) -> str:
        return str(self.config.get("version", "0.0.0"))

    # -------------------------- matching ---------------------------------
    @staticmethod
    def _matches(finding: ScorableFinding, criteria: dict[str, Any]) -> bool:
        if "finding_type" in criteria and finding.finding_type != criteria["finding_type"]:
            return False
        if criteria.get("cisa_kev") is True and not finding.cisa_kev:
            return False
        if criteria.get("internet_facing") is True and not finding.internet_facing:
            return False
        if "cvss_min" in criteria:
            if finding.cvss_score is None or finding.cvss_score < float(criteria["cvss_min"]):
                return False
        if "cvss_max" in criteria:
            if finding.cvss_score is None or finding.cvss_score > float(criteria["cvss_max"]):
                return False
        if "epss_min" in criteria:
            if finding.epss_score is None or finding.epss_score < float(criteria["epss_min"]):
                return False
        return True

    def _meets_confidence(self, finding: ScorableFinding, rule: dict[str, Any]) -> bool:
        required = str(rule.get("min_confidence", ConfidenceClass.CONFIRMED.value))
        return CONFIDENCE_RANK.get(finding.confidence_class, 0) >= CONFIDENCE_RANK.get(required, 4)

    def _meets_ownership(self, finding: ScorableFinding, rule: dict[str, Any]) -> bool:
        required = str(rule.get("required_ownership", OwnershipStatus.VERIFIED_OWNED.value))
        return OWNERSHIP_RANK.get(finding.ownership_status, 0) >= OWNERSHIP_RANK.get(required, 4)

    # -------------------------- moltiplicatori ---------------------------
    def _confidence_multiplier(self, finding: ScorableFinding) -> float:
        return float(self.config["confidence_multipliers"].get(finding.confidence_class, 0.0))

    def _ownership_multiplier(self, finding: ScorableFinding) -> float:
        return float(self.config["ownership_multipliers"].get(finding.ownership_status, 0.0))

    def _decay_factor(self, finding: ScorableFinding, rule: dict[str, Any],
                      now: datetime) -> float:
        """Decadimento temporale: un vecchio breach pesa meno di uno recente."""
        profile_name = str(rule.get("decay", "default"))
        profile = self.config.get("temporal_decay", {}).get(profile_name, {"mode": "none"})
        if profile.get("mode") != "half_life":
            return 1.0
        reference = finding.event_date or finding.last_seen_at
        if reference is None:
            return 1.0
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=UTC)
        age_days = max(0.0, (now - reference).total_seconds() / 86400.0)
        half_life = float(profile.get("half_life_days", 365))
        floor = float(profile.get("floor", 0.0))
        factor = 0.5 ** (age_days / half_life) if half_life > 0 else 1.0
        return max(floor, min(1.0, factor))

    # -------------------------- calcolo ----------------------------------
    def score(self, findings: Sequence[ScorableFinding], *,
              now: datetime | None = None) -> ScoringResult:
        now = now or datetime.now(UTC)
        scorable = [f for f in findings if f.is_scorable]

        categories: dict[str, CategoryResult] = {
            key: CategoryResult(key=key, label_it=definition["label_it"],
                                label_en=definition.get("label_en", key),
                                weight=float(definition["weight"]), score=100.0,
                                total_deduction=0.0)
            for key, definition in self.config["categories"].items()
        }

        rule_totals: dict[str, float] = defaultdict(float)
        group_totals: dict[str, float] = defaultdict(float)
        seen_dedup: set[tuple[str, str]] = set()
        # (exclusive_group, finding_id) gia' penalizzati: dentro un gruppo
        # esclusivo un finding e' colpito da una sola regola, la piu' severa.
        exclusive_claimed: set[tuple[str, str]] = set()
        skipped: list[dict[str, str]] = []

        # Ordine deterministico: le regole piu' severe si applicano per prime,
        # cosi' i tetti per gruppo premiano sempre la detrazione maggiore.
        rules = sorted(self.config["rules"], key=lambda r: (-float(r["deduction"]), str(r["id"])))
        ordered_findings = sorted(scorable, key=lambda f: (f.category, f.asset_key, f.finding_id))

        for rule in rules:
            rule_id = str(rule["id"])
            category_key = str(rule["category"])
            max_rule = float(rule.get("max_deduction", rule["deduction"]))
            group = str(rule.get("root_cause_group", rule_id))
            group_cap = float(self.config.get("root_cause_caps", {}).get(group, math.inf))

            for finding in ordered_findings:
                if finding.category != category_key or not self._matches(finding, rule["match"]):
                    continue
                if not self._meets_confidence(finding, rule):
                    skipped.append({"finding_id": finding.finding_id, "rule_id": rule_id,
                                    "reason": f"confidence {finding.confidence_class} inferiore al minimo "
                                              f"{rule.get('min_confidence')}"})
                    continue
                if not self._meets_ownership(finding, rule):
                    skipped.append({"finding_id": finding.finding_id, "rule_id": rule_id,
                                    "reason": f"ownership {finding.ownership_status} inferiore al minimo "
                                              f"{rule.get('required_ownership')}"})
                    continue

                exclusive_group = rule.get("exclusive_group")
                if exclusive_group:
                    claim = (str(exclusive_group), finding.finding_id)
                    if claim in exclusive_claimed:
                        skipped.append({
                            "finding_id": finding.finding_id, "rule_id": rule_id,
                            "reason": f"gia' penalizzato da una regola piu' severa del gruppo "
                                      f"esclusivo {exclusive_group}"})
                        continue
                    exclusive_claimed.add(claim)

                dedup_key = self._dedup_key(finding, rule)
                if (rule_id, dedup_key) in seen_dedup:
                    continue
                seen_dedup.add((rule_id, dedup_key))

                confidence_multiplier = self._confidence_multiplier(finding)
                ownership_multiplier = self._ownership_multiplier(finding)
                decay = self._decay_factor(finding, rule, now)
                raw = float(rule["deduction"]) * confidence_multiplier * ownership_multiplier * decay
                if raw <= 0:
                    continue

                capped_by: str | None = None
                remaining_rule = max_rule - rule_totals[rule_id]
                if raw > remaining_rule:
                    raw, capped_by = max(0.0, remaining_rule), "rule_max"
                remaining_group = group_cap - group_totals[group]
                if raw > remaining_group:
                    raw, capped_by = max(0.0, remaining_group), "root_cause_cap"
                if raw <= 0:
                    continue

                rule_totals[rule_id] += raw
                group_totals[group] += raw
                categories[category_key].deductions.append(AppliedDeduction(
                    rule_id=rule_id, finding_id=finding.finding_id, category=category_key,
                    base_deduction=float(rule["deduction"]),
                    confidence_multiplier=confidence_multiplier,
                    ownership_multiplier=ownership_multiplier, decay_factor=decay,
                    effective_deduction=raw, capped_by=capped_by, dedup_key=dedup_key))

        # Punteggio per categoria (clampato in [0,100]).
        for finding in scorable:
            category = categories.get(finding.category)
            if category is None:
                continue
            category.finding_count += 1
            if finding.severity == "critical":
                category.critical_count += 1
            elif finding.severity == "high":
                category.high_count += 1

        for category in categories.values():
            category.total_deduction = sum(d.effective_deduction for d in category.deductions)
            category.score = max(0.0, min(100.0, 100.0 - category.total_deduction))

        ordered = [categories[key] for key in self.config["categories"]]
        raw_weighted = sum(c.score * c.weight for c in ordered)

        applied_caps = self._evaluate_caps(scorable, now)
        overall = raw_weighted
        for cap in applied_caps:
            overall = min(overall, cap.max_score)
        overall = max(0.0, min(100.0, overall))

        rating_class, label = self._classify(overall)
        return ScoringResult(
            overall_score=round(overall, 2), raw_weighted_score=round(raw_weighted, 2),
            rating_class=rating_class, rating_label_it=label, categories=ordered,
            applied_caps=applied_caps, config_version=self.version, computed_at=now,
            trace={
                "findings_total": len(findings),
                "findings_scorable": len(scorable),
                "rules_evaluated": len(rules),
                "deductions_applied": sum(len(c.deductions) for c in ordered),
                "rule_totals": {k: round(v, 2) for k, v in sorted(rule_totals.items())},
                "root_cause_totals": {k: round(v, 2) for k, v in sorted(group_totals.items())},
                "skipped": skipped[:200],
            })

    # -------------------------- dedup e caps -----------------------------
    @staticmethod
    def _dedup_key(finding: ScorableFinding, rule: dict[str, Any]) -> str:
        """Evita la doppia penalizzazione quando piu' tool rilevano lo stesso problema."""
        parts: list[str] = []
        for field_name in rule.get("dedup_key", ["asset_key", "finding_type"]):
            value = {
                "asset_key": finding.asset_key,
                "finding_type": finding.finding_type,
                "detail": finding.detail or "",
                "cve": finding.cve_id or "",
                "category": finding.category,
            }.get(field_name, "")
            parts.append(str(value).lower())
        return "|".join(parts)

    def _evaluate_caps(self, findings: Iterable[ScorableFinding],
                       now: datetime) -> list[AppliedCap]:
        """I rating cap si applicano solo a evidenze confermate, su asset
        verificati e — dove richiesto — validate da un analista."""
        requirements = self.caps_config.get("global_requirements", {})
        min_confidence = str(requirements.get("min_confidence_class", ConfidenceClass.CONFIRMED.value))
        min_ownership = str(requirements.get("min_ownership", OwnershipStatus.VERIFIED_OWNED.value))
        applied: list[AppliedCap] = []

        for cap in self.caps_config.get("caps", []):
            for finding in findings:
                if not self._matches(finding, cap.get("match", {})):
                    continue
                if CONFIDENCE_RANK.get(finding.confidence_class, 0) < CONFIDENCE_RANK.get(min_confidence, 4):
                    continue
                if OWNERSHIP_RANK.get(finding.ownership_status, 0) < OWNERSHIP_RANK.get(min_ownership, 4):
                    continue
                if cap.get("require_analyst_validation") and finding.analyst_validation != (
                        AnalystValidation.VALIDATED.value):
                    continue
                max_age = cap.get("max_age_days")
                if max_age is not None:
                    reference = finding.event_date or finding.last_seen_at
                    if reference is None:
                        continue
                    if reference.tzinfo is None:
                        reference = reference.replace(tzinfo=UTC)
                    if (now - reference).days > int(max_age):
                        continue
                applied.append(AppliedCap(
                    cap_id=str(cap["id"]), max_score=float(cap["max_overall_score"]),
                    reason_it=str(cap.get("description_it", "")), finding_id=finding.finding_id))
                break  # un cap si applica una sola volta
        return applied

    def _classify(self, score: float) -> tuple[str, str]:
        """Assegna la classe confrontando solo il limite inferiore.

        I limiti superiori dichiarati in configurazione sono interi (84, 69,
        54...): confrontarli direttamente lascerebbe scoperti i punteggi
        frazionari fra due classi (54.5 non e' ne' <= 54 ne' >= 55) e li
        farebbe ricadere nella classe peggiore. Ordinando per soglia
        decrescente e usando il solo `min` la scala resta continua.
        """
        for entry in sorted(self.config["classes"], key=lambda e: float(e["min"]), reverse=True):
            if score >= float(entry["min"]):
                return str(entry["code"]), str(entry["label_it"])
        lowest = min(self.config["classes"], key=lambda e: float(e["min"]))
        return str(lowest["code"]), str(lowest["label_it"])


def class_for_score(score: float, config: dict[str, Any] | None = None) -> str:
    """Helper leggero usato dal frontend e dai report.

    Usa la stessa regola del motore: confronto sul solo limite inferiore,
    cosi' la scala non ha discontinuita' sui punteggi frazionari.
    """
    config = config or load_yaml_config("scoring")
    for entry in sorted(config["classes"], key=lambda e: float(e["min"]), reverse=True):
        if score >= float(entry["min"]):
            return str(entry["code"])
    return str(min(config["classes"], key=lambda e: float(e["min"]))["code"])
