"""Calcolo del Confidence Score (sezione 13).

Il confidence NON modifica il rating: dichiara quanto e' solida la
valutazione. Un controllo non eseguito abbassa la confidence, mai il rating.
Sotto la soglia configurata il rating e' presentato come provvisorio.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Sequence

from app.core.config import load_yaml_config
from app.models.enums import AnalystValidation, ToolRunStatus


@dataclass
class ToolRunSummary:
    tool_key: str
    status: str
    coverage_impact: float = 0.0
    coverage_weight: float = 1.0
    areas: tuple[str, ...] = ()
    optional: bool = False
    was_mocked: bool = False
    error_message: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == ToolRunStatus.SUCCESS.value

    @property
    def contributed(self) -> bool:
        return self.status in {ToolRunStatus.SUCCESS.value, ToolRunStatus.PARTIAL.value}


@dataclass
class ConfidenceInput:
    profile: str
    domains_total: int
    domains_verified: int
    ips_total: int = 0
    ips_authorized: int = 0
    assets_total: int = 0
    assets_with_ownership: int = 0
    technologies_total: int = 0
    technologies_with_version: int = 0
    critical_high_findings: int = 0
    critical_high_validated: int = 0
    distinct_sources: int = 0
    tool_runs: Sequence[ToolRunSummary] = field(default_factory=tuple)
    optional_apis_configured: int = 0
    optional_apis_available: int = 0
    darkweb_sources_available: int = 0
    darkweb_sources_expected: int = 1
    evidence_ages_days: Sequence[float] = field(default_factory=tuple)
    scan_partial: bool = False


@dataclass
class ConfidenceResult:
    value: float
    label_it: str
    label_en: str
    is_publishable: bool
    factors: dict[str, dict[str, Any]]
    penalties: list[dict[str, Any]]
    coverage_matrix: list[dict[str, Any]]
    computed_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": round(self.value, 1), "label_it": self.label_it, "label_en": self.label_en,
            "is_publishable": self.is_publishable, "factors": self.factors,
            "penalties": self.penalties, "coverage_matrix": self.coverage_matrix,
            "computed_at": self.computed_at.isoformat(),
        }


def _ratio(numerator: float, denominator: float) -> float:
    return 0.0 if denominator <= 0 else max(0.0, min(1.0, numerator / denominator))


class ConfidenceEngine:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or load_yaml_config("evidence_confidence")

    # ------------------------------------------------------------------
    def compute(self, data: ConfidenceInput, *, now: datetime | None = None) -> ConfidenceResult:
        now = now or datetime.now(UTC)
        weights = self.config["factors"]
        contributions: dict[str, dict[str, Any]] = {}

        def contribute(name: str, ratio: float, note: str) -> float:
            weight = float(weights[name]["weight"])
            earned = weight * max(0.0, min(1.0, ratio))
            contributions[name] = {
                "ratio": round(ratio, 3), "weight": weight, "earned": round(earned, 2),
                "description_it": weights[name].get("description_it", ""), "note": note,
            }
            return earned

        total = float(self.config.get("base", 0))

        total += contribute("domain_verified",
                            _ratio(data.domains_verified, data.domains_total),
                            f"{data.domains_verified}/{data.domains_total} domini verificati")
        total += contribute("ip_authorized",
                            _ratio(data.ips_authorized, data.ips_total) if data.ips_total else 1.0,
                            f"{data.ips_authorized}/{data.ips_total} IP autorizzati"
                            if data.ips_total else "nessun IP nel perimetro: fattore non penalizzante")
        total += contribute("scope_completeness",
                            _ratio(data.assets_with_ownership, data.assets_total),
                            f"{data.assets_with_ownership}/{data.assets_total} asset con ownership determinata")
        total += contribute("source_diversity",
                            _ratio(data.distinct_sources,
                                   float(self.config.get("source_diversity_target", 8))),
                            f"{data.distinct_sources} fonti indipendenti interrogate")

        planned = [r for r in data.tool_runs if not r.optional]
        succeeded = [r for r in planned if r.succeeded]
        total += contribute("tool_success_rate", _ratio(len(succeeded), len(planned)),
                            f"{len(succeeded)}/{len(planned)} tool completati con successo")

        depth = float(self.config["profile_depth_values"].get(data.profile, 0.5))
        total += contribute("profile_depth", depth, f"profilo {data.profile}")

        total += contribute("fingerprint_precision",
                            _ratio(data.technologies_with_version, data.technologies_total)
                            if data.technologies_total else 0.5,
                            f"{data.technologies_with_version}/{data.technologies_total} "
                            "tecnologie con versione determinata"
                            if data.technologies_total
                            else "nessuna tecnologia rilevata: fattore neutro")

        total += contribute("human_validation",
                            _ratio(data.critical_high_validated, data.critical_high_findings)
                            if data.critical_high_findings else 1.0,
                            f"{data.critical_high_validated}/{data.critical_high_findings} finding "
                            "critici/alti validati da un analista"
                            if data.critical_high_findings
                            else "nessun finding critico o alto da validare")

        total += contribute("darkweb_coverage",
                            _ratio(data.darkweb_sources_available, data.darkweb_sources_expected),
                            f"{data.darkweb_sources_available}/{data.darkweb_sources_expected} "
                            "fonti dark web disponibili")

        total += contribute("optional_apis",
                            _ratio(data.optional_apis_available, data.optional_apis_configured)
                            if data.optional_apis_configured else 0.0,
                            f"{data.optional_apis_available}/{data.optional_apis_configured} "
                            "API opzionali disponibili"
                            if data.optional_apis_configured
                            else "nessuna API opzionale configurata (es. HIBP)")

        total += contribute("data_freshness", self._freshness(data.evidence_ages_days),
                            self._freshness_note(data.evidence_ages_days))

        # ---------------- penalita' esplicite ----------------
        penalties: list[dict[str, Any]] = []
        configured_penalties = self.config.get("penalties", {})
        if data.domains_verified == 0:
            amount = float(configured_penalties.get("no_domain_verified", 0))
            total -= amount
            penalties.append({"key": "no_domain_verified", "amount": amount,
                              "reason_it": "nessun dominio del perimetro e' stato verificato"})
        if planned and not succeeded:
            amount = float(configured_penalties.get("all_tools_failed", 0))
            total -= amount
            penalties.append({"key": "all_tools_failed", "amount": amount,
                              "reason_it": "nessuno strumento pianificato e' andato a buon fine"})
        if data.scan_partial:
            amount = float(configured_penalties.get("scan_partial", 0))
            total -= amount
            penalties.append({"key": "scan_partial", "amount": amount,
                              "reason_it": "la scansione si e' conclusa in stato parziale"})

        value = max(0.0, min(100.0, total))
        threshold = float(self.config.get("minimum_publishable", 50))
        label_it, label_en = self._label(value)
        return ConfidenceResult(
            value=value, label_it=label_it, label_en=label_en,
            is_publishable=value >= threshold, factors=contributions, penalties=penalties,
            coverage_matrix=self._coverage_matrix(data.tool_runs), computed_at=now)

    # ------------------------------------------------------------------
    def _freshness(self, ages: Sequence[float]) -> float:
        if not ages:
            return 0.5
        average = sum(ages) / len(ages)
        for entry in self.config.get("data_freshness_thresholds", []):
            if average <= float(entry["max_age_days"]):
                return float(entry["value"])
        return 0.1

    @staticmethod
    def _freshness_note(ages: Sequence[float]) -> str:
        if not ages:
            return "nessuna evidenza datata disponibile"
        return f"anzianita' media delle evidenze: {sum(ages) / len(ages):.0f} giorni"

    def _label(self, value: float) -> tuple[str, str]:
        for entry in self.config.get("labels", []):
            if value >= float(entry["min"]):
                return str(entry["label_it"]), str(entry.get("label_en", ""))
        return "Affidabilita' insufficiente", "Insufficient reliability"

    @staticmethod
    def _coverage_matrix(runs: Sequence[ToolRunSummary]) -> list[dict[str, Any]]:
        """Matrice pubblicata nel report: cosa e' stato eseguito e cosa no."""
        return [
            {
                "tool": run.tool_key,
                "status": run.status,
                "areas": list(run.areas),
                "optional": run.optional,
                "mocked": run.was_mocked,
                "impact_on_coverage": round(run.coverage_impact, 2),
                "note_it": run.error_message or ("eseguito con successo" if run.succeeded
                                                 else "esito parziale"),
            }
            for run in runs
        ]


PROVISIONAL_NOTICE_IT = (
    "Valutazione provvisoria - evidenze insufficienti per un rating attendibile."
)
PROVISIONAL_NOTICE_EN = (
    "Provisional assessment - insufficient evidence for a reliable rating."
)
