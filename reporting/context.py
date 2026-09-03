"""Costruzione del contesto dati per i report.

Il contesto e' esplicito e sanitizzato: password, token, cookie, contenuti
integrali di leak, dati personali non necessari, istruzioni di exploit e
payload offensivi non entrano MAI nei report (sezione 15).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.config import load_yaml_config, settings
from app.core.redaction import mask_email, strip_forbidden_keys
from app.models.enums import SEVERITY_RANK

DISCLAIMER_IT = (
    "Defenix Exposure Rating e' una valutazione della sicurezza osservabile dall'esterno "
    "e dei rischi a cui l'organizzazione potrebbe essere esposta. Non costituisce un "
    "penetration test, un vulnerability assessment completo ne' una certificazione di "
    "sicurezza. I risultati si riferiscono esclusivamente al perimetro dichiarato e "
    "autorizzato e allo stato osservato alla data della rilevazione."
)

LIMITS_IT = [
    "L'analisi si basa su informazioni osservabili dall'esterno: non sostituisce una "
    "verifica interna dei sistemi.",
    "L'assenza di rilievi in un'area non costituisce prova di sicurezza: puo' dipendere "
    "dalla copertura degli strumenti impiegati.",
    "I rilievi non confermati sono indicati come tali e non incidono sul punteggio.",
    "Le fonti pubbliche e i cataloghi di vulnerabilita' possono essere incompleti o "
    "aggiornati con ritardo.",
    "Gli asset di terzi (CDN, cloud, hosting condivisi, fornitori, SaaS) sono esclusi "
    "dal calcolo del rating.",
]

SEVERITY_LABEL_IT = {"critical": "Critica", "high": "Alta", "medium": "Media",
                     "low": "Bassa", "info": "Informativa"}
CONFIDENCE_LABEL_IT = {"confirmed": "Confermata", "probable": "Probabile",
                       "inferred": "Dedotta", "informational": "Informativa",
                       "false_positive": "Falso positivo", "accepted_risk": "Rischio accettato",
                       "resolved": "Risolta"}
OWNERSHIP_LABEL_IT = {"verified_owned": "Proprieta' verificata",
                      "likely_owned": "Probabile proprieta'", "unverified": "Non verificato",
                      "third_party": "Terza parte", "excluded": "Escluso"}
EFFORT_LABEL_IT = {"xs": "Molto basso", "s": "Basso", "m": "Medio", "l": "Alto", "xl": "Molto alto"}
PRIORITY_LABEL_IT = {"p1": "Immediata", "p2": "Alta", "p3": "Media", "p4": "Pianificabile"}


@dataclass
class ReportContext:
    """Dato passato ai template. Nessun accesso al database dai template."""

    company_name: str
    company_vat: str | None
    generated_at: datetime
    language: str
    profile_key: str
    profile_label: str
    scope: dict[str, Any]
    overall_score: float
    rating_class: str
    rating_label: str
    is_provisional: bool
    provisional_notice: str | None
    confidence_value: float
    confidence_label: str
    categories: list[dict[str, Any]]
    top_risks: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    remediation_plan: list[dict[str, Any]]
    quick_wins: list[dict[str, Any]]
    comparison: dict[str, Any] | None
    coverage_matrix: list[dict[str, Any]]
    exposure_summary: dict[str, Any]
    applied_caps: list[dict[str, Any]]
    brand: dict[str, str]
    disclaimer: str = DISCLAIMER_IT
    limits: list[str] = field(default_factory=lambda: list(LIMITS_IT))

    def as_dict(self) -> dict[str, Any]:
        return {
            "company_name": self.company_name, "company_vat": self.company_vat,
            "generated_at": self.generated_at, "language": self.language,
            "profile_key": self.profile_key, "profile_label": self.profile_label,
            "scope": self.scope, "overall_score": self.overall_score,
            "rating_class": self.rating_class, "rating_label": self.rating_label,
            "is_provisional": self.is_provisional, "provisional_notice": self.provisional_notice,
            "confidence_value": self.confidence_value, "confidence_label": self.confidence_label,
            "categories": self.categories, "top_risks": self.top_risks,
            "findings": self.findings, "remediation_plan": self.remediation_plan,
            "quick_wins": self.quick_wins, "comparison": self.comparison,
            "coverage_matrix": self.coverage_matrix, "exposure_summary": self.exposure_summary,
            "applied_caps": self.applied_caps, "brand": self.brand,
            "disclaimer": self.disclaimer, "limits": self.limits,
            "severity_label": SEVERITY_LABEL_IT, "confidence_label_map": CONFIDENCE_LABEL_IT,
            "ownership_label": OWNERSHIP_LABEL_IT, "effort_label": EFFORT_LABEL_IT,
            "priority_label": PRIORITY_LABEL_IT,
        }


def sanitize_finding(finding: dict[str, Any], *, unmask_pii: bool = False) -> dict[str, Any]:
    """Ripulisce un finding prima di inserirlo nel report."""
    cleaned = strip_forbidden_keys(dict(finding))
    attributes = strip_forbidden_keys(dict(cleaned.get("attributes") or {}))
    # Gli indirizzi e-mail restano mascherati salvo ruolo autorizzato.
    for key, value in list(attributes.items()):
        if isinstance(value, str) and "@" in value and "." in value.split("@")[-1]:
            attributes[key] = mask_email(value, unmask=unmask_pii)
    cleaned["attributes"] = attributes
    cleaned.pop("evidence_ids", None)
    return cleaned


def build_context(*, company: dict[str, Any], scan: dict[str, Any], score: dict[str, Any],
                  findings: list[dict[str, Any]], remediation_plan: list[dict[str, Any]],
                  quick_win_items: list[dict[str, Any]], comparison: dict[str, Any] | None,
                  coverage_matrix: list[dict[str, Any]], exposure: dict[str, Any],
                  language: str = "it", unmask_pii: bool = False) -> ReportContext:
    profiles = load_yaml_config("tool_profiles").get("profiles", {})
    profile_key = str(scan.get("profile_key", "public_passive"))
    profile_label = str(profiles.get(profile_key, {}).get("label_it", profile_key))

    sanitized = [sanitize_finding(f, unmask_pii=unmask_pii) for f in findings]
    ranked = sorted(
        [f for f in sanitized if not f.get("excluded_from_rating")],
        key=lambda f: (-SEVERITY_RANK.get(str(f.get("severity")), 0),
                       -float(f.get("applied_deduction") or 0.0)))

    confidence = score.get("confidence") or {}
    return ReportContext(
        company_name=str(company.get("legal_name", "")),
        company_vat=company.get("vat_number"),
        generated_at=datetime.now(UTC), language=language,
        profile_key=profile_key, profile_label=profile_label,
        scope=scan.get("scope_snapshot") or {},
        overall_score=float(score.get("overall_score", 0.0)),
        rating_class=str(score.get("rating_class", "E")),
        rating_label=str(score.get("rating_label_it", "")),
        is_provisional=bool(score.get("is_provisional")),
        provisional_notice=score.get("provisional_reason"),
        confidence_value=float(confidence.get("value", 0.0)),
        confidence_label=str(confidence.get("label_it", "")),
        categories=list(score.get("categories", [])),
        top_risks=ranked[:5], findings=sanitized,
        remediation_plan=remediation_plan, quick_wins=quick_win_items,
        comparison=comparison, coverage_matrix=coverage_matrix, exposure_summary=exposure,
        applied_caps=list(score.get("applied_caps", [])),
        brand={"name": settings.report_brand_name, "owner": settings.report_brand_owner})
