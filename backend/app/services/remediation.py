"""Catalogo delle remediation e priorizzazione del piano di intervento."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Sequence

from app.core.config import load_yaml_config
from app.models.enums import SEVERITY_RANK

# Peso della priorita' nel calcolo dell'ordine di intervento.
PRIORITY_WEIGHT: dict[str, int] = {"p1": 4, "p2": 3, "p3": 2, "p4": 1}
# Effort: a parita' di rischio si interviene prima su cio' che costa meno.
EFFORT_WEIGHT: dict[str, float] = {"xs": 1.0, "s": 0.85, "m": 0.6, "l": 0.4, "xl": 0.25}


@lru_cache(maxsize=1)
def catalog() -> dict[str, dict[str, Any]]:
    data = load_yaml_config("remediation_catalog")
    return {str(item["id"]): item for item in data.get("remediations", [])}


@lru_cache(maxsize=1)
def rule_to_remediation() -> dict[str, str]:
    """Mappa regola di scoring -> remediation, letta da scoring.yaml."""
    scoring = load_yaml_config("scoring")
    return {str(rule["id"]): str(rule["remediation"])
            for rule in scoring.get("rules", []) if rule.get("remediation")}


@lru_cache(maxsize=1)
def finding_type_to_remediation() -> dict[str, str]:
    """Mappa finding_type -> remediation, derivata dalle regole di scoring."""
    scoring = load_yaml_config("scoring")
    mapping: dict[str, str] = {}
    for rule in scoring.get("rules", []):
        finding_type = rule.get("match", {}).get("finding_type")
        if finding_type and rule.get("remediation"):
            mapping.setdefault(str(finding_type), str(rule["remediation"]))
    return mapping


def remediation_for_finding(finding_type: str, applied_rule_ids: Sequence[str] = ()) -> dict[str, Any] | None:
    """Risolve la remediation: prima dalle regole applicate, poi dal tipo."""
    for rule_id in applied_rule_ids:
        catalog_id = rule_to_remediation().get(rule_id)
        if catalog_id and catalog_id in catalog():
            return catalog()[catalog_id]
    catalog_id = finding_type_to_remediation().get(finding_type)
    return catalog().get(catalog_id) if catalog_id else None


@dataclass
class RemediationPlanItem:
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
    affected_assets: list[str]
    score: float
    is_quick_win: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "catalog_id": self.catalog_id, "title_it": self.title_it, "area": self.area,
            "priority": self.priority, "effort": self.effort, "skills": self.skills,
            "risk_mitigated_it": self.risk_mitigated_it,
            "immediate_action_it": self.immediate_action_it,
            "structural_solution_it": self.structural_solution_it,
            "verification_it": self.verification_it, "references": self.references,
            # Separato dalla raccomandazione tecnica (sezione 18).
            "commercial_services": self.commercial_services,
            "finding_codes": self.finding_codes, "max_severity": self.max_severity,
            "affected_assets": self.affected_assets[:20],
            "affected_asset_count": len(self.affected_assets),
            "priority_score": round(self.score, 2), "is_quick_win": self.is_quick_win,
        }


def build_plan(findings: Sequence[dict[str, Any]]) -> list[RemediationPlanItem]:
    """Costruisce il piano di remediation prioritizzato.

    L'ordine tiene conto di severita' massima, priorita' di catalogo, numero di
    asset interessati ed effort richiesto. Le raccomandazioni tecniche restano
    separate dalle proposte commerciali.
    """
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        entry = remediation_for_finding(
            str(finding.get("finding_type", "")),
            [str(rule.get("rule_id", "")) for rule in finding.get("applied_rules", [])])
        if entry is None:
            continue
        catalog_id = str(entry["id"])
        bucket = grouped.setdefault(catalog_id, {
            "entry": entry, "codes": [], "assets": set(), "severities": []})
        bucket["codes"].append(str(finding.get("reference_code", "")))
        bucket["assets"].add(str(finding.get("asset_key", "")))
        bucket["severities"].append(str(finding.get("severity", "info")))

    items: list[RemediationPlanItem] = []
    for catalog_id, bucket in grouped.items():
        entry = bucket["entry"]
        max_severity = max(bucket["severities"], key=lambda s: SEVERITY_RANK.get(s, 0))
        priority = str(entry.get("priority", "p3"))
        effort = str(entry.get("effort", "m"))
        severity_weight = SEVERITY_RANK.get(max_severity, 0) + 1
        asset_weight = min(3.0, 1.0 + len(bucket["assets"]) / 10.0)
        # La severita' domina: un rilievo critico va affrontato per primo anche
        # se costoso. L'effort ordina solo a parita' di rischio.
        score = (severity_weight ** 2 * PRIORITY_WEIGHT.get(priority, 2) * asset_weight
                 * (0.7 + 0.3 * EFFORT_WEIGHT.get(effort, 0.5)))
        items.append(RemediationPlanItem(
            catalog_id=catalog_id, title_it=str(entry["title_it"]), area=str(entry["area"]),
            priority=priority, effort=effort, skills=list(entry.get("skills", [])),
            risk_mitigated_it=str(entry.get("risk_mitigated_it", "")).strip(),
            immediate_action_it=str(entry.get("immediate_action_it", "")).strip(),
            structural_solution_it=str(entry.get("structural_solution_it", "")).strip(),
            verification_it=str(entry.get("verification_it", "")).strip(),
            references=list(entry.get("references", [])),
            commercial_services=list(entry.get("commercial_services", [])),
            finding_codes=sorted(c for c in bucket["codes"] if c),
            max_severity=max_severity, affected_assets=sorted(a for a in bucket["assets"] if a),
            score=score,
            # Quick win: impatto reale con sforzo minimo e nessuna dipendenza.
            is_quick_win=(effort in {"xs", "s"} and priority in {"p1", "p2"}
                          and SEVERITY_RANK.get(max_severity, 0) >= 2)))

    items.sort(key=lambda item: (
        -SEVERITY_RANK.get(item.max_severity, 0),   # prima il rischio piu' alto
        -PRIORITY_WEIGHT.get(item.priority, 2),     # poi la priorita' di catalogo
        -item.score,                                # infine effort e diffusione
        item.catalog_id))
    return items


def quick_wins(plan: Sequence[RemediationPlanItem], limit: int = 5) -> list[RemediationPlanItem]:
    return [item for item in plan if item.is_quick_win][:limit]
