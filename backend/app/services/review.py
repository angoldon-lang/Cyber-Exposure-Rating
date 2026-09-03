"""Workflow di revisione dei finding (sezione 17).

Detected -> Normalized -> Correlated -> Scored -> Analyst Review -> Approved
-> Reported -> Resolved

Ogni transizione manuale e' registrata nell'audit log dal chiamante.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.models.enums import (
    SEVERITY_RANK,
    AnalystValidation,
    ConfidenceClass,
    FindingWorkflowState,
    Severity,
)

# Transizioni ammesse. Qualsiasi altra combinazione e' rifiutata.
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    FindingWorkflowState.DETECTED.value: {FindingWorkflowState.NORMALIZED.value},
    FindingWorkflowState.NORMALIZED.value: {FindingWorkflowState.CORRELATED.value},
    FindingWorkflowState.CORRELATED.value: {FindingWorkflowState.SCORED.value},
    FindingWorkflowState.SCORED.value: {FindingWorkflowState.ANALYST_REVIEW.value,
                                        FindingWorkflowState.APPROVED.value},
    FindingWorkflowState.ANALYST_REVIEW.value: {FindingWorkflowState.APPROVED.value,
                                                FindingWorkflowState.SCORED.value,
                                                FindingWorkflowState.RESOLVED.value},
    FindingWorkflowState.APPROVED.value: {FindingWorkflowState.REPORTED.value,
                                          FindingWorkflowState.ANALYST_REVIEW.value},
    FindingWorkflowState.REPORTED.value: {FindingWorkflowState.RESOLVED.value,
                                          FindingWorkflowState.ANALYST_REVIEW.value},
    FindingWorkflowState.RESOLVED.value: {FindingWorkflowState.ANALYST_REVIEW.value},
}


class InvalidTransitionError(ValueError):
    pass


class ReviewRequiredError(ValueError):
    """Sollevata quando un report definitivo viene richiesto con finding
    critici non ancora validati da un analista."""


def assert_transition(current: str, target: str) -> None:
    if target not in ALLOWED_TRANSITIONS.get(current, set()):
        raise InvalidTransitionError(
            f"Transizione non ammessa: {current} -> {target}. "
            f"Stati validi: {sorted(ALLOWED_TRANSITIONS.get(current, set()))}")


@dataclass
class ReviewDecision:
    """Esito di un'azione del revisore su un finding."""

    analyst_validation: str
    workflow_state: str
    excluded_from_rating: bool
    confidence_class: str | None = None
    severity: str | None = None
    retest_requested: bool = False
    requires_reason: bool = False


def apply_review_action(action: str, *, current_state: str, current_confidence: str,
                        reason: str | None = None,
                        new_severity: str | None = None,
                        new_confidence: str | None = None) -> ReviewDecision:
    """Applica un'azione del revisore.

    Azioni: `confirm`, `reclassify`, `false_positive`, `accept_risk`,
    `exclude_from_rating`, `request_retest`, `reopen`.
    """
    if action == "confirm":
        assert_transition(current_state, FindingWorkflowState.APPROVED.value)
        return ReviewDecision(AnalystValidation.VALIDATED.value,
                              FindingWorkflowState.APPROVED.value, False,
                              confidence_class=ConfidenceClass.CONFIRMED.value)

    if action == "reclassify":
        if not new_severity and not new_confidence:
            raise ValueError("La riclassificazione richiede una nuova severita' o confidence")
        if new_severity and new_severity not in SEVERITY_RANK:
            raise ValueError(f"Severita' non valida: {new_severity}")
        if not reason:
            raise ValueError("La riclassificazione richiede una motivazione")
        return ReviewDecision(AnalystValidation.VALIDATED.value,
                              FindingWorkflowState.ANALYST_REVIEW.value, False,
                              confidence_class=new_confidence, severity=new_severity,
                              requires_reason=True)

    if action == "false_positive":
        if not reason:
            raise ValueError("La dichiarazione di falso positivo richiede una motivazione")
        return ReviewDecision(AnalystValidation.REJECTED_FALSE_POSITIVE.value,
                              FindingWorkflowState.ANALYST_REVIEW.value, True,
                              confidence_class=ConfidenceClass.FALSE_POSITIVE.value,
                              requires_reason=True)

    if action == "accept_risk":
        if not reason:
            raise ValueError("L'accettazione del rischio richiede una motivazione")
        return ReviewDecision(AnalystValidation.ACCEPTED_RISK.value,
                              FindingWorkflowState.APPROVED.value, True,
                              confidence_class=ConfidenceClass.ACCEPTED_RISK.value,
                              requires_reason=True)

    if action == "exclude_from_rating":
        if not reason:
            raise ValueError("L'esclusione dal rating richiede una motivazione")
        return ReviewDecision(AnalystValidation.EXCLUDED_FROM_RATING.value,
                              FindingWorkflowState.ANALYST_REVIEW.value, True,
                              requires_reason=True)

    if action == "request_retest":
        return ReviewDecision(AnalystValidation.RETEST_REQUESTED.value,
                              FindingWorkflowState.ANALYST_REVIEW.value, False,
                              retest_requested=True)

    if action == "reopen":
        return ReviewDecision(AnalystValidation.NOT_REVIEWED.value,
                              FindingWorkflowState.ANALYST_REVIEW.value, False)

    raise ValueError(f"Azione di revisione sconosciuta: {action}")


def findings_requiring_review(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """I finding critici e alti devono essere validati prima della
    pubblicazione del report definitivo (sezione 12)."""
    return [
        finding for finding in findings
        if SEVERITY_RANK.get(str(finding.get("severity")), 0) >= SEVERITY_RANK[Severity.HIGH.value]
        and finding.get("analyst_validation") == AnalystValidation.NOT_REVIEWED.value
        and not finding.get("excluded_from_rating")
    ]


def assert_report_publishable(findings: list[dict[str, Any]], *, is_final: bool) -> None:
    """Un report definitivo non puo' essere emesso con finding critici pendenti."""
    if not is_final:
        return
    pending = findings_requiring_review(findings)
    if pending:
        codes = ", ".join(str(f.get("reference_code")) for f in pending[:10])
        raise ReviewRequiredError(
            f"{len(pending)} finding critici o alti non sono ancora stati validati da un "
            f"analista: {codes}. Il report definitivo richiede la revisione preventiva.")


def review_progress(findings: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(findings)
    reviewed = sum(1 for f in findings
                   if f.get("analyst_validation") != AnalystValidation.NOT_REVIEWED.value)
    critical_high = [f for f in findings
                     if SEVERITY_RANK.get(str(f.get("severity")), 0) >= SEVERITY_RANK[Severity.HIGH.value]]
    critical_reviewed = sum(1 for f in critical_high
                            if f.get("analyst_validation") != AnalystValidation.NOT_REVIEWED.value)
    return {
        "total": total,
        "reviewed": reviewed,
        "pending": total - reviewed,
        "critical_high_total": len(critical_high),
        "critical_high_reviewed": critical_reviewed,
        "critical_high_pending": len(critical_high) - critical_reviewed,
        "ready_for_final_report": critical_reviewed == len(critical_high),
        "progress_percent": round(100 * reviewed / total, 1) if total else 100.0,
        "computed_at": datetime.now(UTC).isoformat(),
    }
