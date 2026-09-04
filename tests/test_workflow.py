"""Test del workflow di revisione, del gate di autorizzazione e del diff."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.services.authorization import (
    AuthorizationView,
    DomainView,
    ScopeView,
    check_scan_authorization,
)
from app.services.diff import (
    AssetSnapshot,
    FindingSnapshot,
    apply_score_delta,
    diff_assets,
    diff_findings,
)
from app.services.review import (
    InvalidTransitionError,
    ReviewRequiredError,
    apply_review_action,
    assert_report_publishable,
    findings_requiring_review,
    review_progress,
)

pytestmark = pytest.mark.security

PASSIVO = {"requires_verification": False, "requires_authorization": False}
STANDARD = {"requires_verification": True, "requires_authorization": True}
ESTESO = {"requires_verification": True, "requires_authorization": True,
          "requires_explicit_scope_whitelist": True}


def _autorizzazione(now, profili=("verified_standard", "verified_extended"), **overrides):
    defaults = dict(
        authorization_id="A1", status="active", valid_from=now - timedelta(days=1),
        expires_at=now + timedelta(days=30), revoked_at=None,
        allowed_profiles=list(profili))
    defaults.update(overrides)
    return AuthorizationView(**defaults)


# --------------------------------------------------------------------------
# Gate di autorizzazione
# --------------------------------------------------------------------------
def test_profilo_passivo_non_richiede_verifica(now):
    check = check_scan_authorization(
        profile="public_passive", domains=[DomainView("acme.example", "unverified")],
        authorizations=[], scopes=[], profile_definition=PASSIVO, now=now)
    assert check.allowed


def test_profilo_standard_richiede_dominio_verificato(now):
    check = check_scan_authorization(
        profile="verified_standard", domains=[DomainView("acme.example", "unverified")],
        authorizations=[_autorizzazione(now)], scopes=[],
        profile_definition=STANDARD, now=now)
    assert not check.allowed
    assert any("verificato" in r for r in check.reasons)


def test_profilo_standard_richiede_autorizzazione(now):
    check = check_scan_authorization(
        profile="verified_standard", domains=[DomainView("acme.example", "verified")],
        authorizations=[], scopes=[], profile_definition=STANDARD, now=now)
    assert not check.allowed
    assert any("autorizzazione" in r for r in check.reasons)


def test_autorizzazione_scaduta_rifiutata(now):
    scaduta = _autorizzazione(now, valid_from=now - timedelta(days=400),
                              expires_at=now - timedelta(days=1))
    check = check_scan_authorization(
        profile="verified_standard", domains=[DomainView("acme.example", "verified")],
        authorizations=[scaduta], scopes=[], profile_definition=STANDARD, now=now)
    assert not check.allowed


def test_autorizzazione_revocata_rifiutata(now):
    revocata = _autorizzazione(now, revoked_at=now - timedelta(hours=1))
    check = check_scan_authorization(
        profile="verified_standard", domains=[DomainView("acme.example", "verified")],
        authorizations=[revocata], scopes=[], profile_definition=STANDARD, now=now)
    assert not check.allowed


def test_autorizzazione_per_altro_profilo_non_vale(now):
    solo_standard = _autorizzazione(now, profili=("verified_standard",))
    check = check_scan_authorization(
        profile="verified_extended", domains=[DomainView("acme.example", "verified")],
        authorizations=[solo_standard],
        scopes=[ScopeView("cidr", "203.0.113.0/24", "include")],
        profile_definition=ESTESO, now=now)
    assert not check.allowed


def test_profilo_esteso_richiede_whitelist(now):
    check = check_scan_authorization(
        profile="verified_extended", domains=[DomainView("acme.example", "verified")],
        authorizations=[_autorizzazione(now)], scopes=[],
        profile_definition=ESTESO, now=now)
    assert not check.allowed
    assert any("whitelist" in r for r in check.reasons)


def test_profilo_esteso_ammesso_con_tutte_le_condizioni(now):
    check = check_scan_authorization(
        profile="verified_extended", domains=[DomainView("acme.example", "verified")],
        authorizations=[_autorizzazione(now)],
        scopes=[ScopeView("cidr", "203.0.113.0/24", "include")],
        profile_definition=ESTESO, now=now)
    assert check.allowed
    assert check.authorization_id == "A1"


# --------------------------------------------------------------------------
# Revisione
# --------------------------------------------------------------------------
def test_conferma_promuove_ad_approvato():
    decision = apply_review_action("confirm", current_state="scored",
                                   current_confidence="probable")
    assert decision.analyst_validation == "validated"
    assert decision.workflow_state == "approved"
    assert decision.confidence_class == "confirmed"


@pytest.mark.parametrize("action", ["false_positive", "accept_risk", "exclude_from_rating"])
def test_azioni_che_richiedono_motivazione(action):
    with pytest.raises(ValueError):
        apply_review_action(action, current_state="scored", current_confidence="confirmed")


def test_falso_positivo_esclude_dal_rating():
    decision = apply_review_action("false_positive", current_state="scored",
                                   current_confidence="confirmed", reason="host dismesso")
    assert decision.excluded_from_rating
    assert decision.confidence_class == "false_positive"


def test_transizione_non_ammessa_rifiutata():
    with pytest.raises(InvalidTransitionError):
        apply_review_action("confirm", current_state="detected", current_confidence="confirmed")


def test_azione_sconosciuta_rifiutata():
    with pytest.raises(ValueError):
        apply_review_action("cancella_tutto", current_state="scored",
                            current_confidence="confirmed")


def test_report_definitivo_bloccato_con_critici_da_rivedere():
    findings = [{"severity": "critical", "analyst_validation": "not_reviewed",
                 "reference_code": "DW-001", "excluded_from_rating": False}]
    with pytest.raises(ReviewRequiredError):
        assert_report_publishable(findings, is_final=True)


def test_report_provvisorio_sempre_emettibile():
    findings = [{"severity": "critical", "analyst_validation": "not_reviewed",
                 "reference_code": "DW-001", "excluded_from_rating": False}]
    assert_report_publishable(findings, is_final=False)


def test_solo_critici_e_alti_bloccano_il_report():
    findings = [{"severity": "medium", "analyst_validation": "not_reviewed",
                 "reference_code": "WEB-001", "excluded_from_rating": False}]
    assert findings_requiring_review(findings) == []
    assert_report_publishable(findings, is_final=True)


def test_avanzamento_revisione():
    progress = review_progress([
        {"severity": "critical", "analyst_validation": "validated"},
        {"severity": "high", "analyst_validation": "not_reviewed"},
        {"severity": "low", "analyst_validation": "not_reviewed"},
    ])
    assert progress["critical_high_total"] == 2
    assert progress["critical_high_pending"] == 1
    assert not progress["ready_for_final_report"]


# --------------------------------------------------------------------------
# Confronto fra scansioni
# --------------------------------------------------------------------------
def _snapshot(fingerprint: str, missing: int = 0, resolved=None) -> FindingSnapshot:
    return FindingSnapshot(
        fingerprint=fingerprint, reference_code=f"EML-{fingerprint}", title="rilievo",
        category="email_dns_security", severity="high", asset_key="mail:acme.example",
        finding_type="dmarc_missing", first_seen_at=datetime.now(UTC) - timedelta(days=60),
        last_seen_at=datetime.now(UTC), resolved_at=resolved, missing_confirmations=missing)


def test_nuovo_rilievo_riconosciuto():
    diff = diff_findings([_snapshot("a")], [_snapshot("a"), _snapshot("b")])
    assert [f["fingerprint"] for f in diff.new_findings] == ["b"]


def test_sparizione_non_chiude_subito_il_rilievo():
    """Una sola assenza non basta: potrebbe essere un tool fallito."""
    diff = diff_findings([_snapshot("a")], [])
    assert diff.resolved_findings == []
    assert len(diff.pending_closure) == 1
    assert diff.pending_closure[0]["missing_confirmations"] == 1


def test_seconda_assenza_chiude_il_rilievo():
    diff = diff_findings([_snapshot("a", missing=1)], [])
    assert len(diff.resolved_findings) == 1


def test_riapertura_riconosciuta():
    risolto = _snapshot("a", resolved=datetime.now(UTC) - timedelta(days=30))
    diff = diff_findings([risolto], [_snapshot("a")])
    assert len(diff.reopened_findings) == 1


def test_diff_asset():
    prima = [AssetSnapshot("a.example", "subdomain", "verified_owned",
                           datetime.now(UTC), datetime.now(UTC))]
    dopo = [AssetSnapshot("b.example", "subdomain", "verified_owned",
                          datetime.now(UTC), datetime.now(UTC))]
    diff = diff_assets(prima, dopo)
    assert [a["asset_key"] for a in diff.new_assets] == ["b.example"]
    assert [a["asset_key"] for a in diff.disappeared_assets] == ["a.example"]


def test_riepilogo_variazione_leggibile():
    diff = apply_score_delta(diff_findings([], []), previous_score=61.0,
                             current_score=68.4, previous_class="C", current_class="C")
    assert "miglioramento" in diff.summary_it()
    assert diff.score_delta == 7.4


def test_prima_scansione_senza_confronto():
    diff = apply_score_delta(diff_findings([], []), previous_score=None,
                             current_score=70.0, previous_class=None, current_class="B")
    assert "Prima scansione" in diff.summary_it()
