"""Test dei rating cap (sezione 12).

I cap si applicano SOLO a evidenze confermate, su asset verificati e su
finding validati da un analista.
"""
from __future__ import annotations

import pytest

pytestmark = [pytest.mark.scoring, pytest.mark.security]


def _cap_finding(make_finding, **overrides):
    base = {
        "finding_type": "ransomware_leak_publication",
        "category": "darkweb_breach",
        "severity": "critical",
        "confidence_class": "confirmed",
        "ownership_status": "verified_owned",
        "analyst_validation": "validated",
        "asset_key": "acme-test.example",
        "detail": "lockbit3:2026-06-01",
    }
    base.update(overrides)
    return make_finding(**base)


def test_ransomware_confermato_limita_a_39(scoring_engine, make_finding, past):
    result = scoring_engine.score([_cap_finding(make_finding, event_date=past(30))])
    assert result.overall_score <= 39
    assert result.rating_class == "E"
    assert "CAP-RANSOMWARE-ACTIVE" in {c.cap_id for c in result.applied_caps}


def test_cap_non_applicato_senza_validazione(scoring_engine, make_finding, past):
    """Un finding automatico non validato non puo' azzerare il rating."""
    result = scoring_engine.score([
        _cap_finding(make_finding, event_date=past(30), analyst_validation="not_reviewed")])
    assert result.applied_caps == []
    assert result.overall_score > 39


def test_cap_non_applicato_su_evidenza_probabile(scoring_engine, make_finding, past):
    result = scoring_engine.score([
        _cap_finding(make_finding, event_date=past(30), confidence_class="probable")])
    assert result.applied_caps == []


def test_cap_non_applicato_su_asset_non_verificato(scoring_engine, make_finding, past):
    result = scoring_engine.score([
        _cap_finding(make_finding, event_date=past(30), ownership_status="likely_owned")])
    assert result.applied_caps == []


def test_cap_ransomware_scade(scoring_engine, make_finding, past):
    """Oltre la finestra configurata (730 giorni) il cap non si applica piu'."""
    result = scoring_engine.score([_cap_finding(make_finding, event_date=past(900))])
    assert result.applied_caps == []


def test_cap_kev_internet_facing_limita_a_49(scoring_engine, make_finding):
    result = scoring_engine.score([_cap_finding(
        make_finding, finding_type="vulnerability",
        category="technical_vulnerabilities", cve_id="CVE-2023-4966",
        cvss_score=9.4, cisa_kev=True, internet_facing=True,
        asset_key="web:vpn.acme-test.example", detail="CVE-2023-4966")])
    assert result.overall_score <= 49
    assert "CAP-KEV-INTERNET-FACING" in {c.cap_id for c in result.applied_caps}


def test_cap_kev_non_applicato_se_non_esposto(scoring_engine, make_finding):
    result = scoring_engine.score([_cap_finding(
        make_finding, finding_type="vulnerability",
        category="technical_vulnerabilities", cve_id="CVE-2023-4966",
        cvss_score=9.4, cisa_kev=True, internet_facing=False,
        asset_key="web:interno.acme-test.example", detail="CVE-2023-4966")])
    assert "CAP-KEV-INTERNET-FACING" not in {c.cap_id for c in result.applied_caps}


def test_cap_stealer_log_recente_limita_a_59(scoring_engine, make_finding, past):
    result = scoring_engine.score([_cap_finding(
        make_finding, finding_type="stealer_log_credentials",
        event_date=past(30), detail="stealer-log")])
    assert result.overall_score <= 59
    assert "CAP-STEALER-LOG-RECENT" in {c.cap_id for c in result.applied_caps}


def test_cap_stealer_log_vecchio_non_si_applica(scoring_engine, make_finding, past):
    result = scoring_engine.score([_cap_finding(
        make_finding, finding_type="stealer_log_credentials",
        event_date=past(400), detail="stealer-log")])
    assert "CAP-STEALER-LOG-RECENT" not in {c.cap_id for c in result.applied_caps}


def test_cap_piu_restrittivo_prevale(scoring_engine, make_finding, past):
    """Con piu' cap attivi vince il tetto piu' basso."""
    findings = [
        _cap_finding(make_finding, event_date=past(30)),                       # 39
        _cap_finding(make_finding, finding_type="stealer_log_credentials",
                     event_date=past(30), detail="stealer"),                   # 59
    ]
    result = scoring_engine.score(findings)
    assert result.overall_score <= 39
    assert len(result.applied_caps) == 2


def test_punteggio_grezzo_conservato(scoring_engine, make_finding, past):
    """Il punteggio prima del cap resta tracciato per trasparenza."""
    result = scoring_engine.score([_cap_finding(make_finding, event_date=past(30))])
    assert result.raw_weighted_score > result.overall_score
    assert result.cap_applied
