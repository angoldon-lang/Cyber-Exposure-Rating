"""Test del motore di scoring deterministico (sezione 12)."""
from __future__ import annotations

import math

import pytest

pytestmark = pytest.mark.scoring


def test_configurazione_valida(scoring_engine):
    """I pesi delle cinque aree devono sommare esattamente a 1.0."""
    weights = [c["weight"] for c in scoring_engine.config["categories"].values()]
    assert math.isclose(sum(weights), 1.0, abs_tol=1e-9)
    assert len(weights) == 5


def test_pesi_conformi_alla_specifica(scoring_engine):
    categories = scoring_engine.config["categories"]
    assert categories["attack_surface"]["weight"] == 0.20
    assert categories["technical_vulnerabilities"]["weight"] == 0.25
    assert categories["web_security"]["weight"] == 0.20
    assert categories["email_dns_security"]["weight"] == 0.20
    assert categories["darkweb_breach"]["weight"] == 0.15


def test_azienda_senza_rilievi_ottiene_cento(scoring_engine):
    result = scoring_engine.score([])
    assert result.overall_score == 100.0
    assert result.rating_class == "A"


def test_determinismo(scoring_engine, make_finding, now):
    """Stessi input e stessa configurazione producono lo stesso punteggio."""
    findings = [
        make_finding(finding_type="dmarc_missing"),
        make_finding(finding_type="spf_missing", finding_id="F-A"),
        make_finding(finding_type="hsts_missing", category="web_security",
                     severity="medium", asset_key="web:www.acme-test.example"),
    ]
    first = scoring_engine.score(findings, now=now)
    second = scoring_engine.score(list(reversed(findings)), now=now)
    assert first.overall_score == second.overall_score
    assert first.rating_class == second.rating_class


@pytest.mark.parametrize(
    ("score", "expected"),
    [(100, "A"), (92, "A"), (85, "A"), (84, "B"), (70, "B"),
     (69, "C"), (55, "C"), (54, "D"), (40, "D"), (39, "E"), (0, "E")],
)
def test_classi_di_rating(scoring_engine, score, expected):
    assert scoring_engine._classify(score)[0] == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [(84.9, "B"), (84.1, "B"), (69.9, "C"), (69.5, "C"),
     (54.9, "D"), (54.46, "D"), (39.9, "E"), (39.5, "E")],
)
def test_punteggi_frazionari_fra_due_classi(scoring_engine, score, expected):
    """I punteggi fra due soglie non devono ricadere nella classe peggiore."""
    assert scoring_engine._classify(score)[0] == expected


def test_scala_delle_classi_continua(scoring_engine):
    """Ogni punteggio da 0 a 100, a passi di 0.1, riceve una classe coerente."""
    from app.services.scoring import class_for_score

    precedente = None
    for centesimi in range(0, 1001):
        score = centesimi / 10
        classe = scoring_engine._classify(score)[0]
        assert classe in {"A", "B", "C", "D", "E"}
        assert class_for_score(score) == classe
        if precedente is not None:
            # Salendo di punteggio la classe non puo' peggiorare.
            assert "ABCDE".index(classe) <= "ABCDE".index(precedente)
        precedente = classe


# --------------------------------------------------------------------------
# Moltiplicatori di confidence e ownership
# --------------------------------------------------------------------------
def test_confidence_confermata_applica_detrazione_piena(scoring_engine, make_finding):
    result = scoring_engine.score([make_finding(confidence_class="confirmed")])
    email = next(c for c in result.categories if c.key == "email_dns_security")
    assert email.total_deduction == 25.0  # EML-DMARC-MISSING


def test_confidence_probabile_dimezza_la_detrazione(scoring_engine, make_finding):
    result = scoring_engine.score([make_finding(confidence_class="probable")])
    email = next(c for c in result.categories if c.key == "email_dns_security")
    assert email.total_deduction == 12.5


@pytest.mark.parametrize("confidence", ["inferred", "informational"])
def test_confidence_dedotta_non_detrae(scoring_engine, make_finding, confidence):
    """Un'evidenza dedotta o informativa e' solo informazione: nessuna detrazione."""
    result = scoring_engine.score([make_finding(confidence_class=confidence)])
    assert result.overall_score == 100.0


@pytest.mark.parametrize("state", ["false_positive", "resolved", "accepted_risk"])
def test_stati_non_attivi_esclusi_dal_calcolo(scoring_engine, make_finding, state):
    result = scoring_engine.score([make_finding(confidence_class=state)])
    assert result.overall_score == 100.0


def test_ownership_verificata_pesa_il_doppio_di_probabile(scoring_engine, make_finding):
    verified = scoring_engine.score([make_finding(ownership_status="verified_owned")])
    likely = scoring_engine.score([make_finding(ownership_status="likely_owned")])
    v_email = next(c for c in verified.categories if c.key == "email_dns_security")
    l_email = next(c for c in likely.categories if c.key == "email_dns_security")
    assert v_email.total_deduction == pytest.approx(2 * l_email.total_deduction)


@pytest.mark.parametrize("ownership", ["unverified", "third_party", "excluded"])
def test_asset_non_di_proprieta_non_incidono(scoring_engine, make_finding, ownership):
    """CDN, cloud e asset di terzi non devono influenzare il rating."""
    result = scoring_engine.score([make_finding(ownership_status=ownership)])
    assert result.overall_score == 100.0


def test_analista_esclude_il_rilievo(scoring_engine, make_finding):
    result = scoring_engine.score([make_finding(excluded_from_rating=True)])
    assert result.overall_score == 100.0


def test_falso_positivo_dichiarato_non_incide(scoring_engine, make_finding):
    result = scoring_engine.score(
        [make_finding(analyst_validation="rejected_false_positive")])
    assert result.overall_score == 100.0


# --------------------------------------------------------------------------
# Deduplicazione e tetti
# --------------------------------------------------------------------------
def test_stesso_problema_da_piu_tool_penalizza_una_volta(scoring_engine, make_finding):
    """Due finding identici sullo stesso asset non devono raddoppiare la pena."""
    duplicated = [
        make_finding(finding_id="F-1", finding_type="hsts_missing",
                     category="web_security", asset_key="web:www.acme-test.example"),
        make_finding(finding_id="F-2", finding_type="hsts_missing",
                     category="web_security", asset_key="web:www.acme-test.example"),
    ]
    single = scoring_engine.score([duplicated[0]])
    both = scoring_engine.score(duplicated)
    assert single.overall_score == both.overall_score


def test_tetto_per_regola(scoring_engine, make_finding):
    """WEB-HSTS-MISSING: 7 punti per host, massimo 21."""
    findings = [
        make_finding(finding_id=f"F-{i}", finding_type="hsts_missing",
                     category="web_security", severity="medium",
                     asset_key=f"web:host{i}.acme-test.example")
        for i in range(10)
    ]
    result = scoring_engine.score(findings)
    web = next(c for c in result.categories if c.key == "web_security")
    assert web.total_deduction == 21.0


def test_tetto_per_causa_radice(scoring_engine, make_finding):
    """Il gruppo `web_headers` non puo' superare 30 punti complessivi."""
    types = ["hsts_missing", "csp_missing", "clickjacking_protection_missing",
             "x_content_type_options_missing", "referrer_policy_missing",
             "permissions_policy_missing"]
    findings = [
        make_finding(finding_id=f"F-{t}-{i}", finding_type=t, category="web_security",
                     severity="medium", asset_key=f"web:host{i}.acme-test.example")
        for t in types for i in range(8)
    ]
    result = scoring_engine.score(findings)
    assert result.trace["root_cause_totals"]["web_headers"] <= 30.0


def test_una_cve_non_e_penalizzata_da_piu_regole(scoring_engine, make_finding):
    """Una CVE in KEV con CVSS 9.8 ed EPSS alto attiverebbe tre regole:
    il gruppo esclusivo garantisce che si applichi solo la piu' severa."""
    finding = make_finding(
        finding_type="vulnerability", category="technical_vulnerabilities",
        severity="critical", cve_id="CVE-2021-44228", cvss_score=10.0,
        epss_score=0.97, cisa_kev=True, asset_key="web:vpn.acme-test.example")
    result = scoring_engine.score([finding])
    vuln = next(c for c in result.categories if c.key == "technical_vulnerabilities")
    # Solo VUL-KEV-CONFIRMED (40), non 40+25+10.
    assert vuln.total_deduction == 40.0
    applied = {d.rule_id for d in vuln.deductions}
    assert applied == {"VUL-KEV-CONFIRMED"}


def test_punteggio_categoria_non_scende_sotto_zero(scoring_engine, make_finding):
    findings = [
        make_finding(finding_id=f"F-{i}", finding_type="vulnerability",
                     category="technical_vulnerabilities", severity="critical",
                     cve_id=f"CVE-2024-{1000 + i}", cvss_score=10.0, cisa_kev=True,
                     asset_key=f"web:host{i}.acme-test.example")
        for i in range(20)
    ]
    result = scoring_engine.score(findings)
    for category in result.categories:
        assert 0.0 <= category.score <= 100.0
    assert 0.0 <= result.overall_score <= 100.0


# --------------------------------------------------------------------------
# Decadimento temporale
# --------------------------------------------------------------------------
def test_breach_vecchio_pesa_meno_di_uno_recente(scoring_engine, make_finding, past):
    recent = scoring_engine.score([make_finding(
        finding_type="breach_credentials_recent", category="darkweb_breach",
        severity="high", event_date=past(10), detail="Breach recente")])
    old = scoring_engine.score([make_finding(
        finding_type="breach_credentials_old", category="darkweb_breach",
        severity="medium", event_date=past(2000), detail="Breach del 2013")])
    recent_dw = next(c for c in recent.categories if c.key == "darkweb_breach")
    old_dw = next(c for c in old.categories if c.key == "darkweb_breach")
    assert recent_dw.total_deduction > old_dw.total_deduction


def test_stealer_log_recente_pesa_piu_di_un_vecchio_breach(scoring_engine, make_finding, past):
    stealer = scoring_engine.score([make_finding(
        finding_type="stealer_log_credentials", category="darkweb_breach",
        severity="critical", event_date=past(20), detail="stealer")])
    breach = scoring_engine.score([make_finding(
        finding_type="breach_credentials_old", category="darkweb_breach",
        severity="medium", event_date=past(1500), detail="breach")])
    s_dw = next(c for c in stealer.categories if c.key == "darkweb_breach")
    b_dw = next(c for c in breach.categories if c.key == "darkweb_breach")
    assert s_dw.total_deduction > b_dw.total_deduction


def test_decadimento_rispetta_il_valore_minimo(scoring_engine, make_finding, past):
    """Anche molto vecchia, una pubblicazione ransomware mantiene il 50%."""
    result = scoring_engine.score([make_finding(
        finding_type="ransomware_leak_publication", category="darkweb_breach",
        severity="critical", event_date=past(4000), detail="gruppo:2015-01-01")])
    dw = next(c for c in result.categories if c.key == "darkweb_breach")
    assert dw.total_deduction == pytest.approx(60 * 0.5)


# --------------------------------------------------------------------------
# Tracciabilita'
# --------------------------------------------------------------------------
def test_ogni_detrazione_e_tracciata(scoring_engine, make_finding):
    result = scoring_engine.score([make_finding()])
    email = next(c for c in result.categories if c.key == "email_dns_security")
    deduction = email.deductions[0]
    assert deduction.rule_id == "EML-DMARC-MISSING"
    assert deduction.finding_id == "F-001"
    assert deduction.confidence_multiplier == 1.0
    assert deduction.ownership_multiplier == 1.0
    assert "remediation" not in deduction.as_dict()  # la remediation vive altrove


def test_motivo_dello_scarto_registrato(scoring_engine, make_finding):
    result = scoring_engine.score([make_finding(ownership_status="unverified")])
    reasons = " ".join(entry["reason"] for entry in result.trace["skipped"])
    assert "ownership" in reasons


def test_versione_configurazione_esposta(scoring_engine, make_finding):
    result = scoring_engine.score([make_finding()])
    assert result.config_version == scoring_engine.config["version"]
