"""Test del confidence score (sezione 13)."""
from __future__ import annotations


from app.services.confidence import ConfidenceInput, ToolRunSummary


def _runs(success: int, failed: int = 0, optional_ok: int = 0) -> list[ToolRunSummary]:
    runs = [ToolRunSummary(f"tool-ok-{i}", "success", areas=("attack_surface",))
            for i in range(success)]
    runs += [ToolRunSummary(f"tool-ko-{i}", "failed", coverage_impact=1.0)
             for i in range(failed)]
    runs += [ToolRunSummary(f"opt-{i}", "success", optional=True)
             for i in range(optional_ok)]
    return runs


def _base(**overrides) -> ConfidenceInput:
    defaults = dict(
        profile="verified_standard", domains_total=1, domains_verified=1,
        ips_total=2, ips_authorized=2, assets_total=20, assets_with_ownership=20,
        technologies_total=10, technologies_with_version=8,
        critical_high_findings=4, critical_high_validated=4,
        distinct_sources=8, tool_runs=_runs(8, optional_ok=1),
        optional_apis_configured=1, optional_apis_available=1,
        darkweb_sources_available=1, darkweb_sources_expected=1,
        evidence_ages_days=[2.0, 3.0, 1.0])
    defaults.update(overrides)
    return ConfidenceInput(**defaults)


def test_scenario_ottimale_alta_affidabilita(confidence_engine):
    result = confidence_engine.compute(_base())
    assert result.value >= 85
    assert result.is_publishable


def test_dominio_non_verificato_abbassa_la_confidence(confidence_engine):
    verified = confidence_engine.compute(_base()).value
    unverified = confidence_engine.compute(_base(domains_verified=0)).value
    assert unverified < verified


def test_penalita_dominio_non_verificato_registrata(confidence_engine):
    result = confidence_engine.compute(_base(domains_verified=0))
    assert "no_domain_verified" in {p["key"] for p in result.penalties}


def test_tool_falliti_abbassano_la_confidence(confidence_engine):
    ok = confidence_engine.compute(_base(tool_runs=_runs(8))).value
    ko = confidence_engine.compute(_base(tool_runs=_runs(4, failed=4))).value
    assert ko < ok


def test_tutti_i_tool_falliti_penalizzati(confidence_engine):
    result = confidence_engine.compute(
        _base(domains_verified=1, tool_runs=_runs(0, failed=6)))
    assert "all_tools_failed" in {p["key"] for p in result.penalties}


def test_profilo_passivo_meno_affidabile_di_esteso(confidence_engine):
    passive = confidence_engine.compute(_base(profile="public_passive")).value
    extended = confidence_engine.compute(_base(profile="verified_extended")).value
    assert passive < extended


def test_evidenze_vecchie_abbassano_la_confidence(confidence_engine):
    fresh = confidence_engine.compute(_base(evidence_ages_days=[1.0, 2.0])).value
    stale = confidence_engine.compute(_base(evidence_ages_days=[400.0, 500.0])).value
    assert stale < fresh


def test_scenario_minimo_non_pubblicabile(confidence_engine):
    """Con dominio non verificato, tool falliti e poche fonti il rating
    non e' pubblicabile e va presentato come provvisorio."""
    result = confidence_engine.compute(ConfidenceInput(
        profile="public_passive", domains_total=1, domains_verified=0,
        assets_total=10, assets_with_ownership=2, distinct_sources=1,
        tool_runs=_runs(0, failed=4), evidence_ages_days=[300.0]))
    assert result.value < 50
    assert not result.is_publishable


def test_confidence_sempre_nel_range(confidence_engine):
    for data in (_base(), _base(domains_verified=0, tool_runs=_runs(0, failed=9)),
                 _base(distinct_sources=100)):
        result = confidence_engine.compute(data)
        assert 0.0 <= result.value <= 100.0


def test_fattori_tracciati(confidence_engine):
    result = confidence_engine.compute(_base())
    assert "tool_success_rate" in result.factors
    assert "domain_verified" in result.factors
    for factor in result.factors.values():
        assert "note" in factor and "earned" in factor


def test_matrice_di_copertura_prodotta(confidence_engine):
    result = confidence_engine.compute(_base(tool_runs=_runs(3, failed=1)))
    assert len(result.coverage_matrix) == 4
    assert any(entry["status"] == "failed" for entry in result.coverage_matrix)


def test_modello_non_satura(confidence_engine):
    """I pesi sommano a 100: il punteggio massimo si raggiunge solo con
    copertura totale, cosi' la scala discrimina anche nella parte alta."""
    total = sum(f["weight"] for f in confidence_engine.config["factors"].values())
    assert total == 100
    assert confidence_engine.config["base"] == 0
    perfetto = confidence_engine.compute(_base()).value
    quasi = confidence_engine.compute(_base(technologies_with_version=2)).value
    assert quasi < perfetto <= 100


def test_confidence_non_modifica_il_rating(scoring_engine, confidence_engine, make_finding):
    """Il confidence e' un indice separato: non entra nel calcolo del punteggio."""
    findings = [make_finding()]
    score = scoring_engine.score(findings).overall_score
    for data in (_base(), _base(domains_verified=0, tool_runs=_runs(0, failed=8))):
        confidence_engine.compute(data)
        assert scoring_engine.score(findings).overall_score == score


# ---------------------------------------------------------------------------
# Assenze che non sono guasti
# ---------------------------------------------------------------------------
def test_uno_strumento_sostituito_non_abbassa_la_quota_di_riusciti(confidence_engine):
    """naabu non esiste per arm64 e la stessa area la copre `port_scan`. La
    quota di strumenti riusciti e' un indicatore di salute della piattaforma:
    contarci dentro un'assenza prevista la fa scendere senza che ci sia niente
    da sistemare, e le toglie il significato che aveva."""
    sano = confidence_engine.compute(_base(tool_runs=_runs(8))).value
    con_sostituito = confidence_engine.compute(_base(tool_runs=_runs(8) + [
        ToolRunSummary("naabu", "skipped", replaced_successfully=True)])).value

    assert con_sostituito == sano


def test_un_sostituto_fallito_lascia_la_lacuna_dov_era(confidence_engine):
    """Altrimenti basterebbe dichiarare una sostituzione per far sparire una
    lacuna: la sostituzione vale solo se il sostituto e' riuscito davvero."""
    sano = confidence_engine.compute(_base(tool_runs=_runs(8))).value
    con_lacuna = confidence_engine.compute(_base(tool_runs=_runs(8) + [
        ToolRunSummary("naabu", "skipped", coverage_impact=1.0,
                       replaced_successfully=False)])).value

    assert con_lacuna < sano


def test_uno_strumento_in_attesa_di_un_dato_non_e_un_insuccesso(confidence_engine):
    """`email_header` esamina l'intestazione di un messaggio, che la incolla un
    analista: senza, resta saltato per sempre. L'area resta non verificata e il
    suo peso continua a contare; cio' che non deve contare e' il guasto, perche'
    non c'e'."""
    sano = confidence_engine.compute(_base(tool_runs=_runs(8))).value
    in_attesa = confidence_engine.compute(_base(tool_runs=_runs(8) + [
        ToolRunSummary("email_header", "skipped", requires_input=True)])).value

    assert in_attesa == sano


def test_uno_strumento_in_attesa_che_pero_fallisce_resta_un_guasto(confidence_engine):
    """Il dato e' arrivato e l'analisi e' andata male: e' un guasto come un
    altro, e deve pesare come tale."""
    sano = confidence_engine.compute(_base(tool_runs=_runs(8))).value
    guasto = confidence_engine.compute(_base(tool_runs=_runs(8) + [
        ToolRunSummary("email_header", "failed", requires_input=True,
                       coverage_impact=0.7)])).value

    assert guasto < sano


def test_la_nota_dice_quali_strumenti_non_sono_stati_conteggiati(confidence_engine):
    """Un denominatore che cambia senza spiegazione e' peggio di una penalita':
    chi legge il fattore deve poter vedere che cosa e' stato escluso."""
    esito = confidence_engine.compute(_base(tool_runs=_runs(8) + [
        ToolRunSummary("naabu", "skipped", replaced_successfully=True),
        ToolRunSummary("email_header", "skipped", requires_input=True)]))

    nota = esito.factors["tool_success_rate"]["note"]

    assert "naabu" in nota and "email_header" in nota
