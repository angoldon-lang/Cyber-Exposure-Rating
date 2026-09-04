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
