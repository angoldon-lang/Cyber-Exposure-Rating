"""Test end-to-end della pipeline di scansione su dati sintetici."""
from __future__ import annotations

import pytest

from app.workers.pipeline import ScanPipeline, ScanRequest


def _request(**overrides) -> ScanRequest:
    defaults = dict(
        scan_id="test-scan-0001", tenant_id="t1", company_id="c1",
        company_name="ACME Test S.p.A.", profile="verified_standard",
        domains=["acme-test.example"], verified_domains=["acme-test.example"],
        ip_addresses=["203.0.113.10"], authorized_ips=["203.0.113.10"],
        network_ranges=["203.0.113.0/24"], mock_mode=True,
        connector_config={"hibp": {"mock_enabled": True},
                          "synthetic": {"severity_bias": 0.5}})
    defaults.update(overrides)
    return ScanRequest(**defaults)


@pytest.fixture(scope="module")
def outcome():
    return ScanPipeline(_request()).run()


def test_scansione_completata(outcome):
    assert outcome.status in {"completed", "partial"}
    assert outcome.stats["tools_total"] > 5


def test_produce_asset_evidenze_e_finding(outcome):
    assert len(outcome.normalization.assets) > 0
    assert len(outcome.normalization.evidences) > 0
    assert len(outcome.normalization.findings) > 0


def test_deduplicazione_effettiva(outcome):
    assert len(outcome.normalization.findings) <= len(outcome.normalization.evidences)


def test_punteggio_e_classe_coerenti(outcome):
    assert 0 <= outcome.scoring.overall_score <= 100
    assert outcome.scoring.rating_class in {"A", "B", "C", "D", "E"}
    for category in outcome.scoring.categories:
        assert 0 <= category.score <= 100


def test_cinque_aree_calcolate(outcome):
    assert len(outcome.scoring.categories) == 5


def test_confidence_calcolata(outcome):
    assert 0 <= outcome.confidence.value <= 100
    assert outcome.confidence.coverage_matrix


def test_ogni_tool_ha_un_esito(outcome):
    stati = {run["status"] for run in outcome.tool_runs}
    assert stati <= {"success", "partial", "failed", "skipped"}
    assert all(run["tool_key"] for run in outcome.tool_runs)


def test_pipeline_deterministica():
    prima = ScanPipeline(_request()).run()
    seconda = ScanPipeline(_request()).run()
    assert prima.scoring.overall_score == seconda.scoring.overall_score
    assert prima.scoring.rating_class == seconda.scoring.rating_class


def test_profilo_passivo_esclude_i_tool_attivi():
    outcome = ScanPipeline(_request(profile="public_passive")).run()
    eseguiti = {run["tool_key"] for run in outcome.tool_runs}
    for attivo in ("httpx", "testssl", "nuclei", "naabu", "zap_baseline"):
        assert attivo not in eseguiti


def test_fallimento_di_un_tool_non_ferma_la_scansione(monkeypatch):
    """Un adapter che esplode riduce la copertura, non blocca la scansione."""
    from adapters.checkdmarc_adapter import CheckDMARCAdapter

    def esplodi(self):
        raise RuntimeError("guasto simulato")

    monkeypatch.setattr(CheckDMARCAdapter, "mock", esplodi)
    outcome = ScanPipeline(_request()).run()
    assert outcome.status == "partial"
    falliti = [r for r in outcome.tool_runs if r["status"] == "failed"]
    assert any(r["tool_key"] == "checkdmarc" for r in falliti)
    # Gli altri strumenti hanno comunque prodotto risultati.
    assert len(outcome.normalization.findings) > 0


def test_tool_fallito_abbassa_la_confidence(monkeypatch):
    from adapters.checkdmarc_adapter import CheckDMARCAdapter
    from adapters.httpx_adapter import HTTPXAdapter

    integra = ScanPipeline(_request()).run().confidence.value

    def esplodi(self):
        raise RuntimeError("guasto simulato")

    monkeypatch.setattr(CheckDMARCAdapter, "mock", esplodi)
    monkeypatch.setattr(HTTPXAdapter, "mock", esplodi)
    degradata = ScanPipeline(_request()).run().confidence.value
    assert degradata < integra


def test_asset_di_terzi_esclusi_dal_rating(outcome):
    for asset in outcome.normalization.assets:
        if asset.ownership.status == "third_party":
            assert not asset.scores_toward_rating


def test_nessun_asset_fuori_perimetro():
    """Tutti gli asset che pesano sul rating devono essere riconducibili
    ai domini dichiarati o verificati."""
    outcome = ScanPipeline(_request()).run()
    for asset in outcome.normalization.assets:
        if not asset.scores_toward_rating:
            continue
        chiave = asset.asset_key.split(":")[-1]
        assert ("acme-test.example" in chiave or chiave.startswith("203.0.113.")
                or chiave.startswith("198.51.100.")), asset.asset_key


def test_output_grezzo_conservato(outcome):
    assert outcome.raw_outputs
    for payload in outcome.raw_outputs.values():
        assert isinstance(payload, bytes)


def test_statistiche_complete(outcome):
    for chiave in ("tools_total", "tools_failed", "overall_score", "rating_class",
                   "confidence", "is_provisional", "findings_after_dedup"):
        assert chiave in outcome.stats


def test_azienda_pulita_ottiene_rating_alto():
    outcome = ScanPipeline(_request(
        connector_config={"synthetic": {"severity_bias": 0.0}})).run()
    assert outcome.scoring.overall_score >= 55
    assert outcome.scoring.rating_class in {"A", "B", "C"}


def test_azienda_compromessa_ottiene_rating_basso():
    outcome = ScanPipeline(_request(
        connector_config={"hibp": {"mock_enabled": True},
                          "synthetic": {"severity_bias": 1.0}})).run()
    assert outcome.scoring.overall_score < 60


def test_perimetro_vuoto_non_produce_risultati():
    """Senza alcun target gli strumenti non hanno nulla da analizzare: il
    risultato non e' un'azienda sicura, e' una valutazione non attendibile."""
    outcome = ScanPipeline(_request(
        domains=[], verified_domains=[], ip_addresses=[], authorized_ips=[],
        network_ranges=[])).run()
    assert outcome.normalization.findings == []
    assert outcome.scoring.overall_score == 100.0
    assert not outcome.confidence.is_publishable
    assert "empty_scope" in {p["key"] for p in outcome.confidence.penalties}


def test_perimetro_di_soli_ip_resta_valido():
    """Un perimetro composto da soli IP autorizzati e' legittimo: non deve
    essere trattato come perimetro vuoto."""
    outcome = ScanPipeline(_request(domains=[], verified_domains=[])).run()
    assert "empty_scope" not in {p["key"] for p in outcome.confidence.penalties}
