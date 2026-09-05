"""Bersagli degli strumenti e indirizzi delle fonti esterne.

Due classi di guasto silenzioso: uno strumento che filtra i propri bersagli
con il controllo sbagliato li scarta tutti e dichiara «nessun host in
perimetro»; una fonte il cui endpoint non esiste piu' risponde con la pagina
HTML della documentazione e fallisce con un errore che non nomina la causa.
"""
from __future__ import annotations

import inspect

import httpx
import pytest

from adapters.base import AdapterStatus
from adapters.ransomware_live_adapter import RansomwareLiveAdapter, _json_o_errore, _motivo
from tests.test_company_crud import admin, client, tenant_unico  # noqa: F401

pytestmark = pytest.mark.security


# ------------------------------------------------------------------ bersagli
def test_ogni_strumento_filtra_i_bersagli_con_il_controllo_giusto():
    """`web_targets` contiene URL, `known_subdomains` e `domains` nomi host.

    Filtrare URL con il controllo per hostname li scarta tutti: lo strumento
    risulta eseguito, non produce nulla e dichiara un perimetro vuoto anche
    quando il perimetro e' corretto. E' successo a testssl.
    """
    import adapters.httpx_adapter as m_httpx
    import adapters.phase2 as m_phase2
    import adapters.testssl_adapter as m_testssl

    for modulo in (m_httpx, m_testssl, m_phase2):
        # Le chiamate vanno a capo: il confronto e' su una forma compattata.
        compattato = " ".join(inspect.getsource(modulo).split())
        assert 'web_targets, "hostname"' not in compattato, (
            f"{modulo.__name__} filtra URL con il controllo per hostname: "
            "li scarta tutti e dichiara un perimetro vuoto")


def test_testssl_usa_i_sottodomini_scoperti(adapter_context):
    """Regressione: filtrava `web_targets` («https://host») come hostname e
    restava senza bersagli a ogni scansione."""
    from adapters.testssl_adapter import TestSSLAdapter

    adapter_context.mock_mode = False
    adapter_context.known_subdomains = ["www.acme-test.example"]
    adapter_context.web_targets = ["https://www.acme-test.example"]

    sorgente = inspect.getsource(TestSSLAdapter.execute)
    assert "known_subdomains" in sorgente
    assert "self.context.web_targets" not in sorgente

    adattatore = TestSSLAdapter(adapter_context)
    bersagli = adattatore.context.scope_guard.filter_targets(
        adattatore.context.known_subdomains, "hostname")
    assert bersagli == ["www.acme-test.example"]


# -------------------------------------------------------------------- fonti
def test_l_indirizzo_di_ransomware_live_include_la_versione(adapter_context):
    """La v1 non serve piu' `searchvictims`: risponde 302 e rimanda alla
    documentazione HTML. Il prefisso di versione fa parte dell'indirizzo."""
    adapter_context.connector_config = {}
    assert RansomwareLiveAdapter(adapter_context).base_url.endswith("/v2")


def test_una_risposta_html_dice_perche_non_e_utilizzabile():
    """Un JSONDecodeError nudo non aiuta: la causa e' un endpoint non piu'
    valido, e il rimedio e' aggiornare l'indirizzo, non riprovare."""
    risposta = httpx.Response(
        200, headers={"content-type": "text/html; charset=utf-8"},
        text="<html><body>API documentation</body></html>",
        request=httpx.Request("GET", "https://www.ransomware.live/api"))
    with pytest.raises(Exception) as errore:
        _json_o_errore(risposta)
    messaggio = _motivo(errore.value)
    assert "non JSON" in messaggio
    assert "non e' piu' valido" in messaggio
    assert "JSONDecodeError" not in messaggio


def test_una_risposta_json_passa():
    risposta = httpx.Response(
        200, headers={"content-type": "application/json"}, json=[{"victim": "ACME"}],
        request=httpx.Request("GET", "https://api.ransomware.live/v2/searchvictims/acme"))
    assert _json_o_errore(risposta) == [{"victim": "ACME"}]


def test_il_nome_dell_azienda_e_codificato_nell_url():
    """Un nome con spazi, `&` o `/` costruito a mano rompe l'indirizzo o, peggio,
    cambia il percorso della richiesta."""
    sorgente = inspect.getsource(RansomwareLiveAdapter.execute)
    assert "quote(" in sorgente
    assert "replace(' ', '%20')" not in sorgente


def test_il_fallimento_della_fonte_non_ferma_la_scansione(adapter_context, monkeypatch):
    """Il contratto degli adapter: nessun esito, nemmeno il fallimento, puo'
    interrompere la scansione."""
    adapter_context.mock_mode = False

    def esplode(*_a, **_k):
        raise httpx.ConnectError("rete assente")

    monkeypatch.setattr("adapters.ransomware_live_adapter.get_seguendo_redirect", esplode)
    esito = RansomwareLiveAdapter(adapter_context).run()
    assert esito.status in {AdapterStatus.FAILED, AdapterStatus.SKIPPED}
    assert esito.coverage_impact > 0


# ------------------------------------------------------- rilievi da validare
def test_il_filtro_dei_rilievi_da_validare_usa_lo_stesso_criterio_dell_avviso():
    """L'avviso in dashboard conta i critici e alti non ancora validati.

    Se il filtro dell'elenco usasse un criterio proprio, l'avviso potrebbe
    annunciare quattro rilievi e l'elenco mostrarne tre, senza che nulla
    spieghi la differenza. Il criterio vive nell'API, una volta sola.
    """
    from app.api.routers import findings as router
    from app.services import review

    filtro = inspect.getsource(router.list_findings)
    conteggio = inspect.getsource(review.review_progress)
    for frammento in ("CRITICAL", "HIGH", "NOT_REVIEWED"):
        assert frammento in filtro, f"il filtro non considera {frammento}"
    assert "SEVERITY_RANK[Severity.HIGH.value]" in conteggio


def test_il_rilievo_porta_alla_sua_remediation():
    """Dal rilievo non si raggiungeva l'intervento che lo risolve: restava al
    lettore ricordare quale voce del piano lo riguardasse."""
    from app.schemas.scanning import FindingRead

    campi = FindingRead.model_fields
    assert "remediation_catalog_id" in campi
    assert "remediation_title_it" in campi


@pytest.mark.slow
def test_il_conteggio_dell_avviso_e_l_elenco_coincidono(client, admin):  # noqa: F811
    """Verifica sui dati, non sul codice: l'avviso annuncia N rilievi e
    l'elenco filtrato ne restituisce esattamente N."""
    import uuid
    from datetime import UTC, datetime

    from app.models.enums import ScanStatus
    from app.models.scanning import Scan
    from app.services.persistence import persist_outcome
    from app.workers.pipeline import ScanPipeline, ScanRequest
    from tests.test_company_crud import _azienda

    azienda = _azienda(client, admin)
    dominio = "acme-validazione.example"
    with client.session_factory() as db:
        scansione = Scan(
            tenant_id=uuid.UUID(azienda["tenant_id"]), company_id=uuid.UUID(azienda["id"]),
            profile_key="verified_standard", status=ScanStatus.RUNNING.value, mock_mode=True,
            started_at=datetime.now(UTC),
            scope_snapshot_json={"domains": [dominio], "verified_domains": [dominio]})
        db.add(scansione)
        db.commit()
        scan_id = scansione.id

    esito = ScanPipeline(ScanRequest(
        scan_id=str(scan_id), tenant_id=azienda["tenant_id"], company_id=azienda["id"],
        company_name=azienda["legal_name"], profile="verified_standard",
        domains=[dominio], verified_domains=[dominio], mock_mode=True,
        connector_config={"synthetic": {"severity_bias": 0.8}})).run()
    with client.session_factory() as db:
        persist_outcome(db, db.get(Scan, scan_id), esito)
        db.commit()

    cruscotto = client.get(f"/api/v1/companies/{azienda['id']}/dashboard", headers=admin).json()
    attesi = cruscotto["review_progress"]["critical_high_pending"]
    assert attesi > 0, "fixture non rappresentativa: nessun rilievo da validare"

    elenco = client.get(f"/api/v1/scans/{scan_id}/findings?pending_review=true",
                        headers=admin).json()
    assert elenco["total"] == attesi
    assert all(v["severity"] in {"critical", "high"} for v in elenco["items"])
    assert all(v["analyst_validation"] == "not_reviewed" for v in elenco["items"])
