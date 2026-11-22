"""SpiderFoot parlava con una pagina web, non con un'API.

Quattro difetti su una sola chiamata, trovati riproducendo la richiesta contro
un'istanza 4.0 avviata davvero.

1. `/startscan` risponde **303** verso la pagina della scansione se il client
   non chiede JSON. Da httpx 0.24 `raise_for_status()` solleva anche sui 3xx,
   quindi l'adapter interrompeva con `HTTPStatusError` una scansione che
   SpiderFoot aveva avviato correttamente, buttando via il redirect che ne
   portava l'identificativo. Con `Accept: application/json` la risposta e'
   `["SUCCESS", "<id>"]`.
2. `usecase` e' un parametro **obbligatorio** della firma CherryPy: senza, 404.
   Valeva `all`, e SpiderFoot ricade sul `usecase` quando `modulelist` e'
   vuoto: in quel caso avrebbe avviato OGNI modulo, compresi gli attivi che il
   profilo passivo vieta. Va inviato vuoto.
3. Gli errori arrivano con stato **200** e involucro `["ERROR", "<motivo>"]`.
   Leggendo il secondo elemento senza guardare il primo, il motivo diventava
   l'identificativo della scansione.
4. `/scaneventresultexport` produce **CSV**, e il codice ne faceva `.json()`.
   L'eccezione era intercettata e l'adapter concludeva con zero eventi e stato
   «riuscito»: SpiderFoot non ha mai prodotto un rilievo da quando e'
   integrato. Gli eventi in JSON stanno su `/scaneventresults`, dove il tipo e'
   l'undicesima colonna e non la seconda.
"""
from __future__ import annotations

import httpx
import pytest

from adapters.base import AdapterContext, AdapterStatus
from adapters.spiderfoot_adapter import SpiderFootAdapter

BASE = "http://spiderfoot:5001"

# Una riga come la restituisce `/scaneventresults`, verificata su un'istanza
# reale: [0] data/ora, [1] valore, [2] origine, [3] modulo, [4] confidenza,
# [5] visibilita', [6] rischio, [7] impronta, [8] falso positivo,
# [9] falso positivo del padre, [10] tipo.
def _riga(valore: str, tipo: str, *, falso_positivo: str = "0") -> list:
    return ["2026-11-22 23:05:37", valore, "azienda.example", "sfp_prova",
            "100", "100", "0", "ABC123", falso_positivo, "0", tipo]


class _ScopeGuardFinto:
    def filter_targets(self, valori, _tipo):  # noqa: ANN001
        return list(valori)


def _contesto(**extra):
    base = dict(
        scan_id="s-12345678", tenant_id="t", company_id="c", company_name="Azienda",
        profile="public_passive", domains=["azienda.example"],
        verified_domains=["azienda.example"], scope_guard=_ScopeGuardFinto(),
        connector_config={"spiderfoot": {"base_url": BASE}},
        tool_config={"spiderfoot": {"timeout_seconds": 1,
                                    "modules": {"public_passive": ["sfp_prova"]}}},
        mock_mode=False)
    base.update(extra)
    return AdapterContext(**base)


def _esegui(monkeypatch, gestore, **extra):
    adapter = SpiderFootAdapter(_contesto(**extra))
    transport = httpx.MockTransport(gestore)
    originale = httpx.Client

    class ClientFinto(originale):
        def __init__(self, *a, **k):
            k["transport"] = transport
            super().__init__(*a, **k)

    monkeypatch.setattr("adapters.spiderfoot_adapter.httpx.Client", ClientFinto)
    monkeypatch.setattr("adapters.spiderfoot_adapter.time.sleep", lambda _s: None)
    return adapter.execute()


def _istanza_sana(righe=None, stato="FINISHED", avvio=None):
    """Un gestore che si comporta come SpiderFoot 4.0."""
    righe = righe if righe is not None else [_riga("mario@azienda.example", "EMAILADDR")]
    viste: list[httpx.Request] = []

    def gestore(richiesta: httpx.Request) -> httpx.Response:
        viste.append(richiesta)
        percorso = richiesta.url.path
        if percorso == "/ping":
            return httpx.Response(200, json=["SUCCESS", "4.0.0"])
        if percorso == "/startscan":
            if avvio is not None:
                return avvio
            return httpx.Response(200, json=["SUCCESS", "ABC12345"])
        if percorso == "/scanstatus":
            return httpx.Response(200, json=["nome", "azienda.example", "x", "y", "z", stato])
        if percorso == "/scaneventresults":
            return httpx.Response(200, json=righe)
        return httpx.Response(404, text="not found")

    gestore.viste = viste  # type: ignore[attr-defined]
    return gestore


# --------------------------------------------------------------------------
# Che cosa viene chiesto
# --------------------------------------------------------------------------
def test_si_chiede_json_altrimenti_la_risposta_e_una_pagina_web(monkeypatch):
    gestore = _istanza_sana()
    _esegui(monkeypatch, gestore)

    avvii = [r for r in gestore.viste if r.url.path == "/startscan"]
    assert avvii, "nessun avvio di scansione"
    assert avvii[0].headers.get("accept") == "application/json", (
        "senza questa intestazione `/startscan` risponde con un redirect 303")


def test_usecase_viene_inviato_ma_vuoto(monkeypatch):
    """Inviarlo: e' obbligatorio nella firma CherryPy, senza arriva 404.
    Vuoto: `all` avvierebbe ogni modulo quando `modulelist` fosse vuoto,
    compresi quelli attivi che il profilo passivo vieta."""
    gestore = _istanza_sana()
    _esegui(monkeypatch, gestore)

    corpo = next(r for r in gestore.viste if r.url.path == "/startscan").content.decode()

    assert "usecase=" in corpo, "parametro obbligatorio assente: la richiesta riceverebbe 404"
    assert "usecase=all" not in corpo, (
        "`usecase=all` e' una via per avviare ogni modulo, attivi compresi")
    assert "modulelist=module_sfp_prova" in corpo


def test_gli_eventi_si_leggono_dall_endpoint_json(monkeypatch):
    """`/scaneventresultexport` produce CSV: `.json()` sollevava sempre, e
    l'adapter concludeva con zero eventi dichiarando successo."""
    gestore = _istanza_sana()
    _esegui(monkeypatch, gestore)

    percorsi = {r.url.path for r in gestore.viste}

    assert "/scaneventresults" in percorsi
    assert "/scaneventresultexport" not in percorsi, (
        "endpoint CSV: non produce JSON in nessun formato")


# --------------------------------------------------------------------------
# Il redirect non e' un guasto
# --------------------------------------------------------------------------
def test_un_redirect_all_avvio_non_e_un_errore(monkeypatch):
    """E' il guasto che l'utente ha visto: «errore SpiderFoot: HTTPStatusError»
    su scansioni che partivano regolarmente."""
    gestore = _istanza_sana(avvio=httpx.Response(
        303, headers={"location": "http://spiderfoot:5001/scaninfo?id=CD2973B6"}))

    esito = _esegui(monkeypatch, gestore)

    assert esito.status is AdapterStatus.SUCCESS, esito.error_message
    assert any(r.url.params.get("id") == "CD2973B6" for r in gestore.viste), (
        "l'identificativo non e' stato letto dall'indirizzo di destinazione")


def test_un_errore_vero_porta_il_codice_di_stato(monkeypatch):
    """«HTTPStatusError» da solo non dice cosa fare."""
    gestore = _istanza_sana(avvio=httpx.Response(500, text="Internal Server Error"))

    esito = _esegui(monkeypatch, gestore)

    assert esito.status is AdapterStatus.FAILED
    assert "500" in (esito.error_message or ""), esito.error_message
    assert "/startscan" in (esito.error_message or "")


def test_l_involucro_d_errore_non_diventa_un_identificativo(monkeypatch):
    """SpiderFoot risponde 200 con `["ERROR", "<motivo>"]`: il motivo non e'
    un identificativo di scansione."""
    gestore = _istanza_sana(avvio=httpx.Response(
        200, json=["ERROR", "Incorrect usage: no modules specified for scan."]))

    esito = _esegui(monkeypatch, gestore)

    assert esito.status is AdapterStatus.FAILED
    assert "no modules specified" in (esito.error_message or "")
    assert not any(r.url.path == "/scaneventresults" for r in gestore.viste), (
        "ha interrogato una scansione che non esiste")


# --------------------------------------------------------------------------
# Le colonne
# --------------------------------------------------------------------------
def test_il_tipo_si_legge_dall_ultima_colonna_non_dalla_seconda(monkeypatch):
    """Nella seconda c'e' il valore. Leggendolo come tipo, nessun evento
    corrispondeva a niente."""
    gestore = _istanza_sana(righe=[
        _riga("mario.rossi@azienda.example", "EMAILADDR"),
        _riga("portale.azienda.example", "INTERNET_NAME"),
    ])

    esito = _esegui(monkeypatch, gestore)

    tipi = {a.asset_type for a in esito.assets}
    assert tipi == {"email_address", "subdomain"}, tipi


def test_un_falso_positivo_marcato_non_diventa_un_rilievo(monkeypatch):
    gestore = _istanza_sana(righe=[
        _riga("vero@azienda.example", "EMAILADDR"),
        _riga("falso@azienda.example", "EMAILADDR", falso_positivo="1"),
    ])

    esito = _esegui(monkeypatch, gestore)

    chiavi = {a.asset_key for a in esito.assets}
    assert "vero@azienda.example" in chiavi
    assert "falso@azienda.example" not in chiavi


def test_una_violazione_diventa_un_rilievo(monkeypatch):
    gestore = _istanza_sana(righe=[
        _riga("info@azienda.example [LinkedIn]", "EMAILADDR_COMPROMISED")])

    esito = _esegui(monkeypatch, gestore)

    assert esito.evidences, "nessuna evidenza da un indirizzo compromesso"
    assert any("LinkedIn" in e.detail for e in esito.evidences)


# --------------------------------------------------------------------------
# Una scansione che non e' mai partita non e' un successo
# --------------------------------------------------------------------------
@pytest.mark.parametrize("stato", ["CREATED", "RUNNING", "STARTING"])
def test_una_scansione_non_conclusa_non_e_un_successo(monkeypatch, stato):
    """Osservato: senza raggiungere publicsuffix.org, SpiderFoot non riesce a
    inizializzare e la scansione resta in `CREATED` per sempre, senza che
    l'API segnali nulla. Dichiararlo riuscito con zero risultati significa
    concludere che l'organizzazione non e' esposta."""
    gestore = _istanza_sana(righe=[], stato=stato)

    esito = _esegui(monkeypatch, gestore)

    assert esito.status is AdapterStatus.FAILED
    assert stato in (esito.error_message or "")
    assert esito.coverage_impact > 0


@pytest.mark.parametrize("stato", ["ERROR-FAILED", "ABORTED"])
def test_una_scansione_terminata_male_e_un_guasto(monkeypatch, stato):
    gestore = _istanza_sana(righe=[], stato=stato)

    esito = _esegui(monkeypatch, gestore)

    assert esito.status is AdapterStatus.FAILED
    assert stato in (esito.error_message or "")


def test_una_scansione_conclusa_senza_risultati_resta_un_successo(monkeypatch):
    """Il contrario del caso sopra, e va distinto: FINISHED senza eventi
    significa che non c'era nulla da trovare, e non va chiamato guasto."""
    gestore = _istanza_sana(righe=[], stato="FINISHED")

    esito = _esegui(monkeypatch, gestore)

    assert esito.status is AdapterStatus.SUCCESS
    assert esito.coverage_impact == 0.0
