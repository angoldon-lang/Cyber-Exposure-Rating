"""ZAP Baseline gira come servizio a se', comandato via API.

L'adapter era un abbozzo: `execute` restituiva sempre «saltato», e il motivo
dichiarato era che avviare l'immagine ZAP richiede un runtime Docker dentro
il worker. Quella richiesta era sbagliata in partenza: il socket Docker
dentro un contenitore equivale al root sull'host, e un contenitore che esegue
scansioni non deve poterlo avere.

Il demone ZAP sta quindi nel compose, accanto agli altri servizi, e il worker
lo comanda sulla rete interna — lo stesso schema di SpiderFoot.
"""
from __future__ import annotations

import httpx
import pytest

from adapters.base import AdapterStatus
from adapters.phase2 import ZAPBaselineAdapter
from adapters.runner import UnsafeCommandError

pytestmark = pytest.mark.security

BASE = "http://zap:8090"
CHIAVE = "chiave-di-prova"


def _adattatore(adapter_context, gestore, **config):  # noqa: ANN001, ANN202
    import adapters.phase2 as modulo

    adapter_context.connector_config = {
        **adapter_context.connector_config,
        "zap": {"base_url": BASE, "api_key": CHIAVE},
    }
    adapter_context.web_targets = ["https://acme-test.example"]

    originale = modulo.httpx.Client

    class ClientFinto(originale):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            kwargs["transport"] = httpx.MockTransport(gestore)
            super().__init__(*args, **kwargs)

    modulo.httpx.Client = ClientFinto
    try:
        strumento = ZAPBaselineAdapter(adapter_context)
        strumento.config = {**strumento.config, **config}
        return strumento
    finally:
        pass


def _ripristina(modulo, originale):  # noqa: ANN001, ANN202
    modulo.httpx.Client = originale


def _zap_che_funziona(richieste: list[httpx.Request]):  # noqa: ANN202
    def gestore(richiesta: httpx.Request) -> httpx.Response:
        richieste.append(richiesta)
        percorso = richiesta.url.path
        if percorso == "/JSON/spider/action/scan/":
            return httpx.Response(200, json={"scan": "1"})
        if percorso == "/JSON/spider/view/status/":
            return httpx.Response(200, json={"status": "100"})
        if percorso == "/JSON/pscan/view/recordsToScan/":
            return httpx.Response(200, json={"recordsToScan": "0"})
        if percorso == "/JSON/core/view/alerts/":
            return httpx.Response(200, json={"alerts": [
                {"pluginid": "10035", "name": "Strict-Transport-Security Header Not Set",
                 "desc": "HSTS non presente."},
                {"pluginid": "10038", "name": "CSP Header Not Set", "desc": "CSP assente."},
                {"pluginid": "99999", "name": "Sconosciuto", "desc": "non mappato"},
            ]})
        return httpx.Response(404, json={})
    return gestore


# ------------------------------------------------------------------ sicurezza
def test_l_attacco_attivo_non_e_invocabile(adapter_context):
    """`ascan` e' l'attacco attivo di ZAP. Un Baseline che attacca non e' piu'
    un Baseline, e il mandato firmato dal cliente non lo copre."""
    import adapters.phase2 as modulo

    originale = modulo.httpx.Client
    strumento = _adattatore(adapter_context, lambda r: httpx.Response(200, json={}))
    try:
        with httpx.Client() as client, pytest.raises(UnsafeCommandError):
            strumento._chiedi(client, "/JSON/ascan/action/scan/")
    finally:
        _ripristina(modulo, originale)

    assert not any("ascan" in azione for azione in strumento.AZIONI_AMMESSE)


def test_la_chiave_viaggia_nell_intestazione_non_nell_indirizzo(adapter_context):
    """Gli indirizzi finiscono nei log di ogni proxy che attraversano."""
    import adapters.phase2 as modulo

    originale = modulo.httpx.Client
    richieste: list[httpx.Request] = []
    strumento = _adattatore(adapter_context, _zap_che_funziona(richieste))
    try:
        strumento.execute()
    finally:
        _ripristina(modulo, originale)

    assert richieste, "nessuna chiamata a ZAP"
    for richiesta in richieste:
        assert CHIAVE not in str(richiesta.url)
        assert richiesta.headers.get("X-ZAP-API-Key") == CHIAVE


# ------------------------------------------------------------------ esecuzione
def test_gli_alert_diventano_rilievi(adapter_context):
    import adapters.phase2 as modulo

    originale = modulo.httpx.Client
    strumento = _adattatore(adapter_context, _zap_che_funziona([]))
    try:
        esito = strumento.execute()
    finally:
        _ripristina(modulo, originale)

    assert esito.status is AdapterStatus.SUCCESS
    tipi = {e.finding_type for e in esito.evidences}
    assert tipi == {"hsts_missing", "csp_missing"}, (
        "un alert non mappato non deve produrre un rilievo senza tipo")


def test_si_aspetta_la_fine_dell_analisi_passiva(adapter_context):
    """Chiedere gli alert prima che la coda sia vuota restituisce un elenco
    parziale, e il sito risulterebbe piu' pulito di quanto sia."""
    import adapters.phase2 as modulo

    originale = modulo.httpx.Client
    ordine: list[str] = []

    def gestore(richiesta: httpx.Request) -> httpx.Response:
        ordine.append(richiesta.url.path)
        base = _zap_che_funziona([])
        return base(richiesta)

    strumento = _adattatore(adapter_context, gestore)
    try:
        strumento.execute()
    finally:
        _ripristina(modulo, originale)

    assert ordine.index("/JSON/pscan/view/recordsToScan/") < ordine.index("/JSON/core/view/alerts/")


def test_un_guasto_non_passa_per_successo(adapter_context):
    import adapters.phase2 as modulo

    originale = modulo.httpx.Client

    def rotto(richiesta: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connessione rifiutata", request=richiesta)

    strumento = _adattatore(adapter_context, rotto)
    try:
        esito = strumento.execute()
    finally:
        _ripristina(modulo, originale)

    assert esito.status is AdapterStatus.FAILED
    assert esito.coverage_impact > 0
    assert "connessione rifiutata" in (esito.error_message or "")


def test_senza_configurazione_dice_cosa_manca(adapter_context):
    adapter_context.connector_config = {**adapter_context.connector_config, "zap": {}}
    disponibile, motivo = ZAPBaselineAdapter(adapter_context).check_available()

    assert disponibile is False
    assert "ZAP_URL" in motivo
