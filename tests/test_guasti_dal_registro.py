"""Tre difetti emersi dal registro di una scansione reale.

  * SpiderFoot, appena configurato, risultava «non raggiungibile»: il
    controllo anti-SSRF sui bersagli rifiuta gli indirizzi privati, e il
    servizio gira accanto al worker;
  * `certificate_transparency` dichiarava «riuscito, zero risultati» anche
    quando crt.sh andava in timeout: un perimetro piu' piccolo del vero,
    senza che nulla lo segnalasse;
  * la raccolta degli indirizzi costruiva i candidati sull'apice mentre il
    sito porta tutto su «www»: tre richieste al posto di una, sul sito del
    cliente.
"""
from __future__ import annotations

import httpx
import pytest

from adapters.base import AdapterStatus
from adapters.http_sicuro import RedirectNonConsentito, get_da_servizio_configurato

pytestmark = pytest.mark.security


# ------------------------------------------------------- servizio configurato
def _client(gestore) -> httpx.Client:  # noqa: ANN001
    return httpx.Client(transport=httpx.MockTransport(gestore), follow_redirects=False)


def test_un_servizio_su_indirizzo_privato_e_raggiungibile():
    """E' il caso reale: SpiderFoot accanto al worker, su rete Docker.

    Il controllo sui bersagli lo rifiutava, e la schermata di configurazione
    appena aggiunta non serviva a niente.
    """
    base = "http://spiderfoot:5001"

    with _client(lambda r: httpx.Response(200, json={"ok": True})) as client:
        risposta = get_da_servizio_configurato(client, f"{base}/ping", base=base)

    assert risposta.status_code == 200


def test_un_redirect_dentro_il_servizio_viene_seguito():
    base = "http://spiderfoot:5001"
    passi: list[str] = []

    def gestore(richiesta: httpx.Request) -> httpx.Response:
        passi.append(str(richiesta.url))
        if richiesta.url.path == "/ping":
            return httpx.Response(302, headers={"location": f"{base}/api/ping"})
        return httpx.Response(200, json={"ok": True})

    with _client(gestore) as client:
        assert get_da_servizio_configurato(client, f"{base}/ping", base=base).status_code == 200
    assert len(passi) == 2


def test_il_servizio_non_puo_mandarci_altrove():
    """E' la protezione che qui conta davvero: un servizio compromesso non
    deve poterci usare per raggiungere qualcos'altro."""
    base = "http://spiderfoot:5001"

    def gestore(richiesta: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    with _client(gestore) as client, pytest.raises(RedirectNonConsentito):
        get_da_servizio_configurato(client, f"{base}/ping", base=base)


def test_un_indirizzo_fuori_dal_servizio_viene_rifiutato_subito():
    with _client(lambda r: httpx.Response(200)) as client, pytest.raises(RedirectNonConsentito):
        get_da_servizio_configurato(client, "http://altrove.example/ping",
                                    base="http://spiderfoot:5001")


# --------------------------------------------------- certificate transparency
def _adattatore_ct(adapter_context, gestore):  # noqa: ANN001, ANN202
    import adapters.ct_adapter as modulo

    originale = modulo.httpx.Client

    class ClientFinto(originale):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            kwargs["transport"] = httpx.MockTransport(gestore)
            super().__init__(*args, **kwargs)

    modulo.httpx.Client = ClientFinto
    try:
        return modulo.CertificateTransparencyAdapter(adapter_context).execute()
    finally:
        modulo.httpx.Client = originale


def test_un_timeout_di_crtsh_non_e_un_successo(adapter_context):
    """Nel registro: 29 secondi, nessun risultato, «riuscito». crt.sh era
    andato in timeout e il perimetro ne usciva piu' piccolo del vero."""
    def scaduto(richiesta: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("tempo scaduto", request=richiesta)

    esito = _adattatore_ct(adapter_context, scaduto)

    assert esito.status is AdapterStatus.FAILED
    assert esito.error_message and "tempo scaduto" in esito.error_message
    assert esito.coverage_impact > 0, "un'area non interrogata deve pesare sulla confidenza"


def test_una_risposta_valida_resta_un_successo(adapter_context):
    def va_bene(richiesta: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"name_value": "www.esempio.it"}])

    esito = _adattatore_ct(adapter_context, va_bene)

    assert esito.status is AdapterStatus.SUCCESS
    assert esito.error_message is None
    assert esito.coverage_impact == 0.0
