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


# -------------------------------------------- crt.sh: 404 non e' un guasto
def test_un_404_di_crtsh_significa_nessun_certificato(adapter_context):
    """E' l'esito normale per un dominio che non ha mai emesso certificati.

    Contarlo come errore toglieva confidenza a una risposta corretta: nel
    registro, `coverage_impact=0.45` per un dominio che semplicemente non ne
    ha. E' lo stesso sbaglio gia' corretto su ransomware.live.
    """
    def non_trovato(richiesta: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="")

    esito = _adattatore_ct(adapter_context, non_trovato)

    assert esito.status is AdapterStatus.SUCCESS
    assert esito.coverage_impact == 0.0
    assert esito.error_message is None


def test_un_502_di_crtsh_resta_un_guasto(adapter_context):
    """Il servizio che non risponde e' un'altra cosa dal dominio senza
    certificati, e va continuato a dire."""
    def rotto(richiesta: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="bad gateway")

    esito = _adattatore_ct(adapter_context, rotto)

    assert esito.status is AdapterStatus.FAILED
    assert esito.coverage_impact > 0


# ------------------------------------------ testssl: un'uscita non nulla
def test_un_host_irraggiungibile_non_passa_per_verificato(adapter_context, monkeypatch):
    """Nel registro: cinque host su otto usciti con codice 246, e lo
    strumento dichiarava `success` con copertura piena.

    Senza file JSON, `json.loads(b"[]")` non solleva: il guasto non veniva
    contato da nessuna parte.
    """
    from adapters import testssl_adapter
    from adapters.runner import CommandResult

    monkeypatch.setattr(testssl_adapter, "_risolve", lambda host: True)
    monkeypatch.setattr(testssl_adapter, "read_output_file", lambda *a, **k: b"")
    monkeypatch.setattr(
        testssl_adapter, "run_command",
        lambda *a, **k: CommandResult(
            exit_code=246, stdout=b"",
            stderr=b"Fatal error: repeated TCP connect problems (connect timeout), giving up",
            timed_out=False, duration_seconds=100.0))

    strumento = testssl_adapter.TestSSLAdapter(adapter_context)
    monkeypatch.setattr(strumento.context.scope_guard, "filter_targets",
                        lambda valori, tipo: ["irraggiungibile.example"])
    esito = strumento.execute()

    assert esito.status is not AdapterStatus.SUCCESS
    assert esito.coverage_impact > 0, "un host non verificato deve pesare sulla confidenza"
    assert "connect" in (esito.error_message or "").lower()


def test_si_prova_un_solo_indirizzo_per_host(adapter_context, monkeypatch):
    """Un host dietro a un bilanciatore risolve in piu' indirizzi e testssl
    li prova tutti: nel registro, cinque indirizzi per oltre due minuti su un
    host solo. La configurazione TLS e' la stessa su ogni nodo."""
    from adapters import testssl_adapter
    from adapters.runner import CommandResult

    argomenti: list[list[str]] = []

    def finto(binary, args, **kwargs):  # noqa: ANN001, ANN202
        argomenti.append(list(args))
        return CommandResult(exit_code=0, stdout=b"", stderr=b"", timed_out=False,
                             duration_seconds=1.0)

    monkeypatch.setattr(testssl_adapter, "_risolve", lambda host: True)
    monkeypatch.setattr(testssl_adapter, "read_output_file", lambda *a, **k: b"[]")
    monkeypatch.setattr(testssl_adapter, "run_command", finto)

    strumento = testssl_adapter.TestSSLAdapter(adapter_context)
    monkeypatch.setattr(strumento.context.scope_guard, "filter_targets",
                        lambda valori, tipo: ["bilanciato.example"])
    strumento.execute()

    assert argomenti, "testssl non e' stato eseguito"
    for args in argomenti:
        assert "--ip" in args and args[args.index("--ip") + 1] == "one"
