"""Raccolta degli indirizzi e-mail dalle pagine pubbliche dell'azienda.

Le fonti DNS danno solo caselle tecniche — i destinatari dei rapporti DMARC,
il responsabile della zona nel SOA — e quelle in una violazione non compaiono
praticamente mai: nessuno le usa per registrarsi da qualche parte. La verifica
girava, non trovava nulla, e sembrava dire che l'organizzazione non e' esposta.
"""
from __future__ import annotations

import pytest

from adapters.email_harvest_adapter import (
    EmailHarvestAdapter,
    collegamenti_interni,
    indirizzi_in_pagina,
)

pytestmark = pytest.mark.security

DOMINIO = "acme-test.example"


# ------------------------------------------------------------- estrazione
def test_estrae_gli_indirizzi_dalle_forme_piu_comuni():
    pagina = ('<a href="mailto:Mario.Rossi@ACME.it">scrivici</a> '
              'oppure info@acme.it, oppure amministrazione@acme.it.')
    assert indirizzi_in_pagina(pagina) == {
        "mario.rossi@acme.it", "info@acme.it", "amministrazione@acme.it"}


@pytest.mark.parametrize("rumore", [
    "logo@2x.png",                     # risorsa con densita' di pixel
    "tuonome@example.com",             # esempio nella documentazione del tema
    "abc@sentry.io",                   # chiave di un servizio
    "user@domain.com",                 # segnaposto
])
def test_scarta_cio_che_somiglia_a_un_indirizzo(rumore):
    """Ogni falso positivo diventa una richiesta sprecata verso la fonte
    sulle violazioni, che ha un limite severo di chiamate."""
    assert rumore not in indirizzi_in_pagina(f"contatto {rumore} fine")


def test_i_collegamenti_seguiti_sono_solo_interni_e_a_pagine():
    pagina = ('<a href="/contatti">c</a><a href="https://altro.example/x">e</a>'
              '<a href="/brochure.pdf">p</a><a href="mailto:a@b.it">m</a>'
              '<a href="https://acme.it/chi-siamo">s</a>')
    assert collegamenti_interni(pagina, "https://acme.it/") == [
        "https://acme.it/contatti", "https://acme.it/chi-siamo"]


# ---------------------------------------------------------------- adapter
def test_gli_indirizzi_di_terzi_non_vengono_raccolti(adapter_context):
    """Il consulente che cura il sito e il fornitore citato in una pagina
    sono dati personali estranei alla valutazione."""
    adattatore = EmailHarvestAdapter(adapter_context)
    assert adattatore._in_perimetro(f"info@{DOMINIO}")
    assert adattatore._in_perimetro(f"x@sub.{DOMINIO}")
    assert not adattatore._in_perimetro("webmaster@agenzia-esterna.example")


def test_gli_indirizzi_sono_mascherati(adapter_context):
    esito = EmailHarvestAdapter(adapter_context).run()
    assert esito.assets
    for asset in esito.assets:
        assert "*" in asset.display_name
        assert asset.attributes["masked"] is True


def test_non_e_ammesso_nel_profilo_passivo():
    """Sono richieste ai sistemi dell'organizzazione, non a fonti pubbliche di
    terzi: la stessa regola degli altri controlli web."""
    from adapters.registry import tools_for_profile

    assert "email_harvest" not in tools_for_profile("public_passive")
    assert "email_harvest" in tools_for_profile("verified_standard")
    assert "email_harvest" in tools_for_profile("verified_extended")


def test_la_raccolta_precede_la_verifica_sulle_violazioni():
    """Invertirli lascerebbe XposedOrNot senza indirizzi, che e' esattamente
    il guasto silenzioso da cui nasce questo strumento."""
    import inspect

    from app.workers import pipeline

    sorgente = inspect.getsource(pipeline.ScanPipeline.run)
    assert sorgente.index('"email_harvest"') < sorgente.index('"xposedornot"')


def test_una_pagina_non_html_non_viene_analizzata(adapter_context, monkeypatch):
    """Un PDF o un'immagine contengono sequenze che somigliano a indirizzi e
    costerebbero solo richieste sprecate."""
    import httpx

    adapter_context.mock_mode = False
    risposta = httpx.Response(
        200, headers={"content-type": "application/pdf"}, content=b"%PDF finto@acme-test.example",
        request=httpx.Request("GET", f"https://{DOMINIO}/"))
    monkeypatch.setattr("adapters.email_harvest_adapter.get_seguendo_redirect",
                        lambda *_a, **_k: risposta)

    esito = EmailHarvestAdapter(adapter_context).run()
    assert esito.assets == []


def test_raccoglie_e_deduplica_dalle_pagine(adapter_context, monkeypatch):
    import httpx

    adapter_context.mock_mode = False
    pagine = {
        f"https://{DOMINIO}/": f'<a href="/contatti">c</a> info@{DOMINIO}',
        f"https://{DOMINIO}/contatti": f'mario.rossi@{DOMINIO} e info@{DOMINIO}',
    }

    def finta(_client, url, **_k):  # noqa: ANN001, ANN202
        corpo = pagine.get(url)
        if corpo is None:
            raise httpx.ConnectError("non esiste")
        return httpx.Response(200, headers={"content-type": "text/html"}, text=corpo,
                              request=httpx.Request("GET", url))

    monkeypatch.setattr("adapters.email_harvest_adapter.get_seguendo_redirect", finta)
    esito = EmailHarvestAdapter(adapter_context).run()

    assert sorted(a.asset_key for a in esito.assets) == [
        f"info@{DOMINIO}", f"mario.rossi@{DOMINIO}"]


def test_l_output_grezzo_non_contiene_indirizzi_in_chiaro(adapter_context, monkeypatch):
    """L'output grezzo viene archiviato: gli indirizzi vanno mascherati anche
    li', altrimenti mascherarli nel modello dati non serve a nulla."""
    import httpx

    adapter_context.mock_mode = False
    monkeypatch.setattr(
        "adapters.email_harvest_adapter.get_seguendo_redirect",
        lambda _c, url, **_k: httpx.Response(
            200, headers={"content-type": "text/html"},
            text=f"mario.rossi@{DOMINIO}", request=httpx.Request("GET", url)))

    esito = EmailHarvestAdapter(adapter_context).run()
    assert b"mario.rossi@" not in (esito.raw_output or b"")
