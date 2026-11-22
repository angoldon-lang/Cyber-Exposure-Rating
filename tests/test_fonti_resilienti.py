"""Un guasto transitorio di una fonte pubblica non deve costare un'area.

Due casi reali, diversi fra loro.

crt.sh risponde 502 sotto carico: e' il server a cedere, e passa al secondo
colpo. Non ritentare significava perdere la superficie esposta di un dominio
per un guasto durato un secondo.

Il feed CISA KEV non si raggiungeva (`ConnectError`), e l'adapter rinunciava
all'intera area delle vulnerabilita' -- pur avendo una copia del catalogo sul
disco, scartata perche' oltre il TTL di 24 ore. Il catalogo CISA cambia di
qualche voce la settimana: una copia di ventisei ore e' quasi identica a
quella di adesso, e infinitamente piu' utile di nessun catalogo, che significa
non sapere quali CVE sono sfruttate in natura. Si usa e si DICHIARA: spacciare
per fresco un dato vecchio e' l'errore che non ci si concede.
"""
from __future__ import annotations

import time

import httpx
import pytest

from adapters.http_sicuro import get_con_ritentativi


# --------------------------------------------------------------------------
# Che cosa si ritenta, e che cosa no
# --------------------------------------------------------------------------
def _client(risposte: list):
    """Un client che restituisce le risposte indicate, una per chiamata."""
    sequenza = list(risposte)
    chiamate: list[httpx.Request] = []

    def gestore(richiesta: httpx.Request) -> httpx.Response:
        chiamate.append(richiesta)
        esito = sequenza.pop(0) if sequenza else httpx.Response(200, text="ok")
        if isinstance(esito, Exception):
            raise esito
        return esito

    client = httpx.Client(transport=httpx.MockTransport(gestore))
    return client, chiamate


@pytest.fixture(autouse=True)
def _senza_attese(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)


def test_un_502_viene_ritentato_e_recuperato():
    """E' il caso di crt.sh: il secondo tentativo riesce."""
    client, chiamate = _client([httpx.Response(502, text="Bad Gateway"),
                                httpx.Response(200, json=[{"name_value": "a.example"}])])

    risposta = get_con_ritentativi(client, "https://crt.sh/")

    assert risposta.status_code == 200
    assert len(chiamate) == 2


def test_un_errore_di_trasporto_viene_ritentato():
    client, chiamate = _client([httpx.ConnectError("connessione rifiutata"),
                                httpx.Response(200, text="ok")])

    assert get_con_ritentativi(client, "https://esempio.example").status_code == 200
    assert len(chiamate) == 2


def test_un_404_non_viene_ritentato():
    """Per crt.sh un 404 significa «nessun certificato per questo dominio»:
    e' una risposta, non un guasto, e ripeterla e' traffico sprecato."""
    client, chiamate = _client([httpx.Response(404, text="")])

    assert get_con_ritentativi(client, "https://crt.sh/").status_code == 404
    assert len(chiamate) == 1


def test_un_429_non_viene_ritentato():
    """La fonte chiede di rallentare: riprovare subito e' esattamente il
    contrario di cio' che ha chiesto."""
    client, chiamate = _client([httpx.Response(429, text="slow down")])

    assert get_con_ritentativi(client, "https://crt.sh/").status_code == 429
    assert len(chiamate) == 1


def test_i_tentativi_sono_pochi_e_finiti():
    """Insistere trasforma una fonte lenta in una scansione che non termina."""
    client, chiamate = _client([httpx.Response(502)] * 10)

    risposta = get_con_ritentativi(client, "https://crt.sh/")

    assert risposta.status_code == 502
    assert len(chiamate) == 2, "il numero di tentativi non e' limitato"


def test_un_guasto_persistente_di_trasporto_viene_propagato():
    client, _ = _client([httpx.ConnectError("giu'")] * 5)

    with pytest.raises(httpx.ConnectError):
        get_con_ritentativi(client, "https://esempio.example")


def test_i_bersagli_non_passano_da_qui():
    """La cortesia verso il bersaglio e' un requisito: ritentare raddoppia il
    traffico verso i sistemi di un'azienda. L'aiuto e' per le FONTI."""
    from adapters import http_sicuro

    assert "non per i bersagli" in (get_con_ritentativi.__doc__ or ""), (
        "il vincolo non e' scritto dove lo leggerebbe chi lo riusa")
    assert "crt.sh" in http_sicuro.get_con_ritentativi.__doc__


# --------------------------------------------------------------------------
# Il catalogo KEV vecchio vale piu' di nessun catalogo
# --------------------------------------------------------------------------
def _cache(tmp_path, eta_ore: float, contenuto: dict):
    from adapters.vulnintel.feeds import FeedCache

    cache = FeedCache(tmp_path, ttl_hours=24)
    cache.set("cisa_kev", contenuto)
    percorso = tmp_path / "cisa_kev.json"
    quando = time.time() - eta_ore * 3600
    import os
    os.utime(percorso, (quando, quando))
    return cache


_CATALOGO = {"vulnerabilities": [
    {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "X",
     "vulnerabilityName": "Difetto", "dateAdded": "2024-01-01",
     "knownRansomwareCampaignUse": "Known"}]}


def test_una_copia_fresca_non_viene_riscaricata(tmp_path, monkeypatch):
    from adapters.vulnintel import feeds

    cache = _cache(tmp_path, eta_ore=2, contenuto=_CATALOGO)
    monkeypatch.setattr(feeds, "get_con_ritentativi_semplice",
                        lambda *a, **k: pytest.fail("ha interrogato la rete"))

    voci = feeds.fetch_kev("https://cisa.example/kev.json", cache)

    assert "CVE-2024-0001" in voci


def test_se_il_feed_non_risponde_si_usa_la_copia_scaduta(tmp_path, monkeypatch):
    """Era `ConnectError` e l'intera area delle vulnerabilita' andava persa."""
    from adapters.vulnintel import feeds

    cache = _cache(tmp_path, eta_ore=26, contenuto=_CATALOGO)

    def giu(*_a, **_k):
        raise httpx.ConnectError("rete assente")

    monkeypatch.setattr(feeds, "get_con_ritentativi_semplice", giu)

    with pytest.raises(feeds.KEVScaduto) as atteso:
        feeds.fetch_kev("https://cisa.example/kev.json", cache)

    assert "CVE-2024-0001" in atteso.value.entries
    assert 25 <= atteso.value.eta_ore <= 27, atteso.value.eta_ore
    assert "ConnectError" in atteso.value.causa


def test_senza_nessuna_copia_il_guasto_resta_un_guasto(tmp_path, monkeypatch):
    """Non si inventa un catalogo vuoto: senza dati, l'area e' scoperta."""
    from adapters.vulnintel import feeds

    from adapters.vulnintel.feeds import FeedCache

    def giu(*_a, **_k):
        raise httpx.ConnectError("rete assente")

    monkeypatch.setattr(feeds, "get_con_ritentativi_semplice", giu)

    with pytest.raises(httpx.ConnectError):
        feeds.fetch_kev("https://cisa.example/kev.json", FeedCache(tmp_path))


def test_il_dato_vecchio_non_viene_presentato_come_fresco(tmp_path, monkeypatch):
    """L'adapter lo usa, ma l'esito e' PARTIAL e il motivo dice l'eta': cosi'
    l'indice di fiducia ne tiene conto invece di contarlo come dato fresco."""
    from adapters.base import AdapterContext, AdapterStatus
    from adapters.vulnintel import feeds
    from adapters.vulnintel_adapter import VulnerabilityIntelligenceAdapter

    cache_dir = tmp_path / "feeds"
    _cache(cache_dir, eta_ore=30, contenuto=_CATALOGO)

    def giu(*_a, **_k):
        raise httpx.ConnectError("rete assente")

    monkeypatch.setattr(feeds, "get_con_ritentativi_semplice", giu)

    class G:
        def filter_targets(self, valori, _t):  # noqa: ANN001
            return list(valori)

    contesto = AdapterContext(
        scan_id="s", tenant_id="t", company_id="c", company_name="A",
        profile="public_passive", domains=["azienda.example"],
        verified_domains=["azienda.example"], scope_guard=G(),
        connector_config={"cache_dir": str(cache_dir),
                          "kev": {"url": "https://cisa.example/kev.json"}},
        tool_config={}, mock_mode=False)

    esito = VulnerabilityIntelligenceAdapter(contesto).execute()

    assert esito.status is AdapterStatus.PARTIAL, (
        "un dato vecchio presentato come successo pieno e' un dato spacciato "
        "per fresco")
    assert "ore fa" in (esito.error_message or "")
    assert esito.coverage_impact > 0


def test_il_messaggio_di_guasto_dice_quale_indirizzo(tmp_path, monkeypatch):
    """«ConnectError» non distingue un feed irraggiungibile da un DNS che non
    risolve o da un proxy che nega l'uscita."""
    from adapters.base import AdapterContext, AdapterStatus
    from adapters.vulnintel import feeds
    from adapters.vulnintel_adapter import VulnerabilityIntelligenceAdapter

    def giu(*_a, **_k):
        raise httpx.ConnectError("Name or service not known")

    monkeypatch.setattr(feeds, "get_con_ritentativi_semplice", giu)

    class G:
        def filter_targets(self, valori, _t):  # noqa: ANN001
            return list(valori)

    contesto = AdapterContext(
        scan_id="s", tenant_id="t", company_id="c", company_name="A",
        profile="public_passive", domains=["azienda.example"],
        verified_domains=["azienda.example"], scope_guard=G(),
        connector_config={"cache_dir": str(tmp_path / "vuoto"),
                          "kev": {"url": "https://cisa.example/kev.json"}},
        tool_config={}, mock_mode=False)

    esito = VulnerabilityIntelligenceAdapter(contesto).execute()

    assert esito.status is AdapterStatus.FAILED
    assert "cisa.example" in (esito.error_message or "")
    assert "Name or service not known" in (esito.error_message or "")


# --------------------------------------------------------------------------
# La cache deve sopravvivere al riavvio
# --------------------------------------------------------------------------
def test_la_cache_dei_feed_non_sta_su_tmpfs():
    """Nel worker `/tmp` e' un tmpfs: la cache si svuotava a ogni riavvio, e il
    catalogo veniva riscaricato molto piu' spesso del suo TTL di 24 ore --
    moltiplicando le occasioni di incontrare un guasto di rete."""
    from pathlib import Path

    import yaml

    radice = Path(__file__).resolve().parents[1]
    tasks = (radice / "backend" / "app" / "workers" / "tasks.py").read_text(encoding="utf-8")

    assert '"/tmp/defenix-feeds"' not in tasks, "la cache torna sul tmpfs"
    assert "/var/lib/defenix/feeds" in tasks

    compose = yaml.safe_load((radice / "docker-compose.yml").read_text(encoding="utf-8"))
    montaggi = compose["services"]["worker"]["volumes"]
    assert any("/var/lib/defenix/feeds" in m for m in montaggi), montaggi
    assert "feed-cache" in compose["volumes"]
