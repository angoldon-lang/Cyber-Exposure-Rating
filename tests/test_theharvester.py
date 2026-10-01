"""theHarvester: scoperta di indirizzi e sottodomini da fonti pubbliche.

Lo strumento esiste qui per alimentare la verifica sulle violazioni, che
senza indirizzi da cercare gira e non trova nulla. Due proprieta' vanno tenute
ferme: che all'API non si possa chiedere nulla di attivo, e che un guasto non
si presenti come assenza di esposizione.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml

from adapters.base import AdapterContext, AdapterStatus
from adapters.theharvester_adapter import (
    FONTI_CON_CHIAVE,
    FONTI_GRATUITE,
    PARAMETRI_AMMESSI,
    TheHarvesterAdapter,
)

RADICE = Path(__file__).resolve().parents[1]
BASE = "http://theharvester:5000"

# Parametri dell'endpoint `/query` che non devono mai essere inviati: sono
# attivita' sul bersaglio, fuori da un profilo passivo.
PARAMETRI_VIETATI = ("dns_brute", "take_over", "api_scan", "shodan",
                     "dns_resolve", "dns_lookup", "wordlist", "proxies")


class _ScopeGuardFinto:
    def filter_targets(self, valori, _tipo):  # noqa: ANN001
        return list(valori)


def _contesto(**extra):
    base = dict(
        scan_id="s-1", tenant_id="t-1", company_id="c-1",
        company_name="Azienda di prova", profile="public_passive",
        domains=["azienda.example"], verified_domains=["azienda.example"],
        scope_guard=_ScopeGuardFinto(),
        connector_config={"theharvester": {"base_url": BASE}},
        tool_config={"theharvester": {"sources": list(FONTI_GRATUITE), "max_targets": 5,
                                      "limit": 200, "timeout_seconds": 30}},
        mock_mode=False,
    )
    base.update(extra)
    return AdapterContext(**base)


def _adapter(risposte, **extra):
    """Adapter con un trasporto finto. `risposte` e' chiamata con la richiesta."""
    contesto = _contesto(**extra)
    adapter = TheHarvesterAdapter(contesto)
    transport = httpx.MockTransport(risposte)
    originale = httpx.Client

    class ClientFinto(originale):
        def __init__(self, *a, **k):
            k["transport"] = transport
            super().__init__(*a, **k)

    return adapter, ClientFinto


def _esegui(adapter, ClientFinto, monkeypatch):  # noqa: N803
    monkeypatch.setattr("adapters.theharvester_adapter.httpx.Client", ClientFinto)
    return adapter.execute()


def _risposta_ok(richiesta: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={
        "emails": ["mario.rossi@azienda.example", "info@azienda.example",
                   "estraneo@altrodominio.example", "non-un-indirizzo"],
        "hosts": ["portale.azienda.example:10.0.0.1", "vpn.azienda.example",
                  "qualcosa.altrodominio.example"],
        "ips": ["203.0.113.10"], "asns": [], "interesting_urls": [],
    })


# --------------------------------------------------------------------------
# Che cosa viene chiesto al servizio
# --------------------------------------------------------------------------
def test_all_api_si_chiede_solo_cio_che_e_passivo(monkeypatch):
    """`/query` accetta anche forzatura DNS, verifica dei takeover e scansione
    delle API: sono attivita' attive, e da qui non devono essere raggiungibili
    nemmeno per errore di configurazione."""
    viste: list[httpx.URL] = []

    def gestore(richiesta):
        viste.append(richiesta.url)
        return _risposta_ok(richiesta)

    adapter, client = _adapter(gestore)
    _esegui(adapter, client, monkeypatch)

    assert viste, "nessuna richiesta inviata"
    for url in viste:
        chiavi = set(url.params.keys())
        assert chiavi <= set(PARAMETRI_AMMESSI), f"parametri non ammessi: {chiavi}"
        for vietato in PARAMETRI_VIETATI:
            assert vietato not in chiavi


def test_un_valore_ostile_non_diventa_un_parametro_in_piu(monkeypatch):
    """Il dominio arriva dal perimetro: se finisse concatenato nell'indirizzo,
    un valore con `&` potrebbe aggiungere `dns_brute=true`."""
    viste: list[httpx.URL] = []

    def gestore(richiesta):
        viste.append(richiesta.url)
        return _risposta_ok(richiesta)

    adapter, client = _adapter(gestore, domains=["azienda.example&take_over=true"])
    _esegui(adapter, client, monkeypatch)

    assert viste
    assert "take_over" not in set(viste[0].params.keys())


# --------------------------------------------------------------------------
# Che cosa esce
# --------------------------------------------------------------------------
def test_gli_indirizzi_del_dominio_diventano_asset_mascherati(monkeypatch):
    adapter, client = _adapter(_risposta_ok)
    esito = _esegui(adapter, client, monkeypatch)

    email = [a for a in esito.assets if a.asset_type == "email_address"]
    chiavi = {a.asset_key for a in email}

    assert "mario.rossi@azienda.example" in chiavi
    assert "estraneo@altrodominio.example" not in chiavi, "indirizzo fuori perimetro accettato"
    assert "non-un-indirizzo" not in chiavi
    assert all(a.display_name != a.asset_key for a in email), "indirizzo non mascherato"
    assert all(a.attributes.get("masked") for a in email)


def test_gli_host_del_dominio_diventano_sottodomini(monkeypatch):
    adapter, client = _adapter(_risposta_ok)
    esito = _esegui(adapter, client, monkeypatch)

    sottodomini = {a.asset_key for a in esito.assets if a.asset_type == "subdomain"}

    assert sottodomini == {"portale.azienda.example", "vpn.azienda.example"}, (
        "l'host va ripulito dalla porta e quelli fuori dominio scartati")


def test_il_grezzo_non_conserva_indirizzi_in_chiaro(monkeypatch):
    """Il campo viene conservato per la verifica: un indirizzo leggibile li'
    dentro sarebbe un dato personale senza ragione di esserci."""
    adapter, client = _adapter(_risposta_ok)
    esito = _esegui(adapter, client, monkeypatch)

    grezzo = json.loads(esito.raw_output.decode("utf-8"))
    testo = json.dumps(grezzo)

    assert "mario.rossi@azienda.example" not in testo
    assert any("@" in e for e in grezzo["domini"]["azienda.example"]["emails"])


# --------------------------------------------------------------------------
# Quando qualcosa non va
# --------------------------------------------------------------------------
def test_senza_servizio_configurato_e_saltato_non_riuscito():
    adapter = TheHarvesterAdapter(_contesto(connector_config={}))
    esito = adapter.execute()

    assert esito.status == AdapterStatus.SKIPPED
    assert "THEHARVESTER_URL" in esito.error_message


def test_un_guasto_su_tutti_i_domini_non_e_un_successo_senza_risultati(monkeypatch):
    """E' la classe di guasto che questo progetto ha gia' pagato due volte:
    lo strumento fallisce, l'esito dice «riuscito», e il report conclude che
    l'organizzazione non e' esposta."""
    def gestore(_richiesta):
        return httpx.Response(502, text="bad gateway")

    adapter, client = _adapter(gestore)
    esito = _esegui(adapter, client, monkeypatch)

    assert esito.status == AdapterStatus.FAILED
    assert esito.assets == []
    assert esito.error_message


def test_una_fonte_senza_chiave_viene_scartata_e_dichiarata(monkeypatch):
    """Chiedere una fonte a pagamento senza averne la chiave non deve
    produrre silenzio: l'esito e' parziale e dice quale manca."""
    adapter, client = _adapter(_risposta_ok)
    adapter.config["sources"] = ["crtsh", "hunter", "intelx"]
    adapter.config["sources_con_chiave"] = ["hunter"]
    esito = _esegui(adapter, client, monkeypatch)

    assert esito.status == AdapterStatus.PARTIAL
    assert "intelx" in esito.error_message
    assert esito.config_snapshot["sources"] == ["crtsh", "hunter"]


def test_se_nessuna_fonte_e_utilizzabile_lo_strumento_e_saltato():
    contesto = _contesto(tool_config={"theharvester": {"sources": ["hunter", "intelx"]}})
    adapter = TheHarvesterAdapter(contesto)
    esito = adapter.execute()

    assert esito.status == AdapterStatus.SKIPPED
    assert "chiave" in esito.error_message


# --------------------------------------------------------------------------
# La configurazione
# --------------------------------------------------------------------------
def test_le_fonti_predefinite_sono_tutte_gratuite():
    """Una fonte a pagamento fra le predefinite farebbe sembrare rotto lo
    strumento a chi ha appena installato."""
    assert not set(FONTI_GRATUITE) & set(FONTI_CON_CHIAVE)

    profili = yaml.safe_load((RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))
    configurate = profili["tools"]["theharvester"]["sources"]

    assert set(configurate) <= set(FONTI_GRATUITE), (
        "il catalogo propone fonti che richiedono una chiave")


def test_lo_strumento_e_in_tutti_i_profili_perche_e_passivo():
    profili = yaml.safe_load((RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))

    assert profili["tools"]["theharvester"]["passive"] is True
    for nome, profilo in profili["profiles"].items():
        assert "theharvester" in profilo["tools"], f"manca nel profilo {nome}"


def test_l_immagine_e_fissata_per_digest():
    """Il progetto non pubblica tag di versione sul registro e `latest` si
    sposta: il digest e' l'unico ancoraggio immutabile."""
    compose = yaml.safe_load((RADICE / "docker-compose.yml").read_text(encoding="utf-8"))
    immagine = compose["services"]["theharvester"]["image"]

    assert "@sha256:" in immagine, f"immagine non fissata per digest: {immagine}"
    assert compose["services"]["theharvester"]["profiles"] == ["osint"]


def test_il_limite_di_frequenza_e_alzato_all_avvio():
    """Il valore predefinito dell'API e' 5 richieste al minuto: con piu'
    domini in perimetro la scansione verrebbe respinta a meta'."""
    compose = yaml.safe_load((RADICE / "docker-compose.yml").read_text(encoding="utf-8"))
    comando = compose["services"]["theharvester"]["command"]

    assert "--rate-limit" in comando


def test_la_configurazione_espone_l_indirizzo_del_servizio():
    from app.services.tool_config import PER_NOME

    variabile = PER_NOME.get("THEHARVESTER_URL")

    assert variabile is not None, "l'indirizzo non e' configurabile dall'interfaccia"
    assert variabile.segreto is False
    assert variabile.strumento == "theharvester"


@pytest.mark.parametrize("campo", ["label", "notes", "coverage_areas"])
def test_la_voce_del_catalogo_e_completa(campo):
    profili = yaml.safe_load((RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))
    assert profili["tools"]["theharvester"].get(campo)
