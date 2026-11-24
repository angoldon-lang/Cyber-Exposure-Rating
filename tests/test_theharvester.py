"""theHarvester: scoperta di indirizzi e sottodomini da fonti pubbliche.

Lo strumento esiste qui per alimentare la verifica sulle violazioni, che
senza indirizzi da cercare gira e non trova nulla. Tre proprieta' vanno
tenute ferme: che all'API non si possa chiedere nulla di attivo, che un
guasto non si presenti come assenza di esposizione, e che il contenitore
riceva gli argomenti che il suo entry point accetta davvero.

L'API e' quella a lavori asincroni sotto `/api/v1`, misurata su un'istanza
avviata e non dedotta: `GET /sources` con il campo `ready` per fonte,
`POST /runs` -> 201 `{run_id, status}`, `GET /runs/{id}` -> `{status,
results, source_executions, error}`, con i risultati come
`{"type": ..., "value": ...}`.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml

from adapters.base import AdapterContext, AdapterStatus
from adapters.theharvester_adapter import PERCORSO_API, TheHarvesterAdapter

RADICE = Path(__file__).resolve().parents[1]
BASE = "http://theharvester:8000"
CHIAVE = "chiave-di-prova"
FONTI = ["crtsh", "certspotter"]


class _ScopeGuardFinto:
    def filter_targets(self, valori, _tipo):  # noqa: ANN001
        return list(valori)


def _contesto(**extra):
    base = dict(
        scan_id="s-1", tenant_id="t-1", company_id="c-1",
        company_name="Azienda di prova", profile="public_passive",
        domains=["azienda.example"], verified_domains=["azienda.example"],
        scope_guard=_ScopeGuardFinto(),
        connector_config={"theharvester": {"base_url": BASE, "api_key": CHIAVE}},
        tool_config={"theharvester": {"sources": list(FONTI), "max_targets": 5,
                                      "limit": 200, "timeout_seconds": 30}},
        mock_mode=False,
    )
    base.update(extra)
    return AdapterContext(**base)


# --------------------------------------------------------------------------
# Un servizio finto che parla come quello vero
# --------------------------------------------------------------------------
def _servizio(*, fonti=None, risultati=None, esecuzioni=None, stato="completed",
              errore=None, viste=None):
    """Trasporto che riproduce il giro completo: elenco, avvio, attesa."""
    pronte = fonti if fonti is not None else [
        {"name": "crtsh", "ready": True}, {"name": "certspotter", "ready": True},
        {"name": "hunter", "ready": False}, {"name": "intelx", "ready": False},
    ]

    def gestore(richiesta: httpx.Request) -> httpx.Response:
        if viste is not None:
            viste.append(richiesta)
        percorso = richiesta.url.path
        if percorso == f"{PERCORSO_API}/sources":
            return httpx.Response(200, json={"sources": pronte})
        if percorso == f"{PERCORSO_API}/runs" and richiesta.method == "POST":
            return httpx.Response(201, json={"run_id": "r-1", "status": "queued"})
        if percorso.startswith(f"{PERCORSO_API}/runs/"):
            corpo = {"status": stato, "results": risultati or [],
                     "result_count": len(risultati or []),
                     "source_executions": esecuzioni if esecuzioni is not None
                     else [{"source": f, "status": "completed"} for f in FONTI]}
            if errore:
                corpo["error"] = errore
            return httpx.Response(200, json=corpo)
        return httpx.Response(404, json={"detail": percorso})

    return gestore


RISULTATI = [
    {"type": "email", "value": "mario.rossi@azienda.example", "sources": ["crtsh"]},
    {"type": "email", "value": "info@azienda.example", "sources": ["crtsh"]},
    {"type": "email", "value": "estraneo@altrodominio.example", "sources": ["crtsh"]},
    {"type": "email", "value": "x@sub.azienda.example.altrui.com", "sources": ["crtsh"]},
    {"type": "email", "value": "non-un-indirizzo", "sources": ["crtsh"]},
    {"type": "hostname", "value": "portale.azienda.example:10.0.0.1"},
    {"type": "hostname", "value": "vpn.azienda.example"},
    {"type": "hostname", "value": "qualcosa.altrodominio.example"},
    {"type": "ip", "value": "203.0.113.10"},
    {"type": "person", "value": "Mario Rossi"},
]


def _esegui(monkeypatch, gestore, **extra):
    adapter = TheHarvesterAdapter(_contesto(**extra))
    transport = httpx.MockTransport(gestore)
    originale = httpx.Client

    class ClientFinto(originale):
        def __init__(self, *a, **k):
            k["transport"] = transport
            super().__init__(*a, **k)

    monkeypatch.setattr("adapters.theharvester_adapter.httpx.Client", ClientFinto)
    monkeypatch.setattr("adapters.theharvester_adapter.time.sleep", lambda _s: None)
    return adapter, adapter.execute()


# --------------------------------------------------------------------------
# Che cosa viene chiesto al servizio
# --------------------------------------------------------------------------
def test_al_lavoro_si_chiede_solo_cio_che_e_passivo(monkeypatch):
    """L'API sa fare forzatura DNS, verifica dei takeover e Shodan: sono
    attivita' attive, e da qui non devono essere raggiungibili nemmeno per
    errore di configurazione. Il corpo contiene solo i tre campi che servono."""
    viste: list[httpx.Request] = []
    _esegui(monkeypatch, _servizio(risultati=RISULTATI, viste=viste))

    avvii = [r for r in viste if r.method == "POST"]
    assert avvii, "nessun lavoro avviato"
    for richiesta in avvii:
        corpo = json.loads(richiesta.content)
        assert set(corpo) == {"target", "sources", "limit"}, (
            f"campi non previsti nella richiesta: {sorted(corpo)}")
        for vietato in ("dns_brute", "take_over", "api_scan", "shodan",
                        "dns_resolve", "virtual_host", "proxies"):
            assert vietato not in corpo


def test_la_chiave_viaggia_in_ogni_richiesta(monkeypatch):
    """Senza intestazione l'API risponde 401 e lo strumento sembrerebbe rotto
    per una ragione che non ha niente a che vedere con il bersaglio."""
    viste: list[httpx.Request] = []
    _esegui(monkeypatch, _servizio(risultati=RISULTATI, viste=viste))

    assert viste
    assert all(r.headers.get("x-api-key") == CHIAVE for r in viste)


def test_il_dominio_resta_un_dato_e_non_diventa_indirizzo(monkeypatch):
    """Il dominio arriva dal perimetro: finisce nel corpo JSON, non
    concatenato in un indirizzo dove `&` o `/` cambierebbero la richiesta."""
    viste: list[httpx.Request] = []
    ostile = "azienda.example&take_over=true"
    _esegui(monkeypatch, _servizio(risultati=[], viste=viste), domains=[ostile])

    avvii = [r for r in viste if r.method == "POST"]
    assert avvii
    assert json.loads(avvii[0].content)["target"] == ostile
    assert "take_over" not in str(avvii[0].url)


def test_una_fonte_non_pronta_non_viene_chiesta_ma_e_dichiarata(monkeypatch):
    """Il servizio dice quali fonti sono pronte. Chiederne una che non lo e'
    darebbe un risultato vuoto, che somiglia all'assenza di esposizione."""
    viste: list[httpx.Request] = []
    _, esito = _esegui(
        monkeypatch, _servizio(risultati=RISULTATI, viste=viste),
        tool_config={"theharvester": {"sources": ["crtsh", "hunter", "intelx"]}})

    corpo = json.loads([r for r in viste if r.method == "POST"][0].content)
    assert corpo["sources"] == ["crtsh"]
    assert esito.status == AdapterStatus.PARTIAL
    assert "hunter" in esito.error_message and "intelx" in esito.error_message


def test_senza_fonti_configurate_si_usano_quelle_pronte(monkeypatch):
    viste: list[httpx.Request] = []
    _esegui(monkeypatch, _servizio(risultati=[], viste=viste),
            tool_config={"theharvester": {}})

    corpo = json.loads([r for r in viste if r.method == "POST"][0].content)
    assert corpo["sources"] == ["certspotter", "crtsh"]


# --------------------------------------------------------------------------
# Che cosa esce
# --------------------------------------------------------------------------
def test_gli_indirizzi_del_dominio_diventano_asset_mascherati(monkeypatch):
    _, esito = _esegui(monkeypatch, _servizio(risultati=RISULTATI))

    email = [a for a in esito.assets if a.asset_type == "email_address"]
    chiavi = {a.asset_key for a in email}

    assert "mario.rossi@azienda.example" in chiavi
    assert "estraneo@altrodominio.example" not in chiavi, "indirizzo fuori perimetro"
    assert "x@sub.azienda.example.altrui.com" not in chiavi, (
        "il dominio in mezzo all'indirizzo non e' il nostro dominio")
    assert "non-un-indirizzo" not in chiavi
    assert all(a.display_name != a.asset_key for a in email), "indirizzo non mascherato"
    assert all(a.attributes.get("masked") for a in email)


def test_gli_host_del_dominio_diventano_sottodomini(monkeypatch):
    _, esito = _esegui(monkeypatch, _servizio(risultati=RISULTATI))

    sottodomini = {a.asset_key for a in esito.assets if a.asset_type == "subdomain"}

    assert sottodomini == {"portale.azienda.example", "vpn.azienda.example"}, (
        "l'host va ripulito dalla porta e quelli fuori dominio scartati")


def test_i_tipi_che_non_ci_servono_non_diventano_asset(monkeypatch):
    """L'API restituisce anche `ip`, `url`, `asn`, `person` e `breach`: un
    nome di persona preso da un motore di ricerca non e' un asset, e
    conservarlo sarebbe un dato personale senza ragione di esserci."""
    _, esito = _esegui(monkeypatch, _servizio(risultati=RISULTATI))

    tipi = {a.asset_type for a in esito.assets}
    assert tipi <= {"email_address", "subdomain"}
    assert "Mario Rossi" not in esito.raw_output.decode("utf-8")


def test_il_grezzo_non_conserva_indirizzi_in_chiaro(monkeypatch):
    _, esito = _esegui(monkeypatch, _servizio(risultati=RISULTATI))

    grezzo = json.loads(esito.raw_output.decode("utf-8"))

    assert "mario.rossi@azienda.example" not in json.dumps(grezzo)
    assert any("@" in e for e in grezzo["domini"]["azienda.example"]["emails"])


# --------------------------------------------------------------------------
# Quando qualcosa non va
# --------------------------------------------------------------------------
def test_senza_servizio_configurato_e_saltato_non_riuscito():
    esito = TheHarvesterAdapter(_contesto(connector_config={})).execute()

    assert esito.status == AdapterStatus.SKIPPED
    assert "THEHARVESTER_URL" in esito.error_message


def test_senza_chiave_la_verifica_lo_dice_invece_di_tacere():
    adapter = TheHarvesterAdapter(_contesto(
        connector_config={"theharvester": {"base_url": BASE}}))
    disponibile, motivo = adapter.check_available()

    assert disponibile is False
    assert "THEHARVESTER_API_KEY" in motivo


def test_un_lavoro_concluso_con_tutte_le_fonti_cadute_non_e_un_successo(monkeypatch):
    """E' la classe di guasto che questo progetto ha gia' pagato due volte, e
    qui l'API la nasconde meglio delle altre: lo stato del lavoro dice
    `completed` anche quando ogni singola fonte e' fallita, e i risultati sono
    una lista vuota. Senza guardare `source_executions`, il report concluderebbe
    che l'organizzazione non e' esposta."""
    _, esito = _esegui(monkeypatch, _servizio(
        risultati=[], esecuzioni=[{"source": "crtsh", "status": "failed",
                                   "stop_reason": "transport-error"},
                                  {"source": "certspotter", "status": "failed",
                                   "stop_reason": "transport-error"}]))

    assert esito.status == AdapterStatus.FAILED
    assert esito.assets == []
    assert "transport-error" in esito.error_message


def test_un_lavoro_fallito_non_e_un_successo_senza_risultati(monkeypatch):
    _, esito = _esegui(monkeypatch, _servizio(
        stato="failed", errore="bersaglio non valido", risultati=[]))

    assert esito.status == AdapterStatus.FAILED
    assert esito.assets == []
    assert esito.error_message


def test_un_servizio_che_non_risponde_e_un_guasto(monkeypatch):
    _, esito = _esegui(monkeypatch, lambda _r: httpx.Response(502, text="bad gateway"))

    assert esito.status == AdapterStatus.FAILED
    assert esito.assets == []
    assert esito.error_message


def test_un_lavoro_che_non_si_conclude_non_resta_appeso(monkeypatch):
    """Il lavoro e' asincrono: senza scadenza, un servizio che risponde
    sempre `running` terrebbe fermo il worker fino al timeout di Celery."""
    _, esito = _esegui(monkeypatch, _servizio(stato="running"),
                       tool_config={"theharvester": {"sources": list(FONTI),
                                                     "timeout_seconds": 0}})

    assert esito.status == AdapterStatus.FAILED
    assert "concluso" in esito.error_message or "TimeoutError" in esito.error_message


def test_se_nessuna_fonte_e_pronta_lo_strumento_e_saltato(monkeypatch):
    _, esito = _esegui(monkeypatch, _servizio(
        fonti=[{"name": "hunter", "ready": False}],
        risultati=[]), tool_config={"theharvester": {"sources": ["hunter"]}})

    assert esito.status == AdapterStatus.SKIPPED
    assert "hunter" in esito.error_message


# --------------------------------------------------------------------------
# Il contenitore
# --------------------------------------------------------------------------
def _compose():
    return yaml.safe_load((RADICE / "docker-compose.yml").read_text(encoding="utf-8"))


def test_al_contenitore_si_passano_solo_argomenti_del_suo_entry_point():
    """Regressione: il comando conteneva `restfulHarvest --rate-limit
    60/minute`, ma l'immagine ha ENTRYPOINT ["harvestview"] -- quindi
    diventava `harvestview restfulHarvest ...`, il contenitore ripartiva in
    loop con «unrecognized arguments», e `docker compose up` non diceva
    niente. `restfulHarvest` non esiste piu' fra gli entry point del
    progetto, e il limite di frequenza non e' piu' un'opzione."""
    comando = _compose()["services"]["theharvester"]["command"]

    assert "restfulHarvest" not in comando
    assert "--rate-limit" not in comando
    assert set(comando) <= {"-H", "0.0.0.0", "-p", "8000", "--host", "--port"}


def test_la_porta_dichiarata_e_quella_su_cui_ascolta():
    """Un disallineamento qui non da' errore: il servizio parte, e ogni
    richiesta dell'adapter finisce su una porta chiusa."""
    servizio = _compose()["services"]["theharvester"]
    comando = servizio["command"]
    porta = comando[comando.index("-p") + 1]

    assert servizio["expose"] == [porta]

    esempio = (RADICE / ".env.example").read_text(encoding="utf-8")
    assert f"THEHARVESTER_URL=http://theharvester:{porta}" in esempio


def test_l_immagine_e_fissata_per_digest():
    """Il progetto non pubblica tag di versione sul registro e `latest` si
    sposta: il digest e' l'unico ancoraggio immutabile."""
    servizio = _compose()["services"]["theharvester"]

    assert "@sha256:" in servizio["image"], f"non fissata: {servizio['image']}"
    assert servizio["profiles"] == ["osint"]


def test_la_chiave_arriva_al_contenitore_e_al_worker():
    """Due ambienti distinti, una sola chiave: se il contenitore ne ha una e
    il worker un'altra, l'API risponde 401 e lo strumento sembra guasto."""
    compose = _compose()
    assert "THEHARVESTER_API_KEY" in compose["services"]["theharvester"]["environment"]

    comune = (RADICE / "docker-compose.yml").read_text(encoding="utf-8")
    blocco = comune[comune.index("x-common-env"):comune.index("services:")]
    assert "THEHARVESTER_API_KEY" in blocco, (
        "la chiave non raggiunge api, worker e beat")


# --------------------------------------------------------------------------
# Il catalogo e la configurazione
# --------------------------------------------------------------------------
def test_lo_strumento_e_in_tutti_i_profili_perche_e_passivo():
    profili = yaml.safe_load((RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))

    assert profili["tools"]["theharvester"]["passive"] is True
    for nome, profilo in profili["profiles"].items():
        assert "theharvester" in profilo["tools"], f"manca nel profilo {nome}"


def test_la_configurazione_espone_indirizzo_e_chiave():
    from app.services.tool_config import PER_NOME

    indirizzo = PER_NOME.get("THEHARVESTER_URL")
    chiave = PER_NOME.get("THEHARVESTER_API_KEY")

    assert indirizzo is not None, "l'indirizzo non e' configurabile dall'interfaccia"
    assert indirizzo.segreto is False
    assert chiave is not None, "la chiave non e' configurabile dall'interfaccia"
    assert chiave.segreto is True, "la chiave non deve essere leggibile dall'interfaccia"
    assert chiave.strumento == indirizzo.strumento == "theharvester"


@pytest.mark.parametrize("campo", ["label", "notes", "coverage_areas", "sources"])
def test_la_voce_del_catalogo_e_completa(campo):
    profili = yaml.safe_load((RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))
    assert profili["tools"]["theharvester"].get(campo)
