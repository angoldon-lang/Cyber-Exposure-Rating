"""Verifica sul campo: un indirizzo configurato non e' un servizio che risponde.

La diagnosi che esisteva guardava la configurazione e si fermava li'. Restavano
fuori le due assenze che in pratica fanno risultare «non eseguito» uno
strumento impostato a dovere: il binario che non c'e' nell'immagine, e il
contenitore facoltativo che non e' mai stato avviato perche' il suo profilo
compose non e' attivo. Nessuna delle due produce un avviso: la prima si scopre
leggendo i log del worker, la seconda come «connection refused» a scansione in
corso.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.services.verifica_strumenti import (
    A_PAGAMENTO,
    BINARIO_ASSENTE,
    DA_CONFIGURARE,
    NON_RAGGIUNGIBILE,
    OPERATIVO,
    SOSTITUITO,
    _indirizzi_da_sondare,
    servizio_risponde,
    verifica_strumenti,
)

RADICE = Path(__file__).resolve().parents[1]


def _per_chiave(esiti):
    return {v.chiave: v for v in esiti}


# --------------------------------------------------------------------------
# Il servizio configurato ma non avviato
# --------------------------------------------------------------------------
def test_un_servizio_configurato_ma_spento_non_risulta_operativo(monkeypatch):
    """E' il caso di theHarvester: l'indirizzo c'e', il contenitore no, perche'
    `docker compose up` non crea i servizi sotto profilo. Dichiararlo operativo
    e' precisamente l'errore che fa arrivare il guasto a scansione iniziata."""
    monkeypatch.setattr(
        "app.services.tool_config.valori_effettivi",
        lambda db: {"THEHARVESTER_URL": "http://theharvester:5000"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (False, "connessione rifiutata"))

    esito = _per_chiave(verifica_strumenti(None))["theharvester"]

    assert esito.esito == NON_RAGGIUNGIBILE
    assert esito.richiede_intervento
    assert "osint" in (esito.rimedio or ""), (
        "il rimedio non dice quale profilo compose attivare")


def test_un_servizio_ospitato_in_proprio_viene_sondato_come_gli_altri(monkeypatch):
    """SpiderFoot non fa piu' parte dello stack, ma chi ne ospita uno e ne
    configura l'indirizzo deve sapere se risponde: una sostituzione dichiarata
    non e' una scusa per non guardare cio' che e' stato configurato."""
    monkeypatch.setattr("app.services.tool_config.valori_effettivi",
                        lambda db: {"SPIDERFOOT_URL": "http://mio-spiderfoot:5001"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (False, "connessione rifiutata"))

    esito = _per_chiave(verifica_strumenti(None))["spiderfoot"]

    assert esito.esito == NON_RAGGIUNGIBILE
    assert "mio-spiderfoot" in esito.dettaglio


def test_un_servizio_che_risponde_e_operativo(monkeypatch):
    monkeypatch.setattr("app.services.tool_config.valori_effettivi",
                        lambda db: {"THEHARVESTER_URL": "http://theharvester:5000"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (True, "risponde"))

    assert _per_chiave(verifica_strumenti(None))["theharvester"].esito == OPERATIVO


def test_senza_rete_non_si_apre_nessuna_connessione(monkeypatch):
    """La verifica va anche dove la rete non c'e' (un controllo in CI, una
    configurazione letta da fuori): in quel caso non deve mentire dicendo
    «non raggiungibile», deve soltanto non guardare."""
    chiamate = []
    monkeypatch.setattr("app.services.tool_config.valori_effettivi",
                        lambda db: {"THEHARVESTER_URL": "http://theharvester:5000"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda *a, **k: chiamate.append(a) or (False, "x"))

    esito = _per_chiave(verifica_strumenti(None, sonda_rete=False))["theharvester"]

    assert not chiamate
    assert esito.esito == OPERATIVO


# --------------------------------------------------------------------------
# Che cosa viene contattato, e che cosa no
# --------------------------------------------------------------------------
def test_le_fonti_commerciali_non_vengono_sondate():
    """Un `connect` all'endpoint di un fornitore non dice se l'abbonamento sia
    valido, e quell'indirizzo non e' nostro da interrogare."""
    sondati = _indirizzi_da_sondare({
        "THEHARVESTER_URL": "http://theharvester:5000",
        "CREDENTIAL_EXPOSURE_URL": "https://fornitore.example/api",
    })

    assert "theharvester" in sondati
    assert "credential_exposure" not in sondati


def test_si_sondano_solo_indirizzi_che_arrivano_dalla_configurazione():
    """Il perimetro di una scansione non deve poter entrare qui: un bersaglio
    che facesse da indirizzo trasformerebbe una diagnosi in una richiesta
    verso un sistema di terzi."""
    from app.services.tool_config import VARIABILI

    sondabili = {v.strumento for v in VARIABILI
                 if v.nome.endswith("_URL") and v.gratuito and not v.segreto}
    tutti = {v.nome: "http://x:1" for v in VARIABILI}

    assert set(_indirizzi_da_sondare(tutti)) == sondabili


def test_un_indirizzo_illeggibile_non_solleva():
    riuscito, motivo = servizio_risponde("non-un-indirizzo")

    assert riuscito is False
    assert motivo


# --------------------------------------------------------------------------
# Assenze che non sono guasti
# --------------------------------------------------------------------------
def test_uno_strumento_sostituito_non_richiede_interventi(monkeypatch):
    """naabu non ha binari arm64 e la stessa area la copre `port_scan`:
    presentarlo fra le cose da fare manda a cercare un problema che non
    esiste."""
    monkeypatch.setattr("app.services.tool_status.platform.machine",
                        lambda: "aarch64")

    esito = _per_chiave(verifica_strumenti(None, sonda_rete=False))["naabu"]

    assert esito.esito == SOSTITUITO
    assert not esito.richiede_intervento
    assert "port_scan" in esito.dettaglio


def test_cio_che_costa_e_distinto_da_cio_che_va_configurato():
    """Chi legge l'elenco deve poter separare le due cose: una si risolve con
    una riga di configurazione, l'altra con un contratto."""
    esiti = _per_chiave(verifica_strumenti(None, sonda_rete=False))

    assert esiti["hibp"].esito == A_PAGAMENTO
    assert esiti["credential_exposure"].esito == A_PAGAMENTO
    assert esiti["zap_baseline"].esito == DA_CONFIGURARE


def test_un_binario_assente_si_distingue_da_una_configurazione_mancante(monkeypatch):
    monkeypatch.setattr("app.services.verifica_strumenti.shutil.which", lambda _nome: None)

    esiti = _per_chiave(verifica_strumenti(None, sonda_rete=False))

    assert esiti["subfinder"].esito == BINARIO_ASSENTE
    assert "immagine" in (esiti["subfinder"].rimedio or "")


def test_un_binario_presente_rende_lo_strumento_operativo(monkeypatch):
    monkeypatch.setattr("app.services.verifica_strumenti.shutil.which",
                        lambda nome: f"/opt/defenix/bin/{nome}")
    monkeypatch.setattr("app.services.verifica_strumenti.importlib.util.find_spec",
                        lambda nome: object())

    esiti = _per_chiave(verifica_strumenti(None, sonda_rete=False))

    assert esiti["subfinder"].esito == OPERATIVO
    assert esiti["checkdmarc"].esito == OPERATIVO


# --------------------------------------------------------------------------
# Il catalogo e il compose devono dire la stessa cosa
# --------------------------------------------------------------------------
@pytest.mark.parametrize("campo", ["compose_service", "compose_profile"])
def test_il_catalogo_dichiara_servizio_e_profilo_del_compose(campo):
    """Il rimedio lo legge il catalogo e non il compose, perche' quel file non
    viene copiato nell'immagine del worker -- che e' il contenitore dove
    questa verifica si esegue. Le due dichiarazioni devono percio' coincidere,
    e questo e' il test che lo garantisce."""
    catalogo = yaml.safe_load(
        (RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))["tools"]
    compose = yaml.safe_load(
        (RADICE / "docker-compose.yml").read_text(encoding="utf-8"))["services"]

    verificati = 0
    for chiave, definizione in catalogo.items():
        servizio = definizione.get("compose_service")
        if not servizio or campo not in definizione:
            continue
        assert servizio in compose, (
            f"{chiave} dichiara il servizio '{servizio}', assente dal compose")
        if campo == "compose_profile":
            profili = compose[servizio].get("profiles") or []
            assert definizione["compose_profile"] in profili, (
                f"{chiave}: profilo '{definizione['compose_profile']}' diverso da {profili}")
        verificati += 1

    # Due: theHarvester e ZAP. SpiderFoot ne e' uscito quando lo stack ha
    # smesso di avviarlo. La soglia serve solo a impedire che il test passi
    # perche' non guarda niente.
    assert verificati >= 2, "il test non sta verificando nulla"


def test_ogni_strumento_con_un_servizio_ha_anche_la_variabile_per_indirizzarlo():
    """Un servizio senza variabile non si potrebbe configurare dall'interfaccia,
    e un `compose_service` dichiarato invano non aiuterebbe nessuno."""
    from app.services.tool_config import VARIABILI

    catalogo = yaml.safe_load(
        (RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))["tools"]
    con_variabile = {v.strumento for v in VARIABILI if v.nome.endswith("_URL")}

    senza = sorted(chiave for chiave, d in catalogo.items()
                   if d.get("compose_service") and chiave not in con_variabile)

    assert not senza, f"servizi senza variabile di indirizzo: {senza}"


def test_uno_strumento_non_configurato_ma_sostituito_non_e_da_sistemare():
    """SpiderFoot non e' piu' nello stack perche' il progetto non pubblica
    un'immagine utilizzabile, e le sue aree le copre theHarvester. Presentarlo
    fra le cose da configurare manderebbe a cercare un servizio che non si puo'
    installare."""
    esito = _per_chiave(verifica_strumenti(None, sonda_rete=False))["spiderfoot"]

    assert esito.esito == SOSTITUITO
    assert not esito.richiede_intervento
    assert "theharvester" in esito.dettaglio
