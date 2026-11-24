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
        lambda db: {"THEHARVESTER_URL": "http://theharvester:8000",
                    "THEHARVESTER_API_KEY": "chiave"})
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
                        lambda db: {"THEHARVESTER_URL": "http://theharvester:8000",
                    "THEHARVESTER_API_KEY": "chiave"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (True, "risponde"))

    assert _per_chiave(verifica_strumenti(None))["theharvester"].esito == OPERATIVO


def test_senza_rete_non_si_apre_nessuna_connessione(monkeypatch):
    """La verifica va anche dove la rete non c'e' (un controllo in CI, una
    configurazione letta da fuori): in quel caso non deve mentire dicendo
    «non raggiungibile», deve soltanto non guardare."""
    chiamate = []
    monkeypatch.setattr("app.services.tool_config.valori_effettivi",
                        lambda db: {"THEHARVESTER_URL": "http://theharvester:8000",
                    "THEHARVESTER_API_KEY": "chiave"})
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
        "THEHARVESTER_URL": "http://theharvester:8000",
        "THEHARVESTER_API_KEY": "chiave",
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


def test_uno_strumento_non_configurato_ma_sostituito_non_e_da_sistemare(monkeypatch):
    """Uno strumento che non si puo' installare, e la cui area e' coperta da un
    altro, non va fra le cose da configurare: si manderebbe a cercare un
    servizio che non esiste.

    Il test usa una voce sintetica e non SpiderFoot di proposito. Quando
    SpiderFoot era dichiarato `replaced_by` perche' non c'era un'immagine, un
    test scritto su di lui sembrava verificare il meccanismo e verificava una
    decisione di prodotto: appena l'immagine e' tornata (0.18.8, costruita dal
    sorgente) e' fallito, pur essendo il meccanismo intatto.
    """
    from app.services.verifica_strumenti import verifica_strumenti as vs

    catalogo = {
        "sostituto": {"label": "Sostituto", "coverage_weight": 1.0,
                      "coverage_areas": ["attack_surface"]},
        "finto": {"label": "Finto", "kind": "http_api", "coverage_weight": 1.0,
                  "coverage_areas": ["attack_surface"], "replaced_by": "sostituto"},
    }
    monkeypatch.setattr("app.services.verifica_strumenti.load_yaml_config",
                        lambda _nome: {"tools": catalogo})
    # `finto` non ha variabili fra quelle configurabili: si simula che gliene
    # manchi una, che e' la condizione in cui la sostituzione vale.
    monkeypatch.setattr(
        "app.services.tool_status.stato_strumenti",
        lambda _db: [{"key": "finto", "kind": "configurazione",
                      "requirements": [{"variable": "FINTO_URL", "present": False,
                                        "free": True}], "reason": ""},
                     {"key": "sostituto", "kind": "configurazione",
                      "requirements": [], "reason": ""}])

    esito = _per_chiave(vs(None, sonda_rete=False))["finto"]

    assert esito.esito == SOSTITUITO
    assert not esito.richiede_intervento
    assert "sostituto" in esito.dettaglio


def test_spiderfoot_e_tornato_uno_strumento_dello_stack():
    """Era `replaced_by: theharvester` perche' non si poteva installare.
    L'immagine ora la costruisce lo stack dal sorgente, quindi un suo guasto e'
    un guasto e deve costare copertura."""
    esito = _per_chiave(verifica_strumenti(None, sonda_rete=False))["spiderfoot"]

    assert esito.esito != SOSTITUITO, (
        "dichiararlo sostituito gli azzererebbe il costo di copertura, e un "
        "suo guasto passerebbe per un'assenza prevista")
    assert esito.peso == 1.0


# --------------------------------------------------------------------------
# Voci che non sono esecuzioni
# --------------------------------------------------------------------------
def test_una_voce_che_e_un_alias_non_chiede_niente():
    """`nmap` non e' uno strumento che gira: in scansione quella chiave esegue
    naabu, e non esiste alcun adapter Nmap. Compariva fra i binari assenti con
    il rimedio «make aggiorna», che non lo farebbe comparire (per licenza non
    viene distribuito) e che non servirebbe comunque (quella chiave esegue un
    altro binario).
    """
    from adapters.registry import ADAPTER_CLASSES, TOOL_ALIASES
    from app.services.verifica_strumenti import ALIAS

    esiti = _per_chiave(verifica_strumenti(None, sonda_rete=False))

    for chiave, esegue in TOOL_ALIASES.items():
        if chiave == esegue:
            continue
        assert chiave not in ADAPTER_CLASSES, (
            f"{chiave} ha un adapter proprio: non e' un alias")
        assert esiti[chiave].esito == ALIAS, chiave
        assert not esiti[chiave].richiede_intervento, chiave
        assert esegue in esiti[chiave].dettaglio, (
            f"la voce {chiave} non dice che cosa esegue davvero")


def test_l_alias_riporta_anche_il_motivo_per_cui_non_e_distribuito():
    """Per Nmap il motivo e' una licenza, e chi legge deve poterlo sapere senza
    aprire il catalogo: altrimenti «alias» sembra una stranezza invece di una
    decisione."""
    from app.services.verifica_strumenti import ALIAS

    esito = _per_chiave(verifica_strumenti(None, sonda_rete=False))["nmap"]

    assert esito.esito == ALIAS
    assert "licenza" in esito.dettaglio.lower() or "license" in esito.dettaglio.lower()
    assert "port_scan" in esito.dettaglio


def test_cio_che_non_viene_distribuito_non_propone_una_ricostruzione(monkeypatch):
    """Un binario che l'immagine non contiene per scelta non si ottiene
    ricostruendola: proporre `make aggiorna` manda a perdere dieci minuti per
    ritrovarsi al punto di prima."""
    from app.services.verifica_strumenti import NON_DISTRIBUITO, verifica_strumenti as vs

    catalogo = {"finto": {"label": "Finto", "binary": "finto-che-non-esiste",
                          "coverage_weight": 1.0, "coverage_areas": ["attack_surface"],
                          "not_distributed": "Non distribuito: licenza X."}}
    monkeypatch.setattr("app.services.verifica_strumenti.load_yaml_config",
                        lambda _nome: {"tools": catalogo})

    esito = _per_chiave(vs(None, sonda_rete=False))["finto"]

    assert esito.esito == NON_DISTRIBUITO
    assert esito.rimedio is None, "nessun rimedio: non c'e' nulla da fare"
    assert "licenza" in esito.dettaglio.lower()


def test_se_il_binario_c_e_lo_strumento_non_distribuito_e_utilizzabile(monkeypatch):
    """Chi ha una licenza propria lo installa nell'immagine: dichiararlo
    comunque assente ignorerebbe il lavoro fatto."""
    from app.services.verifica_strumenti import verifica_strumenti as vs

    catalogo = {"finto": {"label": "Finto", "binary": "finto",
                          "coverage_weight": 1.0, "coverage_areas": ["attack_surface"],
                          "not_distributed": "Non distribuito: licenza X."}}
    monkeypatch.setattr("app.services.verifica_strumenti.load_yaml_config",
                        lambda _nome: {"tools": catalogo})
    monkeypatch.setattr("app.services.verifica_strumenti.shutil.which",
                        lambda nome: f"/usr/bin/{nome}")

    assert _per_chiave(vs(None, sonda_rete=False))["finto"].esito == OPERATIVO


# --------------------------------------------------------------------------
# L'indirizzo che sembra giusto e non lo e'
# --------------------------------------------------------------------------
def test_un_indirizzo_di_loopback_dentro_un_contenitore_viene_spiegato(monkeypatch):
    """E' l'errore piu' facile da commettere e il piu' difficile da vedere: un
    servizio avviato sul portatile e indicato come http://127.0.0.1:5001 e'
    irraggiungibile dal worker, perche' li' quell'indirizzo e' il worker. Il
    sistema operativo risponde «connection refused», lo stesso messaggio che si
    otterrebbe se il servizio non fosse mai partito."""
    monkeypatch.setattr("app.services.tool_config.valori_effettivi",
                        lambda db: {"THEHARVESTER_URL": "http://127.0.0.1:8000/",
                    "THEHARVESTER_API_KEY": "chiave"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (False, "connessione rifiutata"))
    monkeypatch.setattr("app.services.verifica_strumenti._dentro_un_contenitore",
                        lambda: True)

    esito = _per_chiave(verifica_strumenti(None))["theharvester"]

    assert esito.esito == NON_RAGGIUNGIBILE
    assert "host.docker.internal" in (esito.rimedio or ""), (
        "il rimedio non dice come raggiungere la macchina che ospita")


def test_fuori_da_un_contenitore_il_loopback_non_viene_corretto(monkeypatch):
    """In sviluppo locale worker e servizio stanno sulla stessa macchina, e
    127.0.0.1 e' giusto: dirlo sbagliato manderebbe a cercare un problema che
    non c'e'."""
    monkeypatch.setattr("app.services.tool_config.valori_effettivi",
                        lambda db: {"THEHARVESTER_URL": "http://127.0.0.1:8000/",
                    "THEHARVESTER_API_KEY": "chiave"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (False, "connessione rifiutata"))
    monkeypatch.setattr("app.services.verifica_strumenti._dentro_un_contenitore",
                        lambda: False)

    esito = _per_chiave(verifica_strumenti(None))["theharvester"]

    assert "host.docker.internal" not in (esito.rimedio or "")


@pytest.mark.parametrize("indirizzo,atteso", [
    ("http://127.0.0.1:5001", True),
    ("http://localhost:5001", True),
    ("http://[::1]:5001", True),
    ("http://127.1.2.3:5001", True),
    ("http://host.docker.internal:5001", False),
    ("http://theharvester:5000", False),
    ("http://192.168.1.10:5001", False),
])
def test_il_riconoscimento_del_loopback(indirizzo, atteso):
    from app.services.verifica_strumenti import _e_loopback

    assert _e_loopback(indirizzo) is atteso


# --------------------------------------------------------------------------
# Da dove arriva il valore decide dove si corregge
# --------------------------------------------------------------------------
def test_un_valore_salvato_dall_interfaccia_lo_dichiara(monkeypatch):
    """E' la trappola piu' costosa della configurazione, perche' non lascia
    tracce: il database ha la precedenza su `.env`, quindi un indirizzo
    salvato una volta da Personalizzazione -> Strumenti rende inefficace ogni
    modifica al file, per sempre. Chi corregge `.env` e rilancia vede lo stesso
    errore e corregge di nuovo lo stesso file.
    """
    monkeypatch.setattr("app.services.tool_config.valori_effettivi",
                        lambda db: {"SPIDERFOOT_URL": "http://127.0.0.1:5001/"})
    monkeypatch.setattr("app.services.tool_config.origine",
                        lambda db: {"SPIDERFOOT_URL": "interfaccia"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (False, "connessione rifiutata"))

    esito = _per_chiave(verifica_strumenti(None))["spiderfoot"]

    assert "interfaccia" in esito.dettaglio, (
        "non dice da dove arriva il valore: si continuerebbe a correggere .env")
    assert "PRECEDENZA" in (esito.rimedio or ""), (
        "non dice che .env e' ignorato")
    assert "--dimentica" in (esito.rimedio or ""), (
        "non indica la via d'uscita")


def test_un_valore_che_arriva_dall_ambiente_non_manda_all_interfaccia(monkeypatch):
    """Il contrario sarebbe altrettanto fuorviante: mandare a cercare in una
    schermata un valore che sta nel file."""
    monkeypatch.setattr("app.services.tool_config.valori_effettivi",
                        lambda db: {"SPIDERFOOT_URL": "http://spiderfoot:5001"})
    monkeypatch.setattr("app.services.tool_config.origine",
                        lambda db: {"SPIDERFOOT_URL": "ambiente"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (False, "connessione rifiutata"))

    esito = _per_chiave(verifica_strumenti(None))["spiderfoot"]

    assert "ambiente" in esito.dettaglio
    assert "PRECEDENZA" not in (esito.rimedio or "")
    assert "osint" in (esito.rimedio or ""), (
        "con il valore giusto nel file, il rimedio e' avviare il servizio")


# --------------------------------------------------------------------------
# Le chiavi che non si impostano dall'interfaccia
# --------------------------------------------------------------------------
def test_la_chiave_di_un_contenitore_nostro_non_manda_all_interfaccia(monkeypatch):
    """ZAP e theHarvester vogliono una chiave che li protegge, e la leggono
    dal PROPRIO ambiente all'avvio. L'interfaccia scrive nel database, che
    quei contenitori non vedono: chi segue il rimedio «Personalizzazione ->
    Strumenti» imposta la chiave da un lato solo, l'API risponde 401, e lo
    strumento sembra guasto per una ragione che non ha niente a che vedere
    con il bersaglio."""
    monkeypatch.setattr(
        "app.services.tool_config.valori_effettivi",
        lambda db: {"THEHARVESTER_URL": "http://theharvester:8000"})
    monkeypatch.setattr("app.services.verifica_strumenti.servizio_risponde",
                        lambda indirizzo, timeout=2.0: (True, ""))

    esito = _per_chiave(verifica_strumenti(None))["theharvester"]

    assert esito.esito == DA_CONFIGURARE
    assert "THEHARVESTER_API_KEY" in (esito.rimedio or "")
    assert ".env" in (esito.rimedio or "")
    assert "Personalizzazione" not in (esito.rimedio or ""), (
        "manda a impostare la chiave dove il contenitore non la legge")


def test_il_rimedio_distingue_i_tre_casi():
    """Tre origini diverse, tre rimedi diversi: il fornitore per cio' che si
    paga, l'interfaccia per cio' che usa solo il worker, `.env` per cio' che
    legge un contenitore. Provato sulla funzione e non sul catalogo: un test
    agganciato a quale strumento oggi ha una chiave gratuita si rompe quando
    quella decisione cambia, ed e' gia' successo qui."""
    from app.services.verifica_strumenti import _rimedio_variabile

    a_pagamento = _rimedio_variabile(
        [{"variable": "X_API_KEY", "free": False, "where": "https://esempio.test/chiavi"}],
        True, {})
    assert a_pagamento == "https://esempio.test/chiavi"

    del_worker = _rimedio_variabile(
        [{"variable": "X_API_KEY", "free": True, "shared_with_container": False}],
        False, {})
    assert "Personalizzazione" in del_worker

    del_contenitore = _rimedio_variabile(
        [{"variable": "X_API_KEY", "free": True, "shared_with_container": True}],
        False, {"compose_service": "x", "compose_profile": "extra"})
    assert ".env" in del_contenitore
    assert "Personalizzazione" not in del_contenitore
    assert "--profile extra up -d x" in del_contenitore, (
        "il rimedio non dice come riavviare il servizio che deve leggerla")


def test_ogni_chiave_dichiarata_condivisa_e_davvero_nell_ambiente_del_servizio():
    """La dichiarazione nel codice e il compose devono dire la stessa cosa.
    Se una variabile e' marcata «la legge il contenitore» e il compose non la
    passa a quel contenitore, il rimedio suggerito e' falso: si mette la
    chiave in `.env`, si riavvia, e il servizio continua a non averla."""
    from app.services.tool_config import VARIABILI

    compose = yaml.safe_load((RADICE / "docker-compose.yml").read_text(encoding="utf-8"))
    catalogo = yaml.safe_load(
        (RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))["tools"]

    condivise = [v for v in VARIABILI if v.condivisa_col_contenitore]
    assert condivise, "nessuna variabile marcata: il controllo non proverebbe nulla"

    for variabile in condivise:
        servizio = catalogo.get(variabile.strumento, {}).get("compose_service")
        assert servizio, (
            f"{variabile.nome} dice di essere letta da un contenitore, ma "
            f"{variabile.strumento} non ne dichiara uno nel catalogo")
        # Puo' arrivare nell'`environment` (theHarvester, che la legge dal
        # proprio ambiente) o interpolata nel `command` (ZAP, che la vuole
        # come `-config api.key=`). In entrambi i casi la fornisce `.env` al
        # momento in cui il contenitore viene creato, che e' cio' che il
        # rimedio promette; cio' che non deve essere e' assente.
        definizione = compose["services"][servizio]
        passata = yaml.safe_dump({k: definizione.get(k)
                                  for k in ("environment", "command", "env_file")})
        assert variabile.nome in passata, (
            f"{variabile.nome} non arriva al servizio `{servizio}`: il rimedio "
            "manderebbe a metterla in .env senza che il servizio la veda")
