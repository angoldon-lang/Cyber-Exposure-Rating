"""Verifica sul campo di cosa sia davvero utilizzabile, strumento per strumento.

`tool_status` risponde alla domanda «la configurazione e' completa?», e lo fa
senza toccare nulla: e' interrogato da una richiesta HTTP e non puo' mettersi
ad aprire connessioni. Restano fuori le due cose che in pratica fanno
risultare «non eseguito» uno strumento configurato a dovere:

  * il binario non c'e'. Vive nell'immagine del worker, e chi guarda da
    fuori — o dal contenitore dell'API, che per scelta non contiene strumenti
    di scansione — non lo vede;
  * il servizio non risponde. Un indirizzo configurato non significa che
    dall'altra parte ci sia qualcuno: i servizi facoltativi del compose
    esistono solo se il loro profilo e' attivo, e senza profilo non viene
    emesso nessun avviso. L'unico segnale arriva a scansione in corso, come
    «connection refused» in una riga di log.

Questo modulo apre connessioni, quindi non sta dietro a un endpoint: lo si
esegue, nel worker, quando si vuole sapere cosa aspettarsi dalla prossima
scansione.

Cosa viene contattato, e cosa no: solo i servizi che ospita chi installa, il
cui indirizzo lo scrive un amministratore nella configurazione (SpiderFoot,
theHarvester, ZAP). Le fonti di terze parti non si sondano: un `connect` a
un endpoint commerciale non dice se l'abbonamento sia valido, e non e' nostro
da interrogare. Nessun bersaglio di scansione entra qui: gli indirizzi
arrivano dalla configurazione, mai dai dati di un'azienda.
"""
from __future__ import annotations

import importlib.util
import shutil
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from app.core.config import load_yaml_config

# Oltre questo non si aspetta: un servizio sulla rete interna risponde in
# millisecondi, e un comando di diagnosi che si blocca non viene usato.
TIMEOUT_CONNESSIONE = 2.0

# Esiti, dal migliore al peggiore. L'ordine e' quello con cui si presentano:
# prima cosa c'e' da fare, poi cosa funziona.
OPERATIVO = "operativo"
SU_RICHIESTA = "su richiesta"
SOSTITUITO = "sostituito"
A_PAGAMENTO = "a pagamento"
DA_CONFIGURARE = "da configurare"
NON_RAGGIUNGIBILE = "non raggiungibile"
BINARIO_ASSENTE = "binario assente"

_GRAVITA = {
    NON_RAGGIUNGIBILE: 0, BINARIO_ASSENTE: 1, DA_CONFIGURARE: 2,
    A_PAGAMENTO: 3, SOSTITUITO: 4, SU_RICHIESTA: 5, OPERATIVO: 6,
}


@dataclass
class Verifica:
    chiave: str
    etichetta: str
    esito: str
    dettaglio: str
    rimedio: str | None
    peso: float
    aree: list[str]
    # Uno strumento dichiarato facoltativo nel catalogo non abbassa la quota
    # di strumenti riusciti: vale la pena saperlo leggendo l'elenco.
    facoltativo: bool

    @property
    def richiede_intervento(self) -> bool:
        return self.esito in {NON_RAGGIUNGIBILE, BINARIO_ASSENTE, DA_CONFIGURARE}

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.chiave, "label": self.etichetta, "outcome": self.esito,
            "detail": self.dettaglio, "remedy": self.rimedio,
            "coverage_weight": self.peso, "areas": self.aree,
            "optional": self.facoltativo,
        }


def servizio_risponde(indirizzo: str,
                      timeout: float = TIMEOUT_CONNESSIONE) -> tuple[bool, str]:
    """Vero se qualcuno accetta connessioni all'indirizzo configurato.

    Si apre una connessione TCP e si chiude subito: non si invia nulla e non
    si legge nulla. Basta a distinguere «il contenitore non e' mai stato
    avviato» da «il servizio risponde», che e' l'unica domanda qui.
    """
    parti = urlsplit(indirizzo)
    if not parti.hostname:
        return False, f"indirizzo non interpretabile: {indirizzo}"
    porta = parti.port or (443 if parti.scheme == "https" else 80)
    try:
        with socket.create_connection((parti.hostname, porta), timeout=timeout):
            return True, "risponde"
    except TimeoutError:
        return False, f"nessuna risposta da {parti.hostname}:{porta} entro {timeout:g}s"
    except OSError as errore:
        # `errno` qui e' la differenza fra «non avviato» (connection refused)
        # e «nome sconosciuto»: due rimedi diversi.
        return False, f"{parti.hostname}:{porta} non raggiungibile ({errore.strerror or errore})"


def _indirizzi_da_sondare(impostate: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Per ogni strumento, l'indirizzo del servizio da sondare.

    Solo le variabili gratuite e non segrete: sono i servizi che ospita chi
    installa. Le fonti commerciali restano fuori, per le ragioni in testa al
    modulo.
    """
    from app.services.tool_config import VARIABILI

    per_strumento: dict[str, tuple[str, str]] = {}
    for v in VARIABILI:
        if not v.nome.endswith("_URL") or v.segreto or not v.gratuito:
            continue
        valore = impostate.get(v.nome)
        if valore:
            per_strumento[v.strumento] = (v.nome, valore)
    return per_strumento


def verifica_strumenti(db: Any = None, *, sonda_rete: bool = True) -> list[Verifica]:
    """Esito per ogni strumento del catalogo, con il rimedio quando serve."""
    from app.services.tool_config import valori_effettivi
    from app.services.tool_status import stato_strumenti

    catalogo = load_yaml_config("tool_profiles").get("tools", {})
    configurazione = {riga["key"]: riga for riga in stato_strumenti(db)}
    impostate = valori_effettivi(db)
    da_sondare = _indirizzi_da_sondare(impostate) if sonda_rete else {}

    esiti: list[Verifica] = []
    for chiave, definizione in catalogo.items():
        stato = configurazione.get(chiave, {})
        peso = float(definizione.get("coverage_weight", 1.0))
        comune = dict(
            chiave=chiave, etichetta=str(definizione.get("label", chiave)),
            peso=peso, aree=list(definizione.get("coverage_areas", [])),
            facoltativo=bool(definizione.get("optional", False)))
        motivo = (stato.get("reason") or "").strip()

        # 1. Sostituito o in attesa di un dato: non c'e' nulla da sistemare,
        #    e `tool_status` lo sa gia' perche' lo distingue per rimedio.
        if stato.get("kind") == "immagine":
            esiti.append(Verifica(esito=SOSTITUITO, dettaglio=motivo,
                                  rimedio=None, **comune))
            continue
        if stato.get("kind") == "uso":
            esiti.append(Verifica(esito=SU_RICHIESTA, dettaglio=motivo,
                                  rimedio=None, **comune))
            continue

        # 2. Configurazione incompleta. A pagamento o gratuita cambia il
        #    rimedio: nell'un caso si compra, nell'altro si imposta.
        mancanti = [r for r in stato.get("requirements", []) if not r.get("present")]
        if mancanti:
            a_pagamento = any(not r.get("free") for r in mancanti)
            nomi = ", ".join(str(r.get("variable")) for r in mancanti)
            esiti.append(Verifica(
                esito=A_PAGAMENTO if a_pagamento else DA_CONFIGURARE,
                dettaglio=motivo or f"Manca {nomi}.",
                rimedio=(mancanti[0].get("where") if a_pagamento
                         else "Personalizzazione -> Strumenti, oppure .env"),
                **comune))
            continue

        # 3. Il binario, o la libreria, dichiarati dal catalogo devono
        #    esserci davvero. Sono la stessa classe di guasto: lo strumento
        #    e' configurato a dovere e non c'e'.
        binario = definizione.get("binary")
        if binario and not shutil.which(str(binario)):
            esiti.append(Verifica(
                esito=BINARIO_ASSENTE,
                dettaglio=f"`{binario}` non e' nel PATH di questo contenitore.",
                rimedio="make aggiorna (ricostruisce l'immagine del worker)",
                **comune))
            continue
        modulo = definizione.get("python_module")
        if modulo and importlib.util.find_spec(str(modulo)) is None:
            esiti.append(Verifica(
                esito=BINARIO_ASSENTE,
                dettaglio=f"la libreria `{modulo}` non e' installata.",
                rimedio="make aggiorna (ricostruisce l'immagine del worker)",
                **comune))
            continue

        # 4. Il servizio configurato deve rispondere.
        if chiave in da_sondare:
            variabile, indirizzo = da_sondare[chiave]
            risponde, come = servizio_risponde(indirizzo)
            if not risponde:
                esiti.append(Verifica(
                    esito=NON_RAGGIUNGIBILE,
                    dettaglio=f"{variabile}={indirizzo}: {come}.",
                    rimedio=_rimedio_servizio(definizione),
                    **comune))
                continue

        esiti.append(Verifica(esito=OPERATIVO, dettaglio="", rimedio=None, **comune))

    esiti.sort(key=lambda v: (_GRAVITA[v.esito], -v.peso, v.chiave))
    return esiti


def _rimedio_servizio(definizione: dict[str, Any]) -> str:
    """Il comando che avvia il servizio, quando e' uno di quelli del compose.

    Il nome del servizio e il suo profilo li dichiara il catalogo, non si
    deducono dal `docker-compose.yml`: quel file non viene copiato
    nell'immagine del worker, che e' proprio il contenitore dove questa
    verifica ha senso eseguirla. Un test controlla che le due dichiarazioni
    coincidano.
    """
    servizio = definizione.get("compose_service")
    profilo = definizione.get("compose_profile")
    if not servizio:
        return "avviare il servizio e verificare che risponda all'indirizzo configurato"
    if not profilo:
        return f"docker compose up -d {servizio}"
    return (f"docker compose --profile {profilo} up -d {servizio}"
            f"  (per non ripeterlo: COMPOSE_PROFILES={profilo} in .env)")
