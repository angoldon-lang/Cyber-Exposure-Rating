"""Stato configurativo degli strumenti di scansione.

Molti strumenti restano saltati per una configurazione mancante, e il motivo
compare solo nel log del worker o in una riga della dashboard. Chi deve porvi
rimedio ha bisogno di sapere tre cose che finora non erano scritte da nessuna
parte: quale variabile impostare, se la fonte costi qualcosa, e dove
procurarsi l'eventuale chiave.

Qui non si conservano segreti. Le chiavi restano nelle variabili d'ambiente:
questa e' una diagnosi di cosa manca, non un magazzino di credenziali.
"""
from __future__ import annotations

import platform
from dataclasses import dataclass, field
from typing import Any

from app.core.config import load_yaml_config


@dataclass
class RequisitoStrumento:
    """Cosa serve a uno strumento per funzionare."""

    variabile: str | None = None
    valore_presente: bool = False
    gratuito: bool = True
    dove: str | None = None
    nota: str | None = None
    # Cosa scrivere nel campo, e se il valore va trattato come un segreto
    # (campo mascherato, mai restituito dall'API).
    etichetta: str | None = None
    segreto: bool = False


@dataclass
class StatoStrumento:
    chiave: str
    etichetta: str
    profili: list[str] = field(default_factory=list)
    aree: list[str] = field(default_factory=list)
    configurato: bool = True
    requisiti: list[RequisitoStrumento] = field(default_factory=list)
    motivo: str | None = None
    # Da dove arriva ciascun valore gia' impostato: «interfaccia» o
    # «ambiente». Senza, chi vede «impostata» non sa dove intervenire.
    origine: dict[str, str] = field(default_factory=dict)
    # Da cosa dipende il rimedio: `configurazione` (una variabile
    # d'ambiente), `immagine` (il worker non contiene il binario o il
    # runtime), `uso` (lo strumento e' pronto ma resta inattivo finche' non
    # gli si da' qualcosa durante la scansione). Distinguerli evita di
    # mandare qualcuno a cercare una variabile che non esiste.
    rimedio: str = "configurazione"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.chiave, "label": self.etichetta, "profiles": self.profili,
            "areas": self.aree, "configured": self.configurato, "reason": self.motivo,
            "kind": self.rimedio,
            "requirements": [
                {"variable": r.variabile, "present": r.valore_presente,
                 "free": r.gratuito, "where": r.dove, "note": r.nota,
                 "label": r.etichetta, "secret": r.segreto,
                 "source": self.origine.get(r.variabile or "")}
                for r in self.requisiti],
        }


def _requisiti(chiave: str, impostate: dict[str, str]) -> list[RequisitoStrumento]:
    """Requisiti esterni di uno strumento, con la variabile che li soddisfa.

    L'elenco sta in `tool_config.VARIABILI`, lo stesso che decide cosa si puo'
    scrivere dall'interfaccia: due elenchi separati avrebbero permesso di
    descrivere una variabile senza poterla impostare, che e' esattamente cio'
    che rendeva la schermata inutile.
    """
    from app.services.tool_config import VARIABILI

    return [RequisitoStrumento(
        variabile=v.nome, valore_presente=v.nome in impostate,
        gratuito=v.gratuito, dove=v.dove, nota=v.nota,
        etichetta=v.etichetta, segreto=v.segreto)
        for v in VARIABILI if v.strumento == chiave]


# Strumenti che dipendono da un binario o da un runtime nel worker, non da una
# variabile: il rimedio e' l'immagine, non la configurazione.
def _dipendenze_nel_worker() -> dict[str, str]:
    dipendenze: dict[str, str] = {}
    # naabu non pubblica binari per arm64 (usa libpcap tramite CGO). Su amd64
    # e' invece presente: dichiararlo mancante ovunque mandava a cercare un
    # problema che su quella architettura non esiste.
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        dipendenze["naabu"] = (
            f"Non esistono binari di naabu per l'architettura "
            f"{platform.machine()}: la rilevazione dei servizi e' svolta da "
            "`port_scan`, integrato nella piattaforma. Nessun intervento "
            "necessario.")
    return dipendenze


# Strumenti installati e configurati che restano inattivi finche' non ricevono
# qualcosa durante la scansione. Non sono un guasto e non hanno una variabile
# da impostare: senza dirlo, si finisce a cercare una configurazione assente.
AZIONI_DELL_ANALISTA = {
    "email_header": "Nessuna configurazione. L'analisi richiede l'intestazione "
                    "completa di un messaggio ricevuto dall'organizzazione, da "
                    "incollare all'avvio della scansione: senza, non c'e' nulla "
                    "da esaminare.",
    "port_scan": "Nessuna configurazione. Sonda gli indirizzi IP pubblici che "
                 "risolvono da un dominio di cui e' stata verificata la "
                 "proprieta' e che non stanno su infrastruttura condivisa "
                 "(CDN, reverse proxy). Se resta saltato, mancano domini "
                 "verificati in Gestione azienda.",
    "xposedornot": "Nessuna configurazione: la fonte e' gratuita e senza "
                   "chiave. Esamina gli indirizzi e-mail dell'organizzazione "
                   "gia' noti; se non ne e' stato individuato nessuno, non ha "
                   "bersagli.",
}


def stato_strumenti(db: Any = None) -> list[dict[str, Any]]:
    """Elenco degli strumenti con cio' che manca a ciascuno.

    Senza sessione si guarda solo l'ambiente: e' il comportamento di prima,
    utile dove il database non c'e'.
    """
    from app.services.tool_config import origine, valori_effettivi

    impostate = valori_effettivi(db)
    fonti = origine(db)
    configurazione = load_yaml_config("tool_profiles")
    profili = configurazione.get("profiles", {})
    strumenti = configurazione.get("tools", {})

    per_strumento: dict[str, list[str]] = {}
    for nome, definizione in profili.items():
        for chiave in definizione.get("tools", []):
            per_strumento.setdefault(chiave, []).append(nome)

    nel_worker = _dipendenze_nel_worker()
    esiti: list[StatoStrumento] = []
    for chiave, definizione in strumenti.items():
        requisiti = _requisiti(chiave, impostate)
        mancanti = [r for r in requisiti if not r.valore_presente]
        motivo = None
        rimedio = "configurazione"
        if chiave in nel_worker:
            motivo, rimedio = nel_worker[chiave], "immagine"
        elif chiave in AZIONI_DELL_ANALISTA:
            motivo, rimedio = AZIONI_DELL_ANALISTA[chiave], "uso"
        elif mancanti:
            motivo = "Manca " + ", ".join(r.variabile or "" for r in mancanti) + "."
        esiti.append(StatoStrumento(
            chiave=chiave, etichetta=str(definizione.get("label", chiave)),
            profili=sorted(per_strumento.get(chiave, [])),
            aree=list(definizione.get("coverage_areas", [])),
            # Uno strumento che aspetta un dato dall'analista e' configurato:
            # contarlo fra quelli da sistemare gonfierebbe l'elenco di cose
            # da fare con voci su cui non c'e' nulla da fare.
            configurato=not mancanti and chiave not in nel_worker,
            requisiti=requisiti, motivo=motivo, rimedio=rimedio,
            origine=fonti))

    # Prima cio' che non funziona: e' l'elenco di cosa c'e' da fare.
    esiti.sort(key=lambda s: (s.configurato, s.etichetta.lower()))
    return [s.to_dict() for s in esiti]
