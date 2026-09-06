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

from dataclasses import dataclass, field
from typing import Any

from app.core.config import load_yaml_config, settings


@dataclass
class RequisitoStrumento:
    """Cosa serve a uno strumento per funzionare."""

    variabile: str | None = None
    valore_presente: bool = False
    gratuito: bool = True
    dove: str | None = None
    nota: str | None = None


@dataclass
class StatoStrumento:
    chiave: str
    etichetta: str
    profili: list[str] = field(default_factory=list)
    aree: list[str] = field(default_factory=list)
    configurato: bool = True
    requisiti: list[RequisitoStrumento] = field(default_factory=list)
    motivo: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.chiave, "label": self.etichetta, "profiles": self.profili,
            "areas": self.aree, "configured": self.configurato, "reason": self.motivo,
            "requirements": [
                {"variable": r.variabile, "present": r.valore_presente,
                 "free": r.gratuito, "where": r.dove, "note": r.nota}
                for r in self.requisiti],
        }


def _requisiti(chiave: str) -> list[RequisitoStrumento]:
    """Requisiti esterni di uno strumento, con la variabile che li soddisfa."""
    if chiave == "spiderfoot":
        return [RequisitoStrumento(
            variabile="SPIDERFOOT_URL", valore_presente=bool(settings.spiderfoot_url),
            gratuito=True, dove="https://github.com/smicallef/spiderfoot",
            nota="Istanza SpiderFoot raggiungibile dal worker. Si avvia con "
                 "`docker run -p 5001:5001 ghcr.io/smicallef/spiderfoot` e si "
                 "indica come SPIDERFOOT_URL=http://spiderfoot:5001.")]
    if chiave == "hibp":
        return [RequisitoStrumento(
            variabile="HIBP_API_KEY", valore_presente=bool(settings.hibp_api_key),
            gratuito=False, dove="https://haveibeenpwned.com/API/Key",
            nota="Abbonamento a pagamento. Senza, la ricerca per dominio non e' "
                 "disponibile: XposedOrNot copre in parte la stessa area, gratis.")]
    if chiave == "credential_exposure":
        return [RequisitoStrumento(
            variabile="CREDENTIAL_EXPOSURE_URL",
            valore_presente=bool(settings.credential_exposure_url), gratuito=False,
            nota="Indirizzo della fonte di intelligence su credenziali esposte."),
            RequisitoStrumento(
            variabile="CREDENTIAL_EXPOSURE_API_KEY",
            valore_presente=bool(settings.credential_exposure_api_key), gratuito=False,
            nota="Le fonti serie in questo ambito sono tutte commerciali. "
                 "Senza abbonamento l'area resta scoperta e il rating lo dichiara.")]
    return []


# Strumenti che dipendono da un binario o da un runtime nel worker, non da una
# variabile: il rimedio e' l'immagine, non la configurazione.
DIPENDENZE_NEL_WORKER = {
    "amass_passive": "Il binario `amass` non e' nell'immagine del worker. "
                     "Subfinder e Certificate Transparency coprono gia' "
                     "l'enumerazione dei sottodomini.",
    "zap_baseline": "Richiede un runtime Docker dentro il worker, che per "
                    "scelta non c'e': il worker non deve poter avviare "
                    "container. L'analisi web resta coperta da httpx e Nuclei.",
    "naabu": "Non esistono binari per l'architettura del worker: la "
             "rilevazione dei servizi e' svolta da `port_scan`, integrato.",
}


def stato_strumenti() -> list[dict[str, Any]]:
    """Elenco degli strumenti con cio' che manca a ciascuno."""
    configurazione = load_yaml_config("tool_profiles")
    profili = configurazione.get("profiles", {})
    strumenti = configurazione.get("tools", {})

    per_strumento: dict[str, list[str]] = {}
    for nome, definizione in profili.items():
        for chiave in definizione.get("tools", []):
            per_strumento.setdefault(chiave, []).append(nome)

    esiti: list[StatoStrumento] = []
    for chiave, definizione in strumenti.items():
        requisiti = _requisiti(chiave)
        mancanti = [r for r in requisiti if not r.valore_presente]
        motivo = None
        if chiave in DIPENDENZE_NEL_WORKER:
            motivo = DIPENDENZE_NEL_WORKER[chiave]
        elif mancanti:
            motivo = "Manca " + ", ".join(r.variabile or "" for r in mancanti) + "."
        esiti.append(StatoStrumento(
            chiave=chiave, etichetta=str(definizione.get("label", chiave)),
            profili=sorted(per_strumento.get(chiave, [])),
            aree=list(definizione.get("coverage_areas", [])),
            configurato=not mancanti and chiave not in DIPENDENZE_NEL_WORKER,
            requisiti=requisiti, motivo=motivo))

    # Prima cio' che non funziona: e' l'elenco di cosa c'e' da fare.
    esiti.sort(key=lambda s: (s.configurato, s.etichetta.lower()))
    return [s.to_dict() for s in esiti]
