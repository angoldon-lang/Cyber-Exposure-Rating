"""Stato dei controlli dedotto da cio' che la scansione ha gia' visto.

Questo modulo non calcola punteggi e non tocca il rating: legge i rilievi
prodotti dal motore e risponde a una domanda diversa — *questo controllo
risulta implementato?* La direzione e' una sola, e va tenuta: la scansione
risponde al controllo, il controllo non cambia il punteggio.

## La regola che tiene onesto il risultato

L'assenza di rilievi non e' prova di conformita'. Vale per il rating — e' la
ragione per cui esiste un indice di affidabilita' separato — e vale a maggior
ragione qui, dove il risultato finisce in un documento che qualcuno mostrera'
a un'autorita'. Quindi:

* rilievi presenti fra quelli che smentiscono il controllo -> **assente**,
  e si puo' dire quali;
* nessun rilievo, **ma** gli strumenti che coprono quell'area hanno girato
  davvero -> **implementato**, con evidenza *dedotta*, non confermata;
* nessun rilievo e nessuno strumento che abbia guardato -> **non valutato**.

Il terzo caso e' quello che un sistema disonesto colorerebbe di verde.

## La contraddizione fra dichiarato e osservato

Quando arrivera' il questionario, la stessa funzione riceve le dichiarazioni
dell'organizzazione e le confronta con l'osservato. Dove i due divergono — il
fornitore dichiara il controllo implementato e la scansione lo smentisce — la
contraddizione e' essa stessa un risultato, ed e' cio' che una piattaforma
fatta di soli questionari non puo' produrre.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import ConfidenceClass
from app.moduli.conformita.catalogo import Catalogo, ControlloCfg
from app.moduli.conformita.enums import OrigineStato, StatoConformita

# Ordine di forza probatoria delle classi di evidenza: serve a scegliere la
# piu' forte fra i rilievi che smentiscono un controllo.
_FORZA = {
    ConfidenceClass.CONFIRMED.value: 4,
    ConfidenceClass.PROBABLE.value: 3,
    ConfidenceClass.INFERRED.value: 2,
    ConfidenceClass.INFORMATIONAL.value: 1,
}

# Esiti di uno strumento che contano come «ha guardato davvero». Un guasto o
# uno strumento non configurato non autorizzano a dedurre nulla.
_ESITI_VALIDI = {"success", "partial"}


@dataclass
class EsitoControllo:
    controllo: ControlloCfg
    stato: str
    origine: str | None
    confidence_class: str | None
    motivo_it: str
    rilievi: list[str] = field(default_factory=list)
    # Popolato solo quando una dichiarazione contraddice l'osservato.
    contraddizione_it: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.controllo.code,
            "titolo": self.controllo.title_it,
            "area": self.controllo.area,
            "stato": self.stato,
            "origine": self.origine,
            "confidence_class": self.confidence_class,
            "motivo_it": self.motivo_it,
            "rilievi": list(self.rilievi),
            "contraddizione_it": self.contraddizione_it,
            "evidenza_attesa_it": self.controllo.evidenza_attesa_it,
            "requisiti": list(self.controllo.soddisfa),
        }


def _aree_osservate(coverage_matrix: list[dict[str, Any]]) -> set[str]:
    """Le aree su cui almeno uno strumento ha prodotto un risultato usabile."""
    aree: set[str] = set()
    for riga in coverage_matrix or []:
        if str(riga.get("status")) in _ESITI_VALIDI:
            aree.update(riga.get("areas") or [])
    return aree


def _rilievi_per_tipo(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indice: dict[str, list[dict[str, Any]]] = {}
    for finding in findings or []:
        if finding.get("excluded_from_rating"):
            continue
        indice.setdefault(str(finding.get("finding_type")), []).append(finding)
    return indice


def valuta(catalogo: Catalogo, *, findings: list[dict[str, Any]],
           coverage_matrix: list[dict[str, Any]],
           dichiarazioni: dict[str, str] | None = None) -> list[EsitoControllo]:
    """Lo stato di ogni controllo del catalogo per una scansione.

    `dichiarazioni` associa il codice di un controllo allo stato dichiarato
    dall'organizzazione. Oggi arriva vuoto: ci arrivera' il questionario.
    """
    osservate = _aree_osservate(coverage_matrix)
    per_tipo = _rilievi_per_tipo(findings)
    dichiarazioni = dichiarazioni or {}
    esiti: list[EsitoControllo] = []

    for controllo in catalogo.controlli.values():
        smentite = [f for tipo in controllo.finding_types for f in per_tipo.get(tipo, [])]

        if smentite:
            classe = max(
                (str(f.get("confidence_class")) for f in smentite),
                key=lambda c: _FORZA.get(c, 0))
            quanti = len(smentite)
            esito = EsitoControllo(
                controllo=controllo,
                stato=StatoConformita.ASSENTE.value,
                origine=OrigineStato.DEDOTTO.value,
                confidence_class=classe,
                motivo_it=(f"{quanti} rilie{'vo' if quanti == 1 else 'vi'} "
                           f"dalla scansione smentis{'ce' if quanti == 1 else 'cono'} "
                           f"il controllo."),
                rilievi=[str(f.get("reference_code")) for f in smentite
                         if f.get("reference_code")])
        elif not controllo.osservabile:
            esito = EsitoControllo(
                controllo=controllo,
                stato=StatoConformita.NON_VALUTATO.value,
                origine=None, confidence_class=None,
                motivo_it=("Dall'esterno non si vede: serve la risposta "
                           "dell'organizzazione, con la prova allegata."))
        elif controllo.area and controllo.area not in osservate:
            esito = EsitoControllo(
                controllo=controllo,
                stato=StatoConformita.NON_VALUTATO.value,
                origine=None, confidence_class=None,
                motivo_it=("Nessuno strumento ha guardato quest'area: l'assenza "
                           "di rilievi non dice niente."))
        else:
            esito = EsitoControllo(
                controllo=controllo,
                stato=StatoConformita.IMPLEMENTATO.value,
                origine=OrigineStato.DEDOTTO.value,
                # Dedotto dall'assenza, non osservato: e' la classe piu' debole
                # che la piattaforma ammette, e va detto.
                confidence_class=ConfidenceClass.INFERRED.value,
                motivo_it=("Gli strumenti che coprono quest'area hanno girato "
                           "e non hanno trovato rilievi contrari."))

        dichiarato = dichiarazioni.get(controllo.code)
        if (dichiarato == StatoConformita.IMPLEMENTATO.value
                and esito.stato == StatoConformita.ASSENTE.value):
            esito.contraddizione_it = (
                "L'organizzazione dichiara il controllo implementato, ma la "
                "scansione lo smentisce. La contraddizione va chiarita prima "
                "di considerare valida la dichiarazione.")
        esiti.append(esito)

    return esiti


def riepilogo(esiti: list[EsitoControllo]) -> dict[str, Any]:
    """I conteggi per stato, piu' la sola percentuale che si possa dichiarare.

    La percentuale si calcola sui controlli **valutati**, non sul totale:
    dividere per il totale farebbe scendere la conformita' ogni volta che si
    aggiunge un controllo nuovo, e salire ogni volta che se ne toglie uno che
    nessuno aveva guardato.
    """
    conteggi = {stato.value: 0 for stato in StatoConformita}
    for esito in esiti:
        conteggi[esito.stato] = conteggi.get(esito.stato, 0) + 1

    valutati = (conteggi[StatoConformita.IMPLEMENTATO.value]
                + conteggi[StatoConformita.PARZIALE.value]
                + conteggi[StatoConformita.ASSENTE.value])
    implementati = conteggi[StatoConformita.IMPLEMENTATO.value]
    return {
        "conteggi": conteggi,
        "totale": len(esiti),
        "valutati": valutati,
        "percentuale_sui_valutati": round(100.0 * implementati / valutati, 1) if valutati else None,
        "contraddizioni": sum(1 for e in esiti if e.contraddizione_it),
    }
