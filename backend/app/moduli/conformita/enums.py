"""Vocabolario della conformita'.

Sta qui e non in `app/models/enums.py` perche' il motore non deve conoscere i
moduli. Le classi di evidenza invece si prendono dal motore: sono le stesse
per un rilievo osservato e per una dichiarazione con prova allegata, e
duplicarle significherebbe ritrovarsi due scale che divergono.
"""
from __future__ import annotations

from app.models.enums import StrEnum


class StatoConformita(StrEnum):
    """Stato di un controllo per un'azienda.

    «Non valutato» e' uno stato, non l'assenza di un record: un controllo mai
    guardato e un controllo guardato e trovato a posto non sono la stessa
    cosa, ed e' l'errore che rende verdi i cruscotti vuoti.
    """

    IMPLEMENTATO = "implementato"
    PARZIALE = "parziale"
    ASSENTE = "assente"
    NON_APPLICABILE = "non_applicabile"
    NON_VALUTATO = "non_valutato"


class OrigineStato(StrEnum):
    """Da dove viene la risposta.

    L'ordine e' quello della forza probatoria: cio' che si osserva da fuori
    vale piu' di cio' che viene dichiarato, e una dichiarazione con prova
    allegata sta in mezzo.
    """

    DEDOTTO = "dedotto"        # dalla scansione: osservato, nessuno lo ha detto
    DICHIARATO = "dichiarato"  # risposta al questionario, senza prova
    VERIFICATO = "verificato"  # dichiarato, con evidenza allegata e valida
