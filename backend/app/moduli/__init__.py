"""Contesti applicativi costruiti sopra il motore di rating.

## La regola

Un solo repository, due prodotti: **Defenix Security Rating**, che si vende
gia' oggi, e i moduli che gli si appoggiano sopra (conformita', NIS2 Starter,
TPRM). Perche' i due restino separabili davvero — e non solo a parole — vale
una regola sola:

    i moduli importano dal motore; il motore non importa mai dai moduli.

Il motore e' `app.core`, `app.models`, `app.services`, `app.api.routers`,
piu' `adapters/` e `reporting/`. Se un giorno il motore importasse da qui,
estrarlo come prodotto a se' diventerebbe un lavoro di districamento invece
che una cancellazione di cartelle.

La regola non e' affidata alla buona volonta': la verifica
`tests/test_confini_moduli.py`, che legge gli import di ogni file sorgente.

## Perche' i modelli si registrano qui e non in `app.models`

`app/models/__init__.py` importa tutte le tabelle del motore perche' Alembic
le veda. Se importasse anche quelle dei moduli, il motore dipenderebbe dai
moduli e la regola sarebbe violata alla prima riga. Quindi i moduli tengono
il proprio registro qui, e l'ambiente di migrazione importa entrambi: e' il
solo punto del progetto che conosce tutte e due le meta', ed e' corretto che
sia lui, perche' non e' codice di prodotto.
"""
from __future__ import annotations

from app.moduli.conformita.models import (
    Controllo,
    Framework,
    Requisito,
    StatoControllo,
    controllo_requisiti,
)

__all__ = [
    "Controllo",
    "Framework",
    "Requisito",
    "StatoControllo",
    "controllo_requisiti",
]
