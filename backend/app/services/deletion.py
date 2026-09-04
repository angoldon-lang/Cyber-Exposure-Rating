"""Cancellazione di un'azienda e di tutti i suoi dati.

Due livelli, deliberatamente distinti:

* **archiviazione** (`is_active = False`): l'azienda sparisce dagli elenchi
  operativi ma storico, evidenze e report restano consultabili. E' l'operazione
  normale quando un contratto termina.
* **cancellazione definitiva**: rimuove ogni riga collegata. Serve a soddisfare
  una richiesta di cancellazione dei dati, e' irreversibile ed e' riservata al
  Platform Administrator.

L'ordine di cancellazione e l'elenco delle tabelle sono ricavati dai metadati
SQLAlchemy invece che scritti a mano: una tabella aggiunta in futuro viene
inclusa automaticamente, senza lasciare righe orfane che violerebbero i vincoli
di integrita' o, peggio, sopravviverebbero silenziosamente a una cancellazione
richiesta dall'interessato.

Il registro di audit non viene mai toccato: e' append-only per requisito, non
ha riferimenti alle aziende e deve conservare traccia della cancellazione
stessa.
"""
from __future__ import annotations

import uuid

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app.models import Base

# Tabelle da non toccare mai, qualunque relazione abbiano.
TABELLE_PROTETTE = {"audit_logs"}


def _tabelle_azienda() -> set[str]:
    return {nome for nome, tabella in Base.metadata.tables.items()
            if "company_id" in tabella.c and nome not in TABELLE_PROTETTE}


def _dipende_da_azienda(tabella, scoped: set[str]) -> bool:
    """Vero per una tabella che dipende da una company-scoped senza esserlo.

    Esempi: `tool_runs` (figlia di `scans`), `score_categories` (figlia di
    `scores`), `confidence_scores` (figlia di entrambe).
    """
    return any(fk.column.table.name in scoped for fk in tabella.foreign_keys)


def piano_di_cancellazione() -> list[str]:
    """Tabelle coinvolte, gia' ordinate dai figli verso i padri."""
    scoped = _tabelle_azienda()
    return [t.name for t in reversed(Base.metadata.sorted_tables)
            if t.name not in TABELLE_PROTETTE
            and (t.name in scoped or _dipende_da_azienda(t, scoped))]


def purge_company(db: Session, company_id: uuid.UUID) -> dict[str, int]:
    """Cancella definitivamente tutti i dati dell'azienda.

    Ritorna il numero di righe rimosse per tabella: viene registrato nell'audit
    log, cosi' la cancellazione resta dimostrabile anche se i dati non ci sono
    piu'.
    """
    scoped = _tabelle_azienda()
    rimosse: dict[str, int] = {}

    for tabella in reversed(Base.metadata.sorted_tables):
        if tabella.name in TABELLE_PROTETTE:
            continue

        if tabella.name in scoped:
            condizione = tabella.c.company_id == company_id
        else:
            condizioni = []
            for fk in tabella.foreign_keys:
                padre = fk.column.table
                if padre.name in scoped:
                    condizioni.append(
                        tabella.c[fk.parent.name].in_(
                            select(padre.c[fk.column.name])
                            .where(padre.c.company_id == company_id)))
            if not condizioni:
                continue
            condizione = or_(*condizioni)

        esito = db.execute(delete(tabella).where(condizione))
        if esito.rowcount:
            rimosse[tabella.name] = esito.rowcount

    return rimosse
