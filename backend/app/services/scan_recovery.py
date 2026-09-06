"""Recupero delle scansioni rimaste in corso senza nessuno che le esegua.

Il problema
-----------
Una scansione viene marcata `running` dal worker e riportata a uno stato
terminale solo dal worker stesso, alla fine. Se quel processo muore — il
container riavviato, la macchina sospesa, il limite di tempo del task
raggiunto — la riga resta `running` per sempre: nessuno la conclude e
nessuno la riprende.

Le conseguenze non sono cosmetiche. L'azienda non puo' piu' essere
scansionata, perche' l'avvio rifiuta una nuova scansione quando ne trova una
in corso; e il messaggio riaccodato dal broker trova lo stato `running` e si
ferma, lasciando tutto com'era. Il risultato e' un'azienda bloccata a tempo
indeterminato da una scansione che non esiste piu'.

Il criterio
-----------
Una scansione e' orfana se non viene toccata da piu' del limite massimo del
task Celery, con un margine. Oltre quel limite il processo sarebbe stato
comunque terminato da Celery: se la riga non e' cambiata, nessuno la sta
eseguendo. Il margine evita di dichiarare orfana una scansione viva ma lenta,
che aggiorna la riga solo al termine di ogni strumento.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import ScanStatus
from app.models.scanning import Scan

logger = get_logger(__name__)

# Margine oltre il limite del task: uno strumento lento aggiorna la riga solo
# quando finisce, e non va scambiato per un processo morto.
MARGINE_SECONDI = 600

STATI_IN_CORSO = (ScanStatus.PENDING.value, ScanStatus.QUEUED.value,
                  ScanStatus.RUNNING.value, ScanStatus.NORMALIZING.value,
                  ScanStatus.SCORING.value)


def soglia_abbandono() -> timedelta:
    return timedelta(seconds=settings.celery_task_time_limit + MARGINE_SECONDI)


def e_orfana(scan: Scan, *, adesso: datetime | None = None) -> bool:
    """Vero se nessuno sta piu' eseguendo questa scansione."""
    if scan.status not in STATI_IN_CORSO:
        return False
    riferimento = scan.updated_at or scan.started_at or scan.created_at
    if riferimento is None:
        return False
    if riferimento.tzinfo is None:
        riferimento = riferimento.replace(tzinfo=UTC)
    return (adesso or datetime.now(UTC)) - riferimento > soglia_abbandono()


def scansioni_orfane(db: Session, *, company_id=None) -> list[Scan]:  # noqa: ANN001
    query = select(Scan).where(Scan.status.in_(STATI_IN_CORSO))
    if company_id is not None:
        query = query.where(Scan.company_id == company_id)
    return [s for s in db.execute(query).scalars().all() if e_orfana(s)]


def recupera(db: Session, scan: Scan) -> Scan:
    """Chiude una scansione orfana dichiarando cosa e' successo.

    Lo stato e' `failed` e non `cancelled`: nessuno l'ha annullata, e' il
    processo che se n'e' andato. La distinzione conta nello storico.
    """
    stato_precedente = scan.status
    scan.status = ScanStatus.FAILED.value
    scan.finished_at = datetime.now(UTC)
    scan.error_message = (
        "Interrotta: il processo che la eseguiva non e' piu' attivo (worker "
        "riavviato, macchina sospesa o limite di tempo del task raggiunto). "
        "I risultati parziali non sono stati salvati: riavviare la scansione."
    )[:2000]
    logger.warning("scan_orphan_recovered", scan_id=str(scan.id),
                   previous_status=stato_precedente, progress=scan.progress_percent)
    return scan


def recupera_orfane(db: Session, *, company_id=None) -> list[Scan]:  # noqa: ANN001
    """Chiude tutte le scansioni orfane, opzionalmente di una sola azienda."""
    orfane = scansioni_orfane(db, company_id=company_id)
    for scan in orfane:
        recupera(db, scan)
    if orfane:
        db.flush()
    return orfane
