"""Scansioni rimaste in corso senza nessuno che le esegua.

Una scansione viene marcata `running` dal worker e riportata a uno stato
terminale solo dal worker stesso. Se quel processo muore — container
riavviato, macchina sospesa, limite di tempo raggiunto — la riga resta
`running` per sempre: l'azienda non puo' piu' essere scansionata e il
messaggio riaccodato dal broker trova lo stato `running` e si arrende.
"""
from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.enums import ScanStatus
from app.models.scanning import Scan
from app.services.scan_recovery import e_orfana, recupera_orfane, soglia_abbandono
from tests.test_company_crud import _azienda, admin, client, tenant_unico  # noqa: F401

pytestmark = pytest.mark.security


def _con_dominio(client, admin, azienda: dict) -> dict:  # noqa: F811
    """Il gate di autorizzazione rifiuta prima ancora di guardare le
    scansioni in corso: senza un dominio non si arriva al caso da provare."""
    risposta = client.post(f"/api/v1/companies/{azienda['id']}/domains", headers=admin,
                           json={"name": "acme-orfane.example", "is_primary": True})
    assert risposta.status_code == 201, risposta.text
    return azienda


def _usa_il_database_di_prova(monkeypatch, client, modulo) -> None:  # noqa: F811
    """Worker e CLI aprono la sessione da soli, non tramite le dipendenze
    dell'API: senza questo puntano al database reale."""
    @contextmanager
    def sessione():  # noqa: ANN202
        db = client.session_factory()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    monkeypatch.setattr(modulo, "session_scope", sessione)


def _scansione(client, azienda: dict, *, stato: str, eta: timedelta) -> uuid.UUID:  # noqa: F811
    momento = datetime.now(UTC) - eta
    with client.session_factory() as db:
        scan = Scan(
            tenant_id=uuid.UUID(azienda["tenant_id"]), company_id=uuid.UUID(azienda["id"]),
            profile_key="public_passive", status=stato, mock_mode=True,
            started_at=momento, progress_percent=60, current_stage="analysis:testssl",
            scope_snapshot_json={"domains": ["acme.example"]})
        db.add(scan)
        db.flush()
        # `updated_at` ha `onupdate`: va forzato dopo il flush per simulare
        # una riga che nessuno tocca da tempo.
        db.execute(Scan.__table__.update().where(Scan.id == scan.id)
                   .values(updated_at=momento))
        db.commit()
        return scan.id


# ------------------------------------------------------------------ criterio
def test_una_scansione_recente_non_e_orfana(client, admin):  # noqa: F811
    """Uno strumento lento aggiorna la riga solo quando finisce: non va
    scambiato per un processo morto."""
    azienda = _azienda(client, admin)
    identificativo = _scansione(client, azienda, stato=ScanStatus.RUNNING.value,
                                eta=timedelta(minutes=5))
    with client.session_factory() as db:
        assert not e_orfana(db.get(Scan, identificativo))


def test_una_scansione_ferma_oltre_la_soglia_e_orfana(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    identificativo = _scansione(client, azienda, stato=ScanStatus.RUNNING.value,
                                eta=soglia_abbandono() + timedelta(minutes=5))
    with client.session_factory() as db:
        assert e_orfana(db.get(Scan, identificativo))


def test_una_scansione_conclusa_non_e_mai_orfana(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    identificativo = _scansione(client, azienda, stato=ScanStatus.COMPLETED.value,
                                eta=timedelta(days=30))
    with client.session_factory() as db:
        assert not e_orfana(db.get(Scan, identificativo))


def test_la_soglia_supera_il_limite_del_task():
    """Sotto il limite di Celery una scansione viva verrebbe dichiarata morta."""
    from app.core.config import settings

    assert soglia_abbandono().total_seconds() > settings.celery_task_time_limit


# -------------------------------------------------------------------- chiusura
def test_la_scansione_orfana_risulta_fallita_non_annullata(client, admin):  # noqa: F811
    """Nessuno l'ha annullata: e' il processo che se n'e' andato, e la
    distinzione conta nello storico."""
    azienda = _azienda(client, admin)
    identificativo = _scansione(client, azienda, stato=ScanStatus.RUNNING.value,
                                eta=soglia_abbandono() + timedelta(minutes=5))
    with client.session_factory() as db:
        assert len(recupera_orfane(db)) == 1
        db.commit()
        chiusa = db.get(Scan, identificativo)
        assert chiusa.status == ScanStatus.FAILED.value
        assert chiusa.finished_at is not None
        assert "non e' piu' attivo" in (chiusa.error_message or "")


# ----------------------------------------------------------------------- API
def test_una_scansione_orfana_non_blocca_l_azienda(client, admin, monkeypatch):  # noqa: F811
    """Regressione: l'avvio rifiutava con 409 finche' la riga restava in
    corso, cioe' per sempre. L'unico rimedio sarebbe stato agire sul
    database."""
    from app.api.routers import scans as router

    # L'accodamento su Celery non c'entra con la decisione da verificare, e
    # senza broker impiegherebbe venti secondi a rinunciare.
    monkeypatch.setattr(router, "_enqueue", lambda *_a, **_k: None)
    azienda = _con_dominio(client, admin, _azienda(client, admin))
    _scansione(client, azienda, stato=ScanStatus.RUNNING.value,
               eta=soglia_abbandono() + timedelta(minutes=5))

    risposta = client.post(f"/api/v1/companies/{azienda['id']}/scans", headers=admin,
                           json={"profile": "public_passive"})
    assert risposta.status_code == 202, risposta.text

    with client.session_factory() as db:
        stati = {s.status for s in db.execute(
            select(Scan).where(Scan.company_id == uuid.UUID(azienda["id"]))).scalars().all()}
        assert ScanStatus.FAILED.value in stati, "l'orfana non e' stata chiusa"


def test_una_scansione_viva_blocca_ancora_l_azienda(client, admin):  # noqa: F811
    """Il recupero non deve diventare un modo per lanciare due scansioni in
    parallelo sulla stessa azienda."""
    azienda = _con_dominio(client, admin, _azienda(client, admin))
    _scansione(client, azienda, stato=ScanStatus.RUNNING.value, eta=timedelta(minutes=2))

    risposta = client.post(f"/api/v1/companies/{azienda['id']}/scans", headers=admin,
                           json={"profile": "public_passive"})
    assert risposta.status_code == 409
    dettaglio = risposta.json()["detail"]
    assert "60%" in dettaglio and "analysis:testssl" in dettaglio, (
        "il messaggio deve dire a che punto e', altrimenti non si sa se attendere")


# ------------------------------------------------------------------- worker
def test_il_worker_chiude_l_orfana_invece_di_arrendersi(client, admin, monkeypatch):  # noqa: F811
    """Il broker riaccoda il messaggio quando il processo se n'e' andato:
    trovare lo stato `running` e fermarsi lascia tutto com'era."""
    from app.workers import tasks
    from app.workers.tasks import run_scan_task

    _usa_il_database_di_prova(monkeypatch, client, tasks)
    azienda = _azienda(client, admin)
    identificativo = _scansione(client, azienda, stato=ScanStatus.RUNNING.value,
                                eta=soglia_abbandono() + timedelta(minutes=5))

    esito = run_scan_task(str(identificativo))
    assert esito["status"] == "recovered"

    with client.session_factory() as db:
        assert db.get(Scan, identificativo).status == ScanStatus.FAILED.value


def test_il_worker_non_tocca_una_scansione_viva(client, admin, monkeypatch):  # noqa: F811
    from app.workers import tasks
    from app.workers.tasks import run_scan_task

    _usa_il_database_di_prova(monkeypatch, client, tasks)
    azienda = _azienda(client, admin)
    identificativo = _scansione(client, azienda, stato=ScanStatus.RUNNING.value,
                                eta=timedelta(minutes=2))

    esito = run_scan_task(str(identificativo))
    assert esito["status"] == "skipped"
    with client.session_factory() as db:
        assert db.get(Scan, identificativo).status == ScanStatus.RUNNING.value


# ---------------------------------------------------------------------- CLI
def test_il_comando_elenca_e_chiude(client, admin, monkeypatch):  # noqa: F811
    """Con `--chiudi` non si attende la soglia: e' una decisione
    dell'operatore, che sa se il worker sta lavorando."""
    from app import cli

    azienda = _azienda(client, admin)
    _scansione(client, azienda, stato=ScanStatus.RUNNING.value, eta=timedelta(minutes=1))
    _usa_il_database_di_prova(monkeypatch, client, cli)

    elenco = cli.scansioni()
    assert len(elenco["scans"]) == 1
    assert elenco["scans"][0]["orphan"] is False
    assert elenco["closed"] == 0

    chiuse = cli.scansioni(chiudi=True)
    assert chiuse["closed"] == 1
    assert cli.scansioni()["scans"] == []
