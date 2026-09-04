"""L'API e il worker devono parlare con lo stesso broker.

E' l'invariante che decide se una scansione parte o resta in coda per sempre.
Nessun test applicativo lo copriva: i due lati funzionavano entrambi, ma su
code diverse.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[1]


def _in_processo_pulito(codice: str) -> str:
    """Esegue il codice in un interprete separato.

    Necessario: l'app Celery e' uno stato globale del processo, e negli altri
    test qualcuno ha gia' importato `celery_app`. Il difetto si manifesta
    proprio quando quell'import NON e' avvenuto, come nel processo dell'API.
    """
    esito = subprocess.run(
        [sys.executable, "-c", codice], capture_output=True, text=True, timeout=120,
        cwd=REPO, env={"PATH": "/usr/bin:/bin", "PYTHONPATH": f"{REPO}/backend:{REPO}",
                       "DATABASE_URL": "sqlite+pysqlite:///:memory:",
                       "JWT_SECRET_KEY": "prova-accodamento-1234",
                       "CELERY_BROKER_URL": "redis://broker-di-prova:6379/7"})
    assert esito.returncode == 0, esito.stderr
    return esito.stdout.strip()


def test_il_task_usa_il_broker_configurato_anche_importato_da_solo():
    """L'API importa `app.workers.tasks` senza importare `celery_app`.

    Con `shared_task` il task si registrava sull'app predefinita di Celery, il
    cui broker non e' configurato: i messaggi accodati dall'API non
    raggiungevano mai il worker e la scansione restava «accodata» a tempo
    indeterminato, senza errori da nessuna parte.
    """
    uscita = _in_processo_pulito(
        "from app.workers.tasks import run_scan_task\n"
        "print(run_scan_task.app.main, run_scan_task.app.conf.broker_url)")
    nome, _, broker = uscita.partition(" ")
    # Il nome dell'app e' il discriminante: l'app predefinita si chiama
    # "default" e, pur leggendo CELERY_BROKER_URL dall'ambiente, non ha la
    # configurazione del prodotto (code, serializzazione, limiti).
    assert nome == "defenix", f"il task e' registrato sull'app «{nome}», non su quella del prodotto"
    assert "broker-di-prova" in broker


def test_il_task_e_instradato_sulla_coda_ascoltata_dal_worker():
    """Il worker ascolta `scans` e `maintenance`: un task instradato altrove
    non verrebbe mai consumato."""
    uscita = _in_processo_pulito(
        "from app.workers.tasks import run_scan_task\n"
        "print(run_scan_task.app.conf.task_routes['defenix.scan.run']['queue'])")
    assert uscita == "scans"

    comando = (REPO / "workers" / "Dockerfile").read_text(encoding="utf-8")
    assert "--queues=scans,maintenance" in comando, (
        "il worker non ascolta la coda su cui i task vengono instradati")


def test_tutti_i_task_sono_registrati_sull_app_configurata():
    uscita = _in_processo_pulito(
        "import app.workers.tasks as t\n"
        "print(','.join(sorted(n for n in t.celery_app.tasks if n.startswith('defenix'))))")
    assert uscita.split(",") == ["defenix.feeds.refresh", "defenix.retention.apply",
                                 "defenix.scan.run"]
