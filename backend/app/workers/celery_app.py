"""Configurazione Celery.

I worker girano in container separati dall'API, con utente non root e limiti
di risorse: nessun tool di scansione viene mai eseguito nel container API.
"""
from __future__ import annotations

from celery import Celery

from app.core.config import settings
from app.core.logging import configure_logging

configure_logging()

celery_app = Celery("defenix", broker=settings.celery_broker_url,
                    backend=settings.celery_result_backend)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],           # niente pickle: nessuna deserializzazione arbitraria
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.celery_task_time_limit,
    task_soft_time_limit=settings.celery_task_soft_time_limit,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,      # una scansione per worker alla volta
    worker_max_tasks_per_child=20,     # riciclo del processo: nessuna perdita di risorse
    broker_connection_retry_on_startup=True,
    # Redis riconsegna un messaggio non confermato dopo il proprio tempo di
    # visibilita' (un'ora per impostazione predefinita). Una scansione lunga
    # veniva cosi' riaccodata mentre era ancora in corso: la seconda copia
    # trovava la scansione in stato `running` e si fermava, ma il messaggio
    # continuava a girare. Il tempo di visibilita' deve superare il limite
    # massimo del task, non essere piu' corto.
    broker_transport_options={
        "visibility_timeout": settings.celery_task_time_limit + 600,
    },
    result_expires=86400,
    task_routes={
        "defenix.scan.run": {"queue": "scans"},
        "defenix.feeds.refresh": {"queue": "maintenance"},
        "defenix.retention.apply": {"queue": "maintenance"},
    },
    beat_schedule={
        "refresh-vulnerability-feeds": {
            "task": "defenix.feeds.refresh",
            "schedule": 6 * 3600.0,
        },
        "apply-retention-policies": {
            "task": "defenix.retention.apply",
            "schedule": 24 * 3600.0,
        },
    },
)

celery_app.autodiscover_tasks(["app.workers"])
