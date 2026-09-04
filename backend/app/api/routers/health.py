"""Health check e metadati pubblici della piattaforma."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import load_yaml_config, settings
from app.core.db import get_db
from app.schemas.common import HealthResponse

router = APIRouter(tags=["health"])

DISCLAIMER_IT = (
    "Defenix Exposure Rating e' una valutazione della sicurezza osservabile "
    "dall'esterno e dei rischi a cui l'organizzazione potrebbe essere esposta. "
    "NON costituisce un penetration test, un vulnerability assessment completo "
    "ne' una certificazione di sicurezza."
)
DISCLAIMER_EN = (
    "Defenix Exposure Rating is an assessment of externally observable security "
    "posture and of the risks the organisation may be exposed to. It is NOT a "
    "penetration test, a full vulnerability assessment, nor a security certification."
)


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        database = f"error: {type(exc).__name__}"

    redis_status = "not_configured"
    try:
        import redis

        redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2).ping()
        redis_status = "ok"
    except Exception as exc:  # noqa: BLE001
        redis_status = f"error: {type(exc).__name__}"

    workers = _worker_attivi()

    # Senza worker le scansioni vengono accodate ma nessuno le esegue: e' uno
    # stato degradato, anche se database e broker rispondono.
    overall = "ok" if database == "ok" and workers > 0 else "degraded"
    return HealthResponse(status=overall, version=settings.app_version,
                          environment=settings.environment, database=database,
                          redis=redis_status, workers=workers,
                          scan_mock_mode=settings.scan_mock_mode,
                          checked_at=datetime.now(UTC))


def _worker_attivi() -> int:
    """Worker Celery che rispondono al ping, 0 se nessuno o se il broker e' giu'."""
    try:
        from app.workers.celery_app import celery_app

        risposte = celery_app.control.ping(timeout=1.0)
        return len(risposte or [])
    except Exception:  # noqa: BLE001
        return 0


@router.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/health/ready")
def readiness(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ready"}


@router.get("/meta/disclaimer")
def disclaimer(profile: str | None = None) -> dict[str, str]:
    """Limitazione d'ambito, mostrata nell'interfaccia e in ogni report.

    Il Public Passive Check non richiede autorizzazione: usa solo fonti gia'
    pubbliche e non interroga i sistemi dell'organizzazione. Dichiarare
    un'autorizzazione inesistente sarebbe scorretto.
    """
    if profile:
        from reporting.context import disclaimer_for

        return {"it": disclaimer_for(profile), "en": DISCLAIMER_EN}
    return {"it": DISCLAIMER_IT, "en": DISCLAIMER_EN}


@router.get("/meta/profiles")
def profiles() -> dict:
    """Descrizione dei tre profili di scansione e delle azioni vietate."""
    config = load_yaml_config("tool_profiles")
    return {
        key: {
            "label_it": definition.get("label_it"),
            "label_en": definition.get("label_en"),
            "description_it": definition.get("description_it"),
            "requires_verification": definition.get("requires_verification", True),
            "requires_authorization": definition.get("requires_authorization", True),
            "requires_explicit_scope_whitelist":
                definition.get("requires_explicit_scope_whitelist", False),
            "tools": definition.get("tools", []),
            "forbidden_actions": definition.get("forbidden_actions", []),
        }
        for key, definition in config.get("profiles", {}).items()
    }


@router.get("/meta/scoring-model")
def scoring_model() -> dict:
    """Modello di scoring pubblicato: pesi, classi e soglie sono trasparenti."""
    config = load_yaml_config("scoring")
    confidence = load_yaml_config("evidence_confidence")
    return {
        "version": config.get("version"),
        "categories": [
            {"key": key, "label_it": value["label_it"], "label_en": value.get("label_en"),
             "weight": value["weight"]}
            for key, value in config["categories"].items()
        ],
        "classes": config["classes"],
        "confidence_multipliers": config["confidence_multipliers"],
        "ownership_multipliers": config["ownership_multipliers"],
        "minimum_confidence_for_rating": config.get("minimum_confidence_for_rating"),
        "confidence_factors": [
            {"key": key, "weight": value["weight"],
             "description_it": value.get("description_it")}
            for key, value in confidence["factors"].items()
        ],
        "rule_count": len(config["rules"]),
    }
