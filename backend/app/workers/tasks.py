"""Task Celery: esecuzione delle scansioni e manutenzione periodica."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.core.config import settings
from app.core.db import session_scope
from app.core.logging import get_logger
from app.models.enums import AuditAction, ScanStatus
from app.models.scanning import Scan
# I task sono legati esplicitamente a `celery_app`, non registrati con
# `shared_task`. Con `shared_task` la registrazione avviene sull'app "corrente":
# nel worker, che importa `celery_app`, e' quella giusta; nell'API, che importa
# soltanto questo modulo, e' l'app predefinita di Celery, il cui broker non e'
# configurato. Le due parti finivano cosi' su broker diversi e i messaggi
# accodati dall'API non raggiungevano mai il worker.
from app.workers.celery_app import celery_app
from app.workers.pipeline import ScanPipeline, ScanRequest

logger = get_logger(__name__)


@celery_app.task(name="defenix.scan.run", bind=True, max_retries=1,
                 default_retry_delay=60)
def run_scan_task(self, scan_id: str, email_header: str | None = None) -> dict:  # noqa: ANN001
    """Esegue una scansione gia' autorizzata.

    Il gate di autorizzazione e' applicato al momento della creazione dello
    Scan: qui si verifica soltanto che lo stato sia coerente.
    """
    from app.services.audit import record_audit
    from app.services.persistence import persist_outcome

    with session_scope() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            logger.error("scan_not_found", scan_id=scan_id)
            return {"status": "not_found", "scan_id": scan_id}
        if scan.status not in {ScanStatus.QUEUED.value, ScanStatus.PENDING.value}:
            logger.warning("scan_not_runnable", scan_id=scan_id, status=scan.status)
            return {"status": "skipped", "reason": f"stato {scan.status}"}

        snapshot = scan.scope_snapshot_json or {}
        company = scan.company
        request = ScanRequest(
            scan_id=str(scan.id), tenant_id=str(scan.tenant_id),
            company_id=str(scan.company_id), company_name=company.legal_name,
            profile=scan.profile_key,
            domains=list(snapshot.get("domains", [])),
            verified_domains=list(snapshot.get("verified_domains", [])),
            ip_addresses=list(snapshot.get("ip_addresses", [])),
            authorized_ips=list(snapshot.get("authorized_ips", [])),
            network_ranges=list(snapshot.get("network_ranges", [])),
            excluded_values=list(snapshot.get("excluded", [])),
            dkim_selectors=list(snapshot.get("dkim_selectors", [])),
            email_header=email_header,
            mock_mode=scan.mock_mode,
            connector_config=_connector_config())
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = scan.started_at or datetime.now(UTC)
        scan_pk = scan.id
        tenant_id = scan.tenant_id

    def progress(stage: str, percent: int) -> None:
        with session_scope() as db:
            row = db.get(Scan, scan_pk)
            if row is not None:
                row.current_stage = stage[:64]
                row.progress_percent = max(0, min(100, percent))

    try:
        outcome = ScanPipeline(request, progress=progress).run()
    except Exception as exc:  # noqa: BLE001
        logger.error("scan_failed", scan_id=scan_id, error=str(exc))
        with session_scope() as db:
            row = db.get(Scan, scan_pk)
            if row is not None:
                row.status = ScanStatus.FAILED.value
                row.error_message = f"{type(exc).__name__}: {exc}"[:2000]
                row.finished_at = datetime.now(UTC)
        raise

    with session_scope() as db:
        row = db.get(Scan, scan_pk)
        score = persist_outcome(db, row, outcome)
        record_audit(db, action=AuditAction.SCAN_COMPLETE.value, tenant_id=tenant_id,
                     entity_type="scan", entity_id=str(scan_pk),
                     message=(f"scansione completata: {score.overall_score:.1f}/100 "
                              f"classe {score.rating_class}"),
                     metadata=outcome.stats)
        result = {
            "scan_id": scan_id, "status": outcome.status,
            "overall_score": score.overall_score, "rating_class": score.rating_class,
            "confidence": outcome.confidence.value,
            "is_provisional": outcome.is_provisional,
            "findings": len(outcome.normalization.findings),
        }
    logger.info("scan_completed", **result)
    return result


def _connector_config() -> dict:
    """Configurazione dei connettori esterni, letta dai settings (mai hardcoded)."""
    return {
        "hibp": {"api_key": settings.hibp_api_key,
                 "base_url": "https://haveibeenpwned.com/api/v3"},
        "credential_exposure": {"api_key": settings.credential_exposure_api_key,
                                "base_url": settings.credential_exposure_url,
                                # In modalita' simulata il connettore produce dati
                                # sintetici: senza, l'area dark web resterebbe vuota
                                # nella dimostrazione.
                                "mock_enabled": settings.scan_mock_mode},
        "spiderfoot": {"base_url": settings.spiderfoot_url},
        "ransomware_live": {"base_url": settings.ransomware_live_url},
        "kev": {"url": settings.kev_feed_url},
        "epss": {"base_url": settings.epss_api_url},
        "cache_dir": "/tmp/defenix-feeds",
    }


@celery_app.task(name="defenix.feeds.refresh")
def refresh_feeds_task() -> dict:
    """Aggiorna la cache locale di CISA KEV. EPSS viene interrogato su richiesta."""
    from pathlib import Path

    from adapters.vulnintel.feeds import FeedCache, fetch_kev

    if settings.scan_mock_mode:
        return {"status": "skipped", "reason": "mock mode attivo: nessuna chiamata esterna"}
    try:
        cache = FeedCache(Path("/tmp/defenix-feeds"))
        entries = fetch_kev(settings.kev_feed_url, cache)
    except Exception as exc:  # noqa: BLE001
        logger.error("kev_refresh_failed", error=str(exc))
        return {"status": "failed", "error": type(exc).__name__}
    logger.info("kev_refreshed", entries=len(entries))
    return {"status": "ok", "kev_entries": len(entries)}


@celery_app.task(name="defenix.retention.apply")
def apply_retention_task() -> dict:
    """Applica le policy di conservazione: cancellazione sicura delle evidenze scadute."""
    from sqlalchemy import delete, select

    from app.models.organization import RetentionPolicy
    from app.models.scanning import Evidence

    removed = 0
    with session_scope() as db:
        policies = db.execute(select(RetentionPolicy)).scalars().all()
        for policy in policies:
            if policy.data_category != "evidence":
                continue
            cutoff = datetime.now(UTC) - timedelta(days=policy.retention_days)
            result = db.execute(
                delete(Evidence).where(Evidence.tenant_id == policy.tenant_id,
                                       Evidence.observed_at < cutoff))
            removed += result.rowcount or 0
            policy.last_applied_at = datetime.now(UTC)
    logger.info("retention_applied", removed_evidences=removed)
    return {"status": "ok", "removed_evidences": removed}
