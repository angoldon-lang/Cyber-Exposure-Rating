"""Applicazione FastAPI Defenix Exposure Rating."""
from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.routers import admin, auth, companies, dashboard, findings, health, reports, scans
from app.core.config import settings
from app.core.logging import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

DESCRIPTION = """
**Defenix Exposure Rating** - External Cyber Exposure Rating.

Valutazione della sicurezza osservabile dall'esterno e dei rischi a cui
l'organizzazione potrebbe essere esposta.

> Non costituisce un penetration test, un vulnerability assessment completo
> ne' una certificazione di sicurezza.

Principio architetturale: **gli strumenti raccolgono le evidenze, il motore
deterministico calcola il rating, l'intelligenza artificiale interpreta e
spiega i risultati.** L'AI non modifica mai il punteggio.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("application_startup", version=settings.app_version,
                environment=settings.environment, auth_mode=settings.auth_mode,
                mock_mode=settings.scan_mock_mode)
    for path in (settings.evidence_storage_path, settings.report_storage_path):
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("storage_path_unavailable", path=str(path), error=str(exc))
    if settings.is_production and settings.jwt_secret_key.startswith("CHANGE-ME"):
        raise RuntimeError(
            "JWT_SECRET_KEY non configurato: impossibile avviare in produzione con il valore di default")
    yield
    logger.info("application_shutdown")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=DESCRIPTION,
    openapi_url=f"{settings.api_prefix}/openapi.json",
    docs_url=f"{settings.api_prefix}/docs",
    redoc_url=f"{settings.api_prefix}/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept-Language"],
    max_age=600,
)
if settings.is_production:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*.defenix.it", "defenix.it"])


@app.middleware("http")
async def security_headers(request: Request, call_next):  # noqa: ANN001, ANN201
    """Header di sicurezza e correlazione delle richieste."""
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    started = time.monotonic()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # L'API risponde solo JSON e file: la CSP puo' essere massimamente restrittiva.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    logger.info("http_request", method=request.method, path=request.url.path,
                status=response.status_code, request_id=request_id,
                duration_ms=round((time.monotonic() - started) * 1000, 1))
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Errori di validazione in forma serializzabile.

    Pydantic v2 inserisce l'eccezione originale in `ctx`, che non e'
    serializzabile in JSON: senza questa normalizzazione un validatore
    personalizzato che solleva `ValueError` produrrebbe un 500 invece di un 422.
    """
    detail = [
        {
            "loc": [str(part) for part in error.get("loc", ())],
            "msg": str(error.get("msg", "")),
            "type": str(error.get("type", "")),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": "Richiesta non valida", "detail": detail})


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    # Nessun dettaglio interno viene esposto al client.
    logger.error("unhandled_exception", path=request.url.path,
                 error=type(exc).__name__, message=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Errore interno del server",
                 "request_id": request.headers.get("x-request-id")})


prefix = settings.api_prefix
app.include_router(health.router, prefix=prefix)
app.include_router(auth.router, prefix=prefix)
app.include_router(companies.router, prefix=prefix)
app.include_router(scans.router, prefix=prefix)
app.include_router(findings.router, prefix=prefix)
app.include_router(dashboard.router, prefix=prefix)
app.include_router(reports.router, prefix=prefix)
app.include_router(admin.router, prefix=prefix)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": f"{settings.api_prefix}/docs",
        "scope_note": ("External Cyber Exposure Rating: valutazione della sicurezza "
                       "osservabile dall'esterno. Non e' un penetration test."),
    }
