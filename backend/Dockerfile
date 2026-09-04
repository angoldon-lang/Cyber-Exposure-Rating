# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# API Defenix Exposure Rating.
# Nel container API NON viene installato alcuno strumento di scansione: i tool
# girano esclusivamente nei worker isolati.
# ---------------------------------------------------------------------------
FROM python:3.11.11-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dipendenze di sistema per WeasyPrint (generazione PDF) e psycopg.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfribidi0 \
        libcairo2 libgdk-pixbuf-2.0-0 libffi8 shared-mime-info \
        fonts-dejavu-core libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY backend/requirements.txt /srv/backend/requirements.txt
RUN pip install --no-cache-dir -r /srv/backend/requirements.txt

# Utente non privilegiato.
RUN groupadd --system --gid 10001 defenix \
    && useradd --system --uid 10001 --gid defenix --home /srv --shell /usr/sbin/nologin defenix \
    && mkdir -p /var/lib/defenix/evidence /var/lib/defenix/reports \
    && chown -R defenix:defenix /var/lib/defenix /srv

COPY --chown=defenix:defenix backend/ /srv/backend/
COPY --chown=defenix:defenix adapters/ /srv/adapters/
COPY --chown=defenix:defenix reporting/ /srv/reporting/
COPY --chown=defenix:defenix config/ /srv/config/

ENV PYTHONPATH=/srv:/srv/backend
USER defenix
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/v1/health/live || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
