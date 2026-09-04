# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Worker di scansione Defenix.
# Contiene gli strumenti open source. Gira come utente non root, senza
# privilegi aggiuntivi e con limiti di CPU/memoria imposti dal compose.
# ---------------------------------------------------------------------------
FROM golang:1.23.4-bookworm AS tools

ENV CGO_ENABLED=0 GOBIN=/out
RUN mkdir -p /out \
    && go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 \
    && go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 \
    && go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.1 \
    && go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.7

FROM python:3.11.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# `dnsutils`, `bind9-host` e `openssl` servono a testssl.sh; `libpcap` a naabu.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bsdmainutils dnsutils bind9-host openssl procps libpcap0.8 \
        ca-certificates git curl libpq5 \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh: usato come strumento esterno invocato via subprocess (GPL-2.0),
# non linkato nel prodotto e non ridistribuito in forma modificata.
ARG TESTSSL_VERSION=3.2rc3
RUN git clone --depth 1 --branch ${TESTSSL_VERSION} \
        https://github.com/testssl/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

COPY --from=tools /out/subfinder /out/httpx /out/naabu /out/nuclei /usr/local/bin/

WORKDIR /srv
COPY backend/requirements.txt /srv/backend/requirements.txt
RUN pip install --no-cache-dir -r /srv/backend/requirements.txt \
    && pip install --no-cache-dir checkdmarc==5.7.4 dnstwist==20240812

RUN groupadd --system --gid 10002 scanner \
    && useradd --system --uid 10002 --gid scanner --home /srv --shell /usr/sbin/nologin scanner \
    && mkdir -p /var/lib/defenix/evidence /tmp/defenix-feeds \
    && chown -R scanner:scanner /var/lib/defenix /tmp/defenix-feeds /srv

COPY --chown=scanner:scanner backend/ /srv/backend/
COPY --chown=scanner:scanner adapters/ /srv/adapters/
COPY --chown=scanner:scanner reporting/ /srv/reporting/
COPY --chown=scanner:scanner config/ /srv/config/

ENV PYTHONPATH=/srv:/srv/backend
USER scanner

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD celery -A app.workers.celery_app.celery_app inspect ping -d celery@$HOSTNAME || exit 1

CMD ["celery", "-A", "app.workers.celery_app.celery_app", "worker", \
     "--loglevel=info", "--queues=scans,maintenance", "--concurrency=2", \
     "--max-tasks-per-child=20"]
