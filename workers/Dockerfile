# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Worker di scansione Defenix.
# Contiene gli strumenti open source. Gira come utente non root, senza
# privilegi aggiuntivi e con limiti di CPU/memoria imposti dal compose.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Strumenti ProjectDiscovery: binari ufficiali gia' compilati.
#
# La compilazione da sorgente con `go install` richiedeva parecchi GB di RAM
# (nuclei ha un albero di dipendenze molto ampio) e veniva terminata dal kernel
# nella VM di Docker Desktop, con `exit code 1` e nessun messaggio. Scaricare i
# binari pubblicati e' anche molto piu' rapido e non dipende da proxy.golang.org.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS tools

# Fornito automaticamente da BuildKit: amd64, arm64, ...
ARG TARGETARCH
ARG SUBFINDER_VERSION=2.6.6
ARG HTTPX_VERSION=1.6.9
ARG NAABU_VERSION=2.3.1
ARG NUCLEI_VERSION=3.3.7
# naabu non pubblica il file dei checksum: l'impronta e' fissata qui, cosi' la
# verifica resta obbligatoria per tutti e quattro gli strumenti.
ARG NAABU_SHA256=834c01c2cdd02efdddb78afee594d1782e704ea6aa7db87e613cf721e11db608

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# naabu non pubblica binari linux/arm64 (usa libpcap tramite CGO): su quella
# architettura viene omesso. L'adapter lo segnala come `skipped`, riduce la
# copertura dichiarata e non blocca la scansione; il port scan e' comunque
# ammesso solo nel profilo Verified Extended Check.
RUN set -eu; \
    arch="${TARGETARCH:-amd64}"; \
    mkdir -p /out /tmp/dl; \
    scarica() { \
        nome="$1"; versione="$2"; atteso="${3:-}"; \
        base="https://github.com/projectdiscovery/${nome}/releases/download/v${versione}"; \
        archivio="${nome}_${versione}_linux_${arch}.zip"; \
        curl -fsSL "${base}/${archivio}" -o "/tmp/dl/${archivio}"; \
        if [ -n "${atteso}" ]; then \
            echo "${atteso}  ${archivio}" > /tmp/dl/atteso.txt; \
        else \
            curl -fsSL "${base}/${nome}_${versione}_checksums.txt" -o /tmp/dl/tutti.txt; \
            grep " ${archivio}$" /tmp/dl/tutti.txt > /tmp/dl/atteso.txt; \
        fi; \
        (cd /tmp/dl && sha256sum -c atteso.txt); \
        unzip -q -o "/tmp/dl/${archivio}" "${nome}" -d /out; \
        chmod +x "/out/${nome}"; \
        "/out/${nome}" -version >/dev/null 2>&1 || true; \
    }; \
    scarica subfinder "${SUBFINDER_VERSION}"; \
    scarica httpx "${HTTPX_VERSION}"; \
    scarica nuclei "${NUCLEI_VERSION}"; \
    if [ "${arch}" = "amd64" ]; then \
        scarica naabu "${NAABU_VERSION}" "${NAABU_SHA256}"; \
    else \
        echo "naabu non disponibile per linux/${arch}: omesso"; \
    fi; \
    rm -rf /tmp/dl

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
# Il tag upstream ha il prefisso `v` (`v3.2.4`, non `3.2.4`): senza, il clone
# fallisce con "Remote branch not found". `--branch` accetta anche i tag.
ARG TESTSSL_VERSION=v3.2.4
RUN git clone --depth 1 --branch ${TESTSSL_VERSION} \
        https://github.com/testssl/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
    && /opt/testssl/testssl.sh --version >/dev/null

# Copia dell'intera cartella: su arm64 naabu non e' presente e un COPY che
# lo elencasse esplicitamente farebbe fallire la build.
COPY --from=tools /out/ /usr/local/bin/

# I template di Nuclei non sono nel binario: senza, ogni esecuzione termina
# con «Could not run nuclei: no templates provided for scan». Vanno messi
# nell'immagine, perche' il worker gira senza rete verso GitHub garantita e
# con la cartella home non scrivibile: scaricarli alla prima esecuzione non
# funziona. La versione e' fissata come per gli altri strumenti.
ARG NUCLEI_TEMPLATES_VERSION=v10.1.5
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN git clone --depth 1 --branch ${NUCLEI_TEMPLATES_VERSION}         https://github.com/projectdiscovery/nuclei-templates.git ${NUCLEI_TEMPLATES_DIR}     && rm -rf ${NUCLEI_TEMPLATES_DIR}/.git

WORKDIR /srv
COPY backend/requirements.txt /srv/backend/requirements.txt
RUN pip install --no-cache-dir -r /srv/backend/requirements.txt \
    && pip install --no-cache-dir checkdmarc==5.7.4 dnstwist==20240812

# Stesso gruppo condiviso dell'immagine API (gid 10000): il worker scrive le
# evidenze grezze che l'API deve poter rileggere. Utenti distinti, gruppo comune.
RUN groupadd --system --gid 10000 defenixdata \
    && groupadd --system --gid 10002 scanner \
    && useradd --system --uid 10002 --gid scanner --groups defenixdata \
       --home /srv --shell /usr/sbin/nologin scanner \
    && mkdir -p /var/lib/defenix/evidence /tmp/defenix-feeds \
    && chown -R scanner:defenixdata /var/lib/defenix \
    && chmod -R 2775 /var/lib/defenix \
    && chown -R scanner:scanner /tmp/defenix-feeds /srv

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
