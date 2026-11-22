# SpiderFoot, costruito da noi dal sorgente.
#
# Il progetto non pubblica un'immagine utilizzabile: `ghcr.io/smicallef/spiderfoot`
# non esiste (il registro risponde «denied»), su Docker Hub non c'e' nulla, e la
# sola immagine raggiungibile e' un fork di terzi solo amd64. Il sorgente invece
# c'e', ed e' tutto cio' che serve.
#
# PERCHE' PYTHON 3.9, e non una versione mantenuta: `requirements.txt` chiede
# `pyyaml>=5.4.1,<6`, e di pyyaml 5.4.1 esistono wheel per arm64 soltanto per
# cp38 e cp39. Da sorgente non si costruisce piu' (Cython 3 interrompe con
# «cython_sources»): misurato, non supposto. Su 3.10 e 3.11 l'installazione
# percio' fallisce, ed e' la ragione per cui non esiste un'immagine funzionante
# di questo progetto.
#
# Tutte le altre dipendenze che si compilano -- lxml, cryptography, Pillow --
# hanno wheel manylinux aarch64 per 3.9: verificate una per una. Solo quattro
# pacchetti arrivano come sorgente (ipaddr, pygexf, python-whois, python-docx) e
# sono tutti puri Python: nessun compilatore nell'immagine, costruzione in
# meno di un minuto su entrambe le architetture.
#
# LICENZA: SpiderFoot 4.0 e' GPL-2.0, non MIT come il catalogo dichiarava fino
# alla 0.18.7. Distribuirlo in un'immagine e' consentito e obbliga a rendere
# disponibile il sorgente corrispondente: qui si parte da un commit pubblico,
# non modificato e fissato per impronta, e il file LICENSE resta nell'immagine.
# La piattaforma lo interroga via HTTP come processo separato, quindi non ne e'
# un'opera derivata.

FROM python:3.9-slim-bookworm AS sorgente

# Il commit, non il tag: un tag si puo' spostare, un'impronta no. E' `v4.0`.
ARG SPIDERFOOT_COMMIT=b9c345de5b085debc7444fc10e0e26e7745df5f2

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# `fetch` di un singolo commit: non si scarica la storia, e l'impronta si
# verifica prima di usarla. Se il commit non e' quello, la costruzione muore
# qui invece di produrre un'immagine di qualcos'altro.
RUN git init -q . \
    && git remote add origin https://github.com/smicallef/spiderfoot.git \
    && git fetch -q --depth 1 origin "${SPIDERFOOT_COMMIT}" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${SPIDERFOOT_COMMIT}" \
    && rm -rf .git


FROM python:3.9-slim-bookworm AS dipendenze

COPY --from=sorgente /src/requirements.txt /tmp/requirements.txt

# `--only-binary` sui pacchetti che si compilano: se una di quelle wheel
# sparisse da PyPI, la costruzione deve fermarsi subito e dirlo, non tentare
# venti minuti di compilazione senza compilatore per poi fallire. Gli altri
# possono arrivare come sorgente: sono puri Python.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir \
         --only-binary=lxml,cryptography,PyYAML,Pillow \
         -r /tmp/requirements.txt


FROM python:3.9-slim-bookworm

# Dati, cache e log fuori dalla cartella di installazione: vanno su un volume.
ENV SPIDERFOOT_DATA=/var/lib/spiderfoot \
    SPIDERFOOT_LOGS=/var/lib/spiderfoot/log \
    SPIDERFOOT_CACHE=/var/lib/spiderfoot/cache \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN groupadd -r spiderfoot && useradd -r -g spiderfoot -d /home/spiderfoot spiderfoot \
    && mkdir -p /home/spiderfoot "$SPIDERFOOT_DATA" "$SPIDERFOOT_LOGS" "$SPIDERFOOT_CACHE" \
    && chown -R spiderfoot:spiderfoot /home/spiderfoot /var/lib/spiderfoot

WORKDIR /home/spiderfoot
COPY --from=sorgente --chown=spiderfoot:spiderfoot /src/ /home/spiderfoot/
COPY --from=dipendenze /opt/venv /opt/venv

USER spiderfoot

# Nessuna porta pubblicata nel compose: ci parla solo il worker, sulla rete
# interna. SpiderFoot senza file `passwd` non chiede autenticazione, e un
# motore di scansione raggiungibile dalla rete non va esposto.
EXPOSE 5001

# `/ping` e' l'endpoint che interroga anche il nostro adapter: se risponde,
# lo strumento e' utilizzabile.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys;\
sys.exit(0 if 'SUCCESS' in urllib.request.urlopen('http://127.0.0.1:5001/ping',timeout=4).read().decode() else 1)"]

ENTRYPOINT ["python"]
CMD ["sf.py", "-l", "0.0.0.0:5001"]
