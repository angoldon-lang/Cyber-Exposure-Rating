#!/usr/bin/env bash
# Raccoglie in un colpo solo lo stato dello stack: serve quando "non si apre"
# senza un errore evidente. Non modifica nulla.
set -uo pipefail
cd "$(dirname "$0")/.."
COMPOSE=${COMPOSE:-docker compose}

riga() { printf '\n===== %s =====\n' "$1"; }

riga "porte configurate in .env"
grep -E '^(API_PORT|FRONTEND_PORT|KEYCLOAK_PORT)=' .env 2>/dev/null || echo "(.env assente)"

riga "stato dei container"
$COMPOSE ps

riga "porte effettivamente pubblicate"
$COMPOSE port frontend 8080 2>&1 || echo "(il container frontend non pubblica la 8080)"
$COMPOSE port api 8000 2>&1 || echo "(il container api non pubblica la 8000)"

riga "il frontend risponde DENTRO il container?"
$COMPOSE exec -T frontend wget -qO- http://localhost:8080/healthz 2>&1 \
  || echo "(nessuna risposta: nginx non serve, vedere i log qui sotto)"

riga "l'API vede worker attivi? (campo workers)"
$COMPOSE exec -T api python -c \
  "import json,urllib.request;d=json.load(urllib.request.urlopen('http://localhost:8000/api/v1/health'));print('  worker attivi:',d['workers'],' stato:',d['status'])" 2>&1 \
  || echo "(health non interrogabile)"

riga "l'API risponde DENTRO il container?"
$COMPOSE exec -T api python -c \
  "import urllib.request;print(urllib.request.urlopen('http://localhost:8000/api/v1/health/live',timeout=5).read().decode())" 2>&1 \
  || echo "(nessuna risposta dall'API)"

riga "il frontend raggiunge l'API? (proxy /api/)"
$COMPOSE exec -T frontend wget -qO- http://api:8000/api/v1/health/live 2>&1 \
  || echo "(il frontend non raggiunge l'API: problema di rete fra i container)"

riga "ultime scansioni registrate"
$COMPOSE exec -T api python - < scripts/diagnostica_scansioni.py 2>&1 \
  || echo "(impossibile interrogare il database)"

riga "il worker e' attivo e vede le code?"
$COMPOSE exec -T worker celery -A app.workers.celery_app.celery_app inspect ping 2>&1 \
  || echo "(il worker non risponde: senza, le scansioni restano in coda)"

riga "task registrati nel worker"
$COMPOSE exec -T worker celery -A app.workers.celery_app.celery_app inspect registered 2>&1 \
  | head -12 || echo "(nessun task registrato)"

riga "messaggi in attesa nelle code Redis"
$COMPOSE exec -T redis redis-cli -n 1 llen scans 2>&1 | sed 's/^/  scans: /'
$COMPOSE exec -T redis redis-cli -n 1 llen maintenance 2>&1 | sed 's/^/  maintenance: /'

riga "ultime 25 righe di log: worker"
$COMPOSE logs --tail=25 --no-color worker 2>&1

riga "ultime 25 righe di log: frontend"
$COMPOSE logs --tail=25 --no-color frontend 2>&1

riga "ultime 25 righe di log: api"
$COMPOSE logs --tail=25 --no-color api 2>&1

riga "prova dall'host"
porta=$(grep -E '^FRONTEND_PORT=' .env 2>/dev/null | cut -d= -f2)
porta=${porta:-8080}
echo "curl http://localhost:${porta}/healthz"
curl -sS -m 5 -o /dev/null -w "  HTTP %{http_code}\n" "http://localhost:${porta}/healthz" 2>&1 \
  || echo "  nessuna risposta dall'host sulla porta ${porta}"

printf '\n===== fine =====\n'
