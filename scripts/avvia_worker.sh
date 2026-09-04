#!/usr/bin/env bash
# Costruisce, avvia e verifica il servizio worker, che e' l'unico a poter
# eseguire scansioni reali. Riporta subito se non ha funzionato, invece di
# lasciare le scansioni in coda in silenzio.
set -uo pipefail
cd "$(dirname "$0")/.."
COMPOSE=${COMPOSE:-docker compose}

echo "== 1/4 costruzione dell'immagine =="
if ! $COMPOSE build worker; then
  echo
  echo "La costruzione e' fallita. L'output qui sopra dice dove."
  exit 1
fi

echo
echo "== 2/4 avvio =="
$COMPOSE up -d worker || exit 1

echo
echo "== 3/4 attesa della registrazione (fino a 60s) =="
for _ in $(seq 1 30); do
  if $COMPOSE exec -T worker celery -A app.workers.celery_app.celery_app \
       inspect ping >/dev/null 2>&1; then
    echo "il worker risponde."
    break
  fi
  sleep 2
done

echo
echo "== 4/4 stato =="
$COMPOSE ps worker
attivi=$($COMPOSE exec -T api python -c \
  "import json,urllib.request;print(json.load(urllib.request.urlopen('http://localhost:8000/api/v1/health'))['workers'])" \
  2>/dev/null || echo 0)
echo "worker visti dall'API: ${attivi}"

if [ "${attivi:-0}" = "0" ]; then
  echo
  echo "Il worker non risulta attivo. Ultime righe di log:"
  $COMPOSE logs --tail=30 --no-color worker
  exit 1
fi

echo
echo "Pronto: le scansioni avviate dall'interfaccia verranno eseguite davvero."
echo "Con SCAN_MOCK_MODE=false useranno gli strumenti reali sui domini autorizzati."
