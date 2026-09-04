#!/usr/bin/env bash
# Corregge proprietario e permessi dei volumi condivisi fra API e worker.
#
# Non si puo' fare dentro il container API: quello gira con `read_only: true` e
# `cap_drop: ALL`, quindi nemmeno root possiede CAP_CHOWN e `chgrp` fallisce con
# "Operation not permitted". Serve un container separato, privo di quei vincoli,
# con i volumi montati.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=${COMPOSE:-docker compose}

# I nomi dei volumi dipendono dal nome del progetto: si ricavano dal container
# invece di ricostruirli a mano.
contenitore=$($COMPOSE ps -q api 2>/dev/null | head -1)
if [ -z "$contenitore" ]; then
  echo "Il servizio api non e' in esecuzione: avviarlo prima (make up)." >&2
  exit 1
fi

mappa=$(docker inspect "$contenitore" --format \
  '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{.Destination}}{{"\n"}}{{end}}{{end}}')

if [ -z "$mappa" ]; then
  echo "Nessun volume montato sul servizio api." >&2
  exit 1
fi

echo "Volumi da correggere:"
echo "$mappa" | sed 's/^/  /'

argomenti=()
comandi=""
indice=0
while read -r nome destinazione; do
  [ -z "$nome" ] && continue
  punto="/riparazione/$indice"
  argomenti+=(-v "${nome}:${punto}")
  # 10000 e' il gruppo condiviso fra le due immagini; 2775 lascia la scrittura
  # al gruppo e, con il setgid, la fa ereditare ai file creati dopo.
  comandi="${comandi} chgrp -R 10000 ${punto}; chmod -R 2775 ${punto};"
  indice=$((indice + 1))
done <<< "$mappa"

docker run --rm "${argomenti[@]}" alpine:3.20 sh -c "set -e; ${comandi} echo OK"

echo
echo "Permessi corretti. Verifica dal worker:"
$COMPOSE exec -T worker sh -c 'ls -ld /var/lib/defenix/evidence && id' 2>/dev/null \
  || echo "(worker non in esecuzione: verranno applicati al prossimo avvio)"
