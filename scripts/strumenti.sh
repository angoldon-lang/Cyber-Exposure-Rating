#!/usr/bin/env bash
# Esegue la verifica di prontezza degli strumenti nel worker, e quando non
# riesce dice il motivo giusto.
#
# Il target chiamava direttamente `compose exec` e, su qualunque uscita diversa
# da zero, stampava «il worker non risponde». Ma il modo piu' probabile di
# fallire e' un altro: il worker risponde benissimo e gira su un'immagine
# precedente, che quel sottocomando non lo conosce. Mandare a riavviare un
# servizio sano, quando cio' che serve e' ricostruirlo, fa perdere il
# pomeriggio a chi ha appena aggiornato il codice.
set -uo pipefail
cd "$(dirname "$0")/.."
COMPOSE=${COMPOSE:-docker compose}

# Il container deve esistere e stare in piedi. `ps -q` e' vuoto in entrambi i
# casi, e sono lo stesso problema per chi legge: il worker non c'e'.
if [ -z "$($COMPOSE ps -q worker 2>/dev/null)" ]; then
  echo "Il servizio worker non e' in esecuzione."
  echo "  make worker-start     lo costruisce, lo avvia e verifica che risponda"
  exit 1
fi

uscita=0
esito=$($COMPOSE exec -T worker python -m app.cli strumenti "$@" 2>&1) || uscita=$?
echo "$esito"
[ "$uscita" -eq 0 ] && exit 0

# argparse rifiuta un sottocomando che non conosce con «invalid choice» e uscita
# 2: non e' un guasto, e' una versione.
if printf '%s' "$esito" | grep -q "invalid choice: 'strumenti'"; then
  attesa=$(cat VERSION 2>/dev/null || echo sconosciuta)
  attiva=$($COMPOSE exec -T worker sh -c 'cat /srv/VERSION 2>/dev/null' 2>/dev/null \
           | tr -d '\r\n' || true)
  echo
  echo "Il worker risponde, ma gira su una versione che non ha questo comando."
  echo "  repository:  ${attesa}"
  echo "  worker:      ${attiva:-sconosciuta}"
  echo
  echo "L'immagine del worker contiene una copia del codice: una modifica al"
  echo "repository non la raggiunge finche' non viene ricostruita."
  echo "  make aggiorna         ricostruisce tutto e applica le migrazioni"
  echo "  make worker-start     ricostruisce e riavvia solo il worker"
  exit 1
fi

echo
echo "Il comando non e' riuscito. L'output qui sopra dice perche'."
echo "Se non dice niente di utile:  make doctor"
exit "$uscita"
