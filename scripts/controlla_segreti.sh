#!/usr/bin/env bash
# Verifica che `.env` contenga i due segreti senza cui lo stack non parte, e
# proponga il rimedio giusto -- che dipende da una cosa sola: se esiste gia' un
# volume del database.
#
# Il messaggio precedente diceva «mancano POSTGRES_PASSWORD e/o
# JWT_SECRET_KEY», cioe' non aveva guardato quale, e proponeva
# `make env FORCE=1`. Quel comando rigenera POSTGRES_PASSWORD, e il volume e'
# stato inizializzato con quella attuale: dopo, Postgres rifiuta la connessione
# e l'unica via documentata era cancellare i dati. Era il consiglio peggiore
# possibile, dato nel momento peggiore.
set -uo pipefail
cd "$(dirname "$0")/.."

mancanti=()
for v in POSTGRES_PASSWORD JWT_SECRET_KEY; do
  if ! grep -qE "^${v}=" .env 2>/dev/null; then
    mancanti+=("${v} (riga assente)")
  elif ! grep -qE "^${v}=.+" .env 2>/dev/null; then
    mancanti+=("${v} (riga presente ma vuota)")
  fi
done

[ "${#mancanti[@]}" -eq 0 ] && exit 0

echo "In .env manca:"
for m in "${mancanti[@]}"; do echo "  - ${m}"; done
echo

volume=""
if command -v docker > /dev/null; then
  volume=$(docker volume ls -q 2>/dev/null | grep -E -- '-postgres-data$' | head -1)
fi

if [ -n "$volume" ]; then
  echo "  ATTENZIONE: il volume del database esiste ($volume)."
  echo "  NON eseguire \`make env FORCE=1\`: rigenererebbe POSTGRES_PASSWORD, e"
  echo "  quel volume e' stato creato con quella attuale. Postgres non si"
  echo "  aprirebbe piu', e l'unico rimedio sarebbe cancellare i dati."
  echo
  echo "  make env-recupera    rilegge i segreti dai contenitori ancora accesi"
  echo "                       (finche' girano, non sono perduti)"
else
  echo "  Nessun volume del database da aprire: rigenerarli e' senza rischi."
  echo "  make env-recupera    li rilegge dai contenitori, se ce ne sono"
  echo "  make env FORCE=1     li rigenera"
fi
exit 1
