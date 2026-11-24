#!/usr/bin/env bash
# Rimette in `.env` i segreti leggendoli dai contenitori in esecuzione.
#
# Serve quando `.env` si e' svuotato o ha perso una riga mentre lo stack gira.
# La via che il Makefile suggeriva -- `make env FORCE=1` -- in quella
# situazione e' la peggiore possibile: rigenera POSTGRES_PASSWORD, e il volume
# del database e' stato inizializzato con quella vecchia. Dopo, Postgres
# rifiuta la connessione e l'unico rimedio documentato e' `down -v`, cioe'
# cancellare i dati.
#
# I segreti sono ancora nell'ambiente dei contenitori accesi: finche' girano,
# non sono perduti.
#
# Si usa `docker` e non `docker compose` di proposito: compose interpola
# l'intero file e si ferma su `${POSTGRES_PASSWORD:?...}`, che e' esattamente
# la variabile che manca. Il contenitore si trova per etichetta.
set -uo pipefail
cd "$(dirname "$0")/.."

if ! command -v docker > /dev/null; then
  echo "docker non disponibile: senza non si possono leggere i contenitori."
  exit 1
fi

# variabile|servizio da cui leggerla
SEGRETI=(
  "POSTGRES_PASSWORD|postgres"
  "JWT_SECRET_KEY|api"
  "EVIDENCE_ENCRYPTION_KEY|api"
)

contenitore_di() {
  docker ps -q --filter "label=com.docker.compose.service=$1" | head -1
}

valore_in_env() {
  grep -E "^$1=.+" .env 2>/dev/null | tail -1 | cut -d= -f2-
}

if [ ! -f .env ]; then
  echo "Manca .env del tutto: qui si puo' solo ricostruirlo."
  echo "  make env           lo crea con segreti NUOVI"
  echo
  echo "Attenzione: con un volume postgres esistente, segreti nuovi non"
  echo "aprono quel database. Se i contenitori girano ancora, fermati e"
  echo "chiedi aiuto: i valori si possono leggere e rimettere a mano."
  exit 1
fi

cp .env ".env.prima-del-recupero"
echo "Copia di sicurezza: .env.prima-del-recupero"
echo

recuperati=0
mancanti=()
for voce in "${SEGRETI[@]}"; do
  nome=${voce%%|*}; servizio=${voce#*|}
  if [ -n "$(valore_in_env "$nome")" ]; then
    printf "  %-28s gia' presente in .env\n" "$nome"
    continue
  fi
  cid=$(contenitore_di "$servizio")
  if [ -z "$cid" ]; then
    printf "  %-28s il contenitore '%s' non e' in esecuzione\n" "$nome" "$servizio"
    mancanti+=("$nome")
    continue
  fi
  valore=$(docker exec "$cid" printenv "$nome" 2>/dev/null | tr -d '\r\n')
  if [ -z "$valore" ]; then
    printf "  %-28s non presente nell'ambiente di '%s'\n" "$nome" "$servizio"
    mancanti+=("$nome")
    continue
  fi
  # La riga esiste vuota: si sostituisce. Non esiste: si aggiunge.
  if grep -qE "^$nome=" .env; then
    # Il valore puo' contenere qualunque carattere: lo si scrive con awk,
    # che non lo interpreta, invece che con sed.
    awk -v n="$nome" -v v="$valore" \
      'BEGIN{FS=OFS="="} $1==n {print n "=" v; next} {print}' .env > .env.nuovo \
      && mv .env.nuovo .env
  else
    printf '%s=%s\n' "$nome" "$valore" >> .env
  fi
  # Il valore non viene stampato: finirebbe nei log del terminale.
  printf "  %-28s RECUPERATO dal contenitore '%s'\n" "$nome" "$servizio"
  recuperati=$((recuperati + 1))
done

chmod 600 .env 2>/dev/null || true
echo
if [ "$recuperati" -gt 0 ]; then
  echo "$recuperati segreti rimessi in .env. Ora: make up"
fi
if [ "${#mancanti[@]}" -gt 0 ]; then
  echo "Non recuperabili: ${mancanti[*]}"
  echo "  JWT_SECRET_KEY si puo' rigenerare senza perdere dati: invalida solo"
  echo "  le sessioni aperte (si rientra con le stesse credenziali) e rende"
  echo "  illeggibili le chiavi salvate da Personalizzazione -> Strumenti,"
  echo "  che si reimpostano."
  echo "  POSTGRES_PASSWORD NO: e' quella con cui il volume e' stato creato."
fi
