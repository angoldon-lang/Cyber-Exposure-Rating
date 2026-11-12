#!/usr/bin/env bash
# Dice cosa sta davvero girando: versioni, schede nel bundle, binari.
#
# Era inline nel Makefile e aveva due difetti della stessa famiglia: diceva
# «da ricostruire» in situazioni in cui non c'era niente da ricostruire, e chi
# lo leggeva ricostruiva per niente.
#
#   * il controllo sul Cache-Control non distingueva «nginx non manda
#     l'header» da «non ho raggiunto il server»: `curl -sfI` tace su
#     qualunque guasto, e il ramo di fallimento stampava la prima delle due;
#   * le schede si cercavano nel bundle per una frase scritta a mano qui.
#     «Uno strumento non configurato non falsa il rating» non esiste piu' nell'interfaccia da qualche
#     versione, quindi la scheda Strumenti risultava ASSENTE sempre, e
#     nessuna ricostruzione poteva farla comparire.
#
# Le frasi da cercare stanno ora in un posto solo, qui sotto, e un test
# verifica che esistano ancora nel codice del frontend: se qualcuno riscrive
# un titolo, fallisce il test invece di questo comando.
set -uo pipefail
cd "$(dirname "$0")/.."
COMPOSE=${COMPOSE:-docker compose}

# scheda|frase da cercare nel bundle
SCHEDE=(
  "Perimetro di rete (Gestione azienda)|Perimetro di rete"
  "Strumenti (Personalizzazione)|Uno strumento non configurato non falsa il rating"
)

# La porta la scrive chi installa in `.env`, e make non esporta quel file:
# leggerla qui evita di interrogare la 8080 quando il frontend sta altrove e
# di concludere che l'immagine sia vecchia.
porta=$(grep -E '^FRONTEND_PORT=' .env 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
porta=${porta:-8080}

atteso=$(cat VERSION 2>/dev/null || echo sconosciuta)

echo "== versione attesa (questo repository) =="
printf "  VERSION                %s\n" "$atteso"
echo
echo "== versione che sta girando =="
printf "  api                    %s\n" \
  "$($COMPOSE exec -T api sh -c 'cat /srv/VERSION 2>/dev/null' 2>/dev/null | tr -d '\r\n' || true)"
printf "  worker                 %s\n" \
  "$($COMPOSE exec -T worker sh -c 'cat /srv/VERSION 2>/dev/null' 2>/dev/null | tr -d '\r\n' || true)"
if $COMPOSE exec -T frontend sh -c "grep -ql '$atteso' /usr/share/nginx/html/assets/*.js" 2>/dev/null; then
  printf "  frontend (nel bundle)  %s\n" "$atteso"
else
  printf "  frontend (nel bundle)  diversa da %s -> ricostruire\n" "$atteso"
fi

cache_di() {
  curl -sS -I --max-time 5 "http://localhost:${porta}$1" 2>&1
}

echo
echo "== interfaccia: come viene servita (porta ${porta}) =="
radice=$(cache_di "/")
if [ -z "$radice" ] || ! printf '%s' "$radice" | grep -qi "^HTTP/"; then
  echo "  NON RAGGIUNTO su localhost:${porta}: non si puo' dire niente sulla cache."
  echo "    ${radice:-nessuna risposta}"
  echo "    Il frontend e' avviato? La porta in .env e' questa?  ->  make doctor"
else
  su_radice=$(printf '%s' "$radice" | grep -i "^cache-control" | tr -d '\r')
  su_index=$(cache_di "/index.html" | grep -i "^cache-control" | tr -d '\r')
  printf "  /             %s\n" "${su_radice:-nessun Cache-Control}"
  printf "  /index.html   %s\n" "${su_index:-nessun Cache-Control}"
  if [ -z "$su_radice" ] && [ -n "$su_index" ]; then
    echo "  La regola vale per /index.html ma non per /, che e' l'indirizzo"
    echo "  che apre il browser: il blocco \`location = /index.html\` non viene"
    echo "  applicato dopo il try_files. E' da correggere in frontend/nginx.conf,"
    echo "  non ricostruendo l'immagine."
  elif [ -z "$su_radice" ]; then
    echo "  NESSUN Cache-Control -> immagine del frontend non aggiornata"
  fi
fi

echo
echo "== interfaccia: le schede sono nel bundle? =="
for voce in "${SCHEDE[@]}"; do
  nome=${voce%%|*}; frase=${voce#*|}
  if $COMPOSE exec -T frontend sh -c "grep -qlF '$frase' /usr/share/nginx/html/assets/*.js" 2>/dev/null; then
    printf "  %-36s presente\n" "$nome:"
  else
    printf "  %-36s ASSENTE -> ricostruire il frontend\n" "$nome:"
  fi
done

echo
echo "== worker: quale binario risponde =="
$COMPOSE exec -T worker sh -c \
  'for t in subfinder httpx nuclei testssl.sh amass; do printf "  %-12s %s\n" "$t" "$(command -v $t || echo ASSENTE)"; done' \
  2>/dev/null || echo "  (il worker non risponde: make worker-start)"

echo
echo "Se una riga dice ASSENTE o manca il Cache-Control: make aggiorna"
echo "Se una riga dice NON RAGGIUNTO: il servizio non e' avviato, non e' vecchio."
