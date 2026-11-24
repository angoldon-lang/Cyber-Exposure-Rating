#!/usr/bin/env python3
"""Aggiunge a `.env` le variabili comparse in `.env.example`, senza toccare
i valori che ci sono.

Un `.env` nasce come copia di `.env.example` e poi non cambia piu'. Ogni
variabile nuova -- e in queste settimane ne sono comparse diverse:
COMPOSE_PROFILES, THEHARVESTER_URL -- resta fuori dal file di chi ha
installato prima, e nessuno lo dice. Lo strumento risulta non configurato,
si corregge il file, non succede niente, e la causa e' che la riga non c'e'
affatto.

`make env FORCE=1` le aggiungerebbe tutte, ma rigenerando i segreti: con un
volume postgres esistente significa non aprire piu' quel database. Qui si
aggiunge soltanto, non si sostituisce nulla.

Uso:  python3 scripts/integra_env.py [--dry-run] [--env .env]
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

RADICE = Path(__file__).resolve().parents[1]
ASSEGNAZIONE = re.compile(r"^(?P<chiave>[A-Z][A-Z0-9_]*)=(?P<valore>.*)$")

# Variabili che NON si aggiungono mai da qui: sono segreti, e una riga vuota
# aggiunta in coda a `.env` farebbe sembrare configurato cio' che non lo e',
# oppure -- peggio -- sovrascriverebbe il valore in vigore se il file ne
# avesse gia' uno piu' in alto.
SEGRETI = frozenset({"POSTGRES_PASSWORD", "JWT_SECRET_KEY", "KEYCLOAK_ADMIN_PASSWORD"})


def _chiavi(testo: str) -> list[str]:
    return [m["chiave"] for riga in testo.splitlines()
            if (m := ASSEGNAZIONE.match(riga))]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=RADICE / ".env")
    parser.add_argument("--example", type=Path, default=RADICE / ".env.example")
    parser.add_argument("--dry-run", action="store_true",
                        help="elenca cosa aggiungerebbe, senza scrivere")
    args = parser.parse_args()

    if not args.env.is_file():
        print(f"{args.env} non esiste: qui non c'e' niente da integrare.\n"
              "  make env    lo crea", file=sys.stderr)
        return 1

    esempio = args.example.read_text(encoding="utf-8")
    attuale = args.env.read_text(encoding="utf-8")
    presenti = set(_chiavi(attuale))

    # Si copiano le righe dell'esempio con il loro commento, che e' la sola
    # documentazione che quelle variabili hanno.
    da_aggiungere: list[str] = []
    commento: list[str] = []
    nomi: list[str] = []
    for riga in esempio.splitlines():
        trovata = ASSEGNAZIONE.match(riga)
        if trovata is None:
            if riga.startswith("#") and not riga.startswith("# ---"):
                commento.append(riga)
            elif not riga.strip():
                commento.clear()
            continue
        chiave = trovata["chiave"]
        if chiave in presenti or chiave in SEGRETI:
            commento.clear()
            continue
        da_aggiungere.extend(commento)
        da_aggiungere.append(riga)
        nomi.append(chiave)
        commento.clear()

    # Un valore PRESENTE ma vecchio non si aggiunge e non si corregge -- non e'
    # lecito sovrascrivere una scelta di chi installa -- ma va detto. Si
    # guardano solo gli indirizzi: un endpoint cambiato a monte e' un guasto
    # (`api.ransomware.live` e' diventato `/v2`), mentre porte e password
    # divergono per scelta e segnalarle sarebbe rumore.
    attesi = {m["chiave"]: m["valore"].strip()
              for riga in esempio.splitlines() if (m := ASSEGNAZIONE.match(riga))}
    correnti = {m["chiave"]: m["valore"].strip()
                for riga in attuale.splitlines() if (m := ASSEGNAZIONE.match(riga))}
    vecchi = [(k, correnti[k], atteso) for k, atteso in attesi.items()
              if atteso.startswith("http") and k in correnti
              and correnti[k] and correnti[k] != atteso]
    if vecchi:
        print("Indirizzi che in `.env.example` sono cambiati:")
        for chiave, adesso, atteso in vecchi:
            print(f"  {chiave}")
            print(f"    nel tuo .env: {adesso}")
            print(f"    nell'esempio: {atteso}")
        print("  Non li tocco: il valore e' una scelta di chi installa. Ma se non")
        print("  e' deliberata, va allineato a mano.")
        print()

    if not nomi:
        print("Niente da integrare: `.env` ha tutte le variabili dell'esempio.")
        return 0

    print(f"Variabili presenti in .env.example e assenti da {args.env.name}:")
    for nome in nomi:
        print(f"  {nome}")
    print()
    if args.dry_run:
        print("(--dry-run: non ho scritto niente)")
        return 0

    salvataggio = args.env.with_name(
        f"{args.env.name}.{datetime.now(UTC):%Y%m%d-%H%M%S}.bak")
    shutil.copy2(args.env, salvataggio)
    salvataggio.chmod(0o600)

    testo = attuale if attuale.endswith("\n") else attuale + "\n"
    testo += ("\n# --- Aggiunte da `make env-integra` "
              f"({datetime.now(UTC):%Y-%m-%d}) ---\n")
    testo += "\n".join(da_aggiungere) + "\n"
    args.env.write_text(testo, encoding="utf-8")
    args.env.chmod(0o600)

    print(f"Aggiunte {len(nomi)} variabili. Copia del precedente: {salvataggio.name}")
    print("I valori esistenti non sono stati toccati.")
    print("Ora: controllare i nuovi valori e `make up`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
