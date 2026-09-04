#!/usr/bin/env python3
"""Genera il file `.env` a partire da `.env.example`, valorizzando i segreti.

Sostituisce le istruzioni `sed` presenti nelle prime versioni del README: la
sintassi di `sed -i` non e' portabile (GNU vuole `sed -i`, BSD/macOS vuole
`sed -i ''`) e su macOS quei comandi fallivano con "invalid command code".

Uso:
    python3 scripts/generate_env.py [--force] [--with-keycloak] [--output .env]
"""
from __future__ import annotations

import argparse
import base64
import os
import secrets
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Variabili da valorizzare -> generatore. La chiave Fernet richiede il formato
# esatto atteso da `cryptography`: 32 byte casuali in base64 url-safe.
GENERATORI = {
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(32),
    "JWT_SECRET_KEY": lambda: secrets.token_urlsafe(48),
    "EVIDENCE_ENCRYPTION_KEY": lambda: base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
}
SOLO_KEYCLOAK = {"KEYCLOAK_ADMIN_PASSWORD": lambda: secrets.token_urlsafe(24)}


def genera(esempio: Path, destinazione: Path, *, con_keycloak: bool) -> list[str]:
    da_valorizzare = dict(GENERATORI)
    if con_keycloak:
        da_valorizzare.update(SOLO_KEYCLOAK)

    righe: list[str] = []
    valorizzate: list[str] = []
    for riga in esempio.read_text(encoding="utf-8").splitlines():
        chiave = riga.split("=", 1)[0] if "=" in riga and not riga.startswith("#") else None
        if chiave in da_valorizzare:
            righe.append(f"{chiave}={da_valorizzare[chiave]()}")
            valorizzate.append(chiave)
        else:
            righe.append(riga)

    mancanti = set(da_valorizzare) - set(valorizzate)
    if mancanti:
        raise SystemExit(f"variabili assenti da {esempio.name}: {sorted(mancanti)}")

    destinazione.write_text("\n".join(righe) + "\n", encoding="utf-8")
    # Il file contiene segreti: leggibile solo dal proprietario.
    destinazione.chmod(0o600)
    return valorizzate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO_ROOT / ".env")
    parser.add_argument("--example", type=Path, default=REPO_ROOT / ".env.example")
    parser.add_argument("--force", action="store_true",
                        help="sovrascrive un `.env` esistente (i segreti cambiano)")
    parser.add_argument("--with-keycloak", action="store_true",
                        help="valorizza anche KEYCLOAK_ADMIN_PASSWORD (profilo oidc)")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        print(f"{args.output} esiste gia': non lo sovrascrivo.\n"
              f"Usare --force per rigenerarlo (i segreti cambiano e il database\n"
              f"esistente non sarebbe piu' accessibile con la nuova password).",
              file=sys.stderr)
        return 1

    valorizzate = genera(args.example, args.output, con_keycloak=args.with_keycloak)
    print(f"Creato {args.output} (permessi 0600).")
    print("Segreti generati: " + ", ".join(sorted(valorizzate)))
    print("Non versionare questo file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
