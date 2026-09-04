#!/usr/bin/env python3
"""Segnala quali porte pubblicate dallo stack sono gia' occupate sull'host.

Docker fallisce una porta alla volta ("port is already allocated") e solo dopo
aver avviato gli altri container. Questo controllo le verifica tutte insieme e
indica quale variabile di `.env` cambiare.

Uso:  python3 scripts/check_ports.py
"""
from __future__ import annotations

import re
import socket
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE = REPO_ROOT / "docker-compose.yml"
ENV = REPO_ROOT / ".env"

# - "${FRONTEND_PORT:-8080}:8080"
PUBBLICAZIONE = re.compile(r'^\s*-\s*"\$\{(\w+):-(\d+)\}:\d+"', re.MULTILINE)


def _porte_configurate() -> list[tuple[str, int]]:
    valori: dict[str, str] = {}
    if ENV.exists():
        for riga in ENV.read_text(encoding="utf-8").splitlines():
            if "=" in riga and not riga.lstrip().startswith("#"):
                chiave, _, valore = riga.partition("=")
                valori[chiave.strip()] = valore.strip()

    porte = []
    for variabile, predefinita in PUBBLICAZIONE.findall(COMPOSE.read_text(encoding="utf-8")):
        grezzo = valori.get(variabile) or predefinita
        try:
            porte.append((variabile, int(grezzo)))
        except ValueError:
            print(f"  ?  {variabile}={grezzo!r} non e' un numero di porta", file=sys.stderr)
    return porte


def _occupata(porta: int) -> bool:
    """Docker pubblica su 0.0.0.0: e' li' che va verificato il conflitto."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as presa:
        presa.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            presa.bind(("0.0.0.0", porta))
        except OSError:
            return True
    return False


def _prima_libera(da: int, gia_assegnate: set[int]) -> int:
    """Evita sia le porte occupate sia quelle gia' destinate a un altro servizio
    dello stack, che darebbero un conflitto al prossimo avvio."""
    for porta in range(da, da + 100):
        if porta not in gia_assegnate and not _occupata(porta):
            return porta
    return 0


def main() -> int:
    porte = _porte_configurate()
    if not porte:
        print("nessuna porta pubblicata trovata nel compose file", file=sys.stderr)
        return 1

    conflitti = []
    for variabile, porta in porte:
        if _occupata(porta):
            conflitti.append((variabile, porta))
            print(f"  OCCUPATA  {porta:>5}  ({variabile})")
        else:
            print(f"  libera    {porta:>5}  ({variabile})")

    if not conflitti:
        print("\nTutte le porte sono disponibili.")
        return 0

    print("\nSe lo stack e' gia' avviato, sono le sue stesse porte: `make down` e riprova.")
    print("Altrimenti un altro programma le occupa. Cambiare in `.env`:")
    assegnate = {p for _, p in porte}
    for variabile, porta in conflitti:
        libera = _prima_libera(porta + 1, assegnate)
        assegnate.add(libera)
        print(f"    {variabile}={libera or '<una porta libera>'}    # invece di {porta}")
    print("\nIl frontend raggiunge l'API tramite il proxy interno di nginx, quindi")
    print("cambiare queste porte non richiede di modificare CORS_ORIGINS.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
