#!/usr/bin/env python3
"""Verifica che le versioni fissate nei Dockerfile esistano ancora upstream.

Un tag rimosso o rinominato si scopre altrimenti solo a meta' di `make build`,
dopo minuti di compilazione (e' successo con testssl.sh, il cui tag e'
`v3.2.4` e non `3.2.4`).

Richiede rete: e' un controllo esplicito, NON fa parte di `make test`, che per
scelta non contatta alcun sistema esterno.

Uso:  python3 scripts/check_pinned_versions.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = ("backend/Dockerfile", "workers/Dockerfile", "frontend/Dockerfile")

# `go install ...@vX.Y.Z` e `ARG TESTSSL_VERSION=vX.Y.Z` + il repo del clone.
GO_MODULE = re.compile(r"go install .*?github\.com/([\w.-]+/[\w.-]+)(?:/v\d+)?/cmd/[\w.-]+@(\S+)")
CLONE = re.compile(r"git clone [^\n]*?--branch \$\{(\w+)\}[^\n]*?"
                   r"https://github\.com/([\w.-]+?/[\w.-]+?)(?:\.git)?(?:\s|$)")
ARG_VERSION = re.compile(r"^ARG (\w+_VERSION)=(\S+)", re.MULTILINE)


def _tag_esiste(repo: str, tag: str) -> tuple[bool, list[str]]:
    esito = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", f"https://github.com/{repo}.git"],
        capture_output=True, text=True, timeout=60)
    if esito.returncode != 0:
        raise RuntimeError(f"impossibile interrogare {repo}: {esito.stderr.strip()}")
    tags = [riga.split("refs/tags/")[-1] for riga in esito.stdout.splitlines()]
    return tag in tags, tags[-5:]


def main() -> int:
    da_verificare: list[tuple[str, str, str]] = []  # (file, repo, tag)
    for nome in DOCKERFILES:
        testo = (REPO_ROOT / nome).read_text(encoding="utf-8")
        # Le continuazioni di riga spezzerebbero le espressioni regolari.
        continuo = testo.replace("\\\n", " ")
        args = dict(ARG_VERSION.findall(testo))
        for repo, tag in GO_MODULE.findall(continuo):
            da_verificare.append((nome, repo, tag))
        for arg, repo in CLONE.findall(continuo):
            if arg in args:
                da_verificare.append((nome, repo, args[arg]))

    if not da_verificare:
        print("nessuna versione fissata da verificare", file=sys.stderr)
        return 1

    problemi = 0
    for nome, repo, tag in da_verificare:
        try:
            esiste, recenti = _tag_esiste(repo, tag)
        except RuntimeError as errore:
            print(f"  ?  {repo} {tag} ({nome}): {errore}")
            problemi += 1
            continue
        if esiste:
            print(f"  ok {repo} {tag}")
        else:
            problemi += 1
            print(f"  NO {repo} {tag} ({nome}) non esiste piu'. Tag recenti: {recenti}")

    print(f"\n{len(da_verificare) - problemi}/{len(da_verificare)} versioni valide.")
    return 1 if problemi else 0


if __name__ == "__main__":
    raise SystemExit(main())
