#!/usr/bin/env python3
"""Verifica che le versioni fissate esistano ancora upstream.

Copre i tag Git dei Dockerfile e le immagini container di
`docker-compose.yml`. Le seconde mancavano, ed e' cosi' che nel compose e'
finito un tag ZAP inesistente: l'errore si e' visto solo al primo
`docker compose up` di chi lo usava.

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
COMPOSE = "docker-compose.yml"

# `image: <registro>/<repo>:<tag>` nel compose. I tag mobili (`latest`,
# `stable`) sono esclusi: per definizione esistono sempre, e fissarli non e'
# il problema che questo controllo previene.
IMMAGINE = re.compile(r"^\s*image:\s*(\S+):(\S+)\s*$", re.MULTILINE)
TAG_MOBILI = {"latest", "stable", "main", "master"}

# Rilascio ProjectDiscovery scaricato da `scarica <nome> "${<NOME>_VERSION}"`,
# con la versione dichiarata da `ARG <NOME>_VERSION=X.Y.Z` (senza prefisso `v`
# nel nome del file, con prefisso nel tag).
PD_TOOL = re.compile(r"^\s*scarica (\w+) \"\$\{(\w+_VERSION)\}\"", re.MULTILINE)
CLONE = re.compile(r"git clone [^\n]*?--branch \$\{(\w+)\}[^\n]*?"
                   r"https://github\.com/([\w.-]+?/[\w.-]+?)(?:\.git)?(?:\s|$)")
ARG_VERSION = re.compile(r"^ARG (\w+_VERSION)=(\S+)", re.MULTILINE)

# Rilascio scaricato da un indirizzo esplicito con `scaricaz`: il repository
# sta nell'URL e la versione in un `ARG`. Senza questa riga amass restava
# fissato e non verificato, come il tag ZAP nel compose.
ZIP_TOOL = re.compile(r"scaricaz \w+ +\"https://github\.com/([\w.-]+?/[\w.-]+?)/releases/"
                      r"download/v\$\{(\w+_VERSION)\}")


def _tag_esiste(repo: str, tag: str) -> tuple[bool, list[str]]:
    esito = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", f"https://github.com/{repo}.git"],
        capture_output=True, text=True, timeout=60)
    if esito.returncode != 0:
        raise RuntimeError(f"impossibile interrogare {repo}: {esito.stderr.strip()}")
    tags = [riga.split("refs/tags/")[-1] for riga in esito.stdout.splitlines()]
    return tag in tags, tags[-5:]


def _immagine_esiste(riferimento: str, tag: str) -> tuple[bool, str]:
    """Interroga il registro per un manifest, senza scaricare l'immagine.

    Niente `docker pull`: il controllo deve poter girare dove Docker non c'e',
    e scaricare centinaia di megabyte per sapere se un tag esiste sarebbe un
    modo lento di rispondere a una domanda semplice.
    """
    import json
    import urllib.request

    pezzi = riferimento.split("/")
    if "." in pezzi[0] or ":" in pezzi[0]:
        registro, repo = pezzi[0], "/".join(pezzi[1:])
    else:
        # Docker Hub: le immagini senza spazio dei nomi stanno in `library`.
        registro = "registry-1.docker.io"
        repo = riferimento if "/" in riferimento else f"library/{riferimento}"

    def _leggi(url: str, intestazioni: dict[str, str]) -> bytes:
        richiesta = urllib.request.Request(url, headers=intestazioni)  # noqa: S310
        with urllib.request.urlopen(richiesta, timeout=30) as risposta:  # noqa: S310
            return risposta.read()

    # Ogni registro pubblica i token da un indirizzo proprio: Docker Hub non
    # li serve dal registro stesso, ed e' il motivo per cui il primo tentativo
    # rispondeva 404 su immagini che esistono.
    token_di = {
        "registry-1.docker.io":
            f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull",
        "ghcr.io": f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull",
        "quay.io": f"https://quay.io/v2/auth?service=quay.io&scope=repository:{repo}:pull",
    }
    url_token = token_di.get(registro,
                             f"https://{registro}/token?service={registro}&scope=repository:{repo}:pull")
    try:
        token = json.loads(_leggi(url_token, {})).get("token", "")
    except Exception as errore:  # noqa: BLE001
        # Registro non interrogabile: non e' un tag mancante, e dichiararlo
        # tale renderebbe il controllo inutile — chi lo esegue imparerebbe a
        # ignorarne le righe rosse.
        return True, f"non verificabile ({str(errore)[:80]})"
    try:
        _leggi(f"https://{registro}/v2/{repo}/manifests/{tag}",
               {"Authorization": f"Bearer {token}",
                "Accept": ("application/vnd.oci.image.index.v1+json,"
                           "application/vnd.docker.distribution.manifest.list.v2+json,"
                           "application/vnd.docker.distribution.manifest.v2+json")})
    except Exception as errore:  # noqa: BLE001
        testo = str(errore)
        if "404" in testo or "MANIFEST_UNKNOWN" in testo:
            return False, "tag inesistente"
        return True, f"non verificabile ({testo[:80]})"
    return True, ""


def main() -> int:
    da_verificare: list[tuple[str, str, str]] = []  # (file, repo, tag)
    for nome in DOCKERFILES:
        testo = (REPO_ROOT / nome).read_text(encoding="utf-8")
        # Le continuazioni di riga spezzerebbero le espressioni regolari.
        continuo = testo.replace("\\\n", " ")
        args = dict(ARG_VERSION.findall(testo))
        for tool, arg in PD_TOOL.findall(testo):
            if arg in args:
                da_verificare.append((nome, f"projectdiscovery/{tool}", f"v{args[arg]}"))
        for repo, arg in ZIP_TOOL.findall(continuo):
            if arg in args:
                da_verificare.append((nome, repo, f"v{args[arg]}"))
        for arg, repo in CLONE.findall(continuo):
            if arg in args:
                da_verificare.append((nome, repo, args[arg]))

    immagini: list[tuple[str, str]] = []
    for riferimento, tag in IMMAGINE.findall((REPO_ROOT / COMPOSE).read_text(encoding="utf-8")):
        if tag not in TAG_MOBILI:
            immagini.append((riferimento, tag))

    if not da_verificare:
        print("nessuna versione fissata da verificare", file=sys.stderr)
        return 1

    problemi = 0
    for riferimento, tag in immagini:
        esiste, nota = _immagine_esiste(riferimento, tag)
        if esiste:
            print(f"  ok   {COMPOSE}: {riferimento}:{tag}"
                  + (f"  [{nota}]" if nota else ""))
        else:
            problemi += 1
            print(f"  NO   {COMPOSE}: {riferimento}:{tag} -> {nota}")

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
