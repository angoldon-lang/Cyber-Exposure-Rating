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
# Un'immagine fissata per digest: `repo@sha256:...`. E' il pin piu' stretto
# che esista — immutabile per costruzione — ed e' l'unico possibile quando il
# progetto a monte non pubblica tag di versione. Va riconosciuto a parte,
# perche' l'espressione qui sopra spezzerebbe sull'ultimo due punti e
# chiederebbe al registro un manifest di nome «8cb9...».
DIGEST = re.compile(r"^\s*image:\s*(\S+)@(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)
TAG_MOBILI = {"latest", "stable", "main", "master"}

# Un commit fissato come argomento di costruzione: `<NOME>_COMMIT: <sha>` nel
# compose. E' il pin piu' stretto possibile per un sorgente, e serve dove il
# progetto a monte non pubblica un'immagine (SpiderFoot). Non si verifica
# chiedendo al registro: si verifica che quel commit sia ancora quello del tag
# da cui e' stato preso, perche' un tag che si sposta e' l'unico modo in cui un
# pin del genere puo' diventare sbagliato senza accorgersene.
COMMIT_ARG = re.compile(r"^\s*(\w+)_COMMIT:\s*([0-9a-f]{40})\s*$", re.MULTILINE)
# Dal Dockerfile che lo usa si ricava a quale repository appartiene, e quale
# tag dovrebbe puntarvi.
ORIGINE = re.compile(r"git remote add origin (https://github\.com/[\w.-]+/[\w.-]+?)(?:\.git)?\s")
TAG_ATTESO = re.compile(r"# Il commit, non il tag:.*?E' `([^`]+)`", re.DOTALL)

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


def _diniego(codice: int) -> str:
    """Perche' un diniego del registro e' un pin rotto, non un dubbio.

    ghcr risponde allo stesso modo per un pacchetto che non esiste e per uno
    privato: non li distingue. Per chi installa e' la stessa cosa — `docker
    pull` si fermera' con «denied» — e un'immagine che non si puo' scaricare
    anonimamente non e' un'immagine su cui fondare un'installazione.
    """
    return (f"HTTP {codice}: il registro nega l'accesso. L'immagine non esiste "
            "piu', oppure non e' piu' pubblica: in entrambi i casi "
            "`docker pull` non riuscira'")


def _immagine_esiste(riferimento: str, tag: str) -> tuple[bool, str]:
    """Interroga il registro per un manifest, senza scaricare l'immagine.

    Niente `docker pull`: il controllo deve poter girare dove Docker non c'e',
    e scaricare centinaia di megabyte per sapere se un tag esiste sarebbe un
    modo lento di rispondere a una domanda semplice.
    """
    import json
    import urllib.error
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
    except urllib.error.HTTPError as errore:
        # Anche il rilascio del token puo' essere negato, e su ghcr e' qui che
        # arriva il diniego per un pacchetto che non esiste: trattarlo come
        # «non verificabile» e' il motivo per cui
        # ghcr.io/smicallef/spiderfoot:v4.0 e' rimasto nel compose dichiarato
        # valido, fino a bloccare `make up` di chi installava.
        if errore.code in {401, 403}:
            return False, _diniego(errore.code)
        return True, f"non verificabile (HTTP {errore.code})"
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
    except urllib.error.HTTPError as errore:
        # Il registro ha risposto, e la sua risposta si crede.
        if errore.code == 404 or "MANIFEST_UNKNOWN" in str(errore):
            return False, "tag inesistente"
        if errore.code in {401, 403}:
            return False, _diniego(errore.code)
        return True, f"non verificabile (HTTP {errore.code})"
    except Exception as errore:  # noqa: BLE001
        # Qui finiscono i guasti di rete: il registro non ha detto niente, e
        # dichiarare mancante un tag per un tunnel caduto renderebbe il
        # controllo inutile -- chi lo esegue imparerebbe a ignorarne le righe.
        return True, f"non verificabile ({str(errore)[:80]})"
    return True, ""


def _commit_e_ancora_quello_del_tag(repo: str, tag: str,
                                    commit: str) -> tuple[bool, str]:
    """Vero se il tag indicato punta ancora al commit fissato.

    Un commit non scompare, quindi un pin per impronta non si rompe come un
    tag. Cio' che puo' cambiare sotto i piedi e' il significato: se `v4.0`
    domani punta altrove, l'immagine che costruiamo non e' piu' «la 4.0», e
    chi legge il compose continuera' a crederlo.
    """
    esito = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", f"{repo}.git", f"refs/tags/{tag}"],
        capture_output=True, text=True, timeout=60)
    if esito.returncode != 0 or not esito.stdout.strip():
        return True, f"non verificabile ({(esito.stderr or 'tag assente').strip()[:60]})"
    trovato = esito.stdout.split()[0]
    if trovato == commit:
        return True, ""
    return False, (f"il tag {tag} ora punta a {trovato[:12]}, non al commit "
                   f"fissato {commit[:12]}: l'immagine costruita non e' piu' "
                   f"quella che il compose dichiara")


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

    compose = (REPO_ROOT / COMPOSE).read_text(encoding="utf-8")
    # `separatore` serve solo a ristampare il riferimento com'e' scritto.
    immagini: list[tuple[str, str, str]] = []
    fissate_per_digest = {riferimento for riferimento, _ in DIGEST.findall(compose)}
    for riferimento, digest in DIGEST.findall(compose):
        immagini.append((riferimento, digest, "@"))
    for riferimento, tag in IMMAGINE.findall(compose):
        # Un riferimento con digest cade anche in questa espressione, spezzato
        # nel punto sbagliato: e' gia' stato raccolto sopra.
        nome = riferimento.rsplit("@", 1)[0]
        if nome in fissate_per_digest or tag in TAG_MOBILI:
            continue
        immagini.append((riferimento, tag, ":"))

    # Commit fissati: il repository e il tag atteso stanno nel Dockerfile che
    # li usa, cosi' il compose resta l'unico posto dove si scrive l'impronta.
    commit_fissati: list[tuple[str, str, str, str]] = []  # (nome, repo, tag, commit)
    for nome_arg, commit in COMMIT_ARG.findall(compose):
        cartella = REPO_ROOT / "deploy" / nome_arg.lower() / "Dockerfile"
        if not cartella.is_file():
            continue
        testo = cartella.read_text(encoding="utf-8")
        origine = ORIGINE.search(testo)
        atteso = TAG_ATTESO.search(testo)
        if origine and atteso:
            commit_fissati.append((str(cartella.relative_to(REPO_ROOT)),
                                   origine.group(1), atteso.group(1), commit))

    if not da_verificare:
        print("nessuna versione fissata da verificare", file=sys.stderr)
        return 1

    problemi = 0
    for riferimento, tag, separatore in immagini:
        esiste, nota = _immagine_esiste(riferimento, tag)
        scritto = f"{riferimento}{separatore}{tag}"
        if esiste:
            print(f"  ok   {COMPOSE}: {scritto}" + (f"  [{nota}]" if nota else ""))
        else:
            problemi += 1
            print(f"  NO   {COMPOSE}: {scritto} -> {nota}")

    for nome, repo, tag, commit in commit_fissati:
        esiste, nota = _commit_e_ancora_quello_del_tag(repo, tag, commit)
        etichetta = f"{repo.rsplit('/', 1)[-1]}@{commit[:12]} ({tag})"
        if esiste:
            print(f"  ok   {nome}: {etichetta}" + (f"  [{nota}]" if nota else ""))
        else:
            problemi += 1
            print(f"  NO   {nome}: {etichetta} -> {nota}")

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

    totale = len(da_verificare) + len(immagini) + len(commit_fissati)
    print(f"\n{totale - problemi}/{totale} versioni valide.")
    return 1 if problemi else 0


if __name__ == "__main__":
    raise SystemExit(main())
