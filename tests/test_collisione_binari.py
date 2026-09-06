"""Un pacchetto Python non deve poter sostituire uno strumento di scansione.

`backend/requirements.txt` contiene `httpx`, il client HTTP di Python, che
installa uno script eseguibile chiamato `httpx` — lo stesso nome del binario
di ProjectDiscovery. Il Dockerfile copiava entrambi in `/usr/local/bin` e il
`pip install`, eseguito dopo, sovrascriveva il binario.

A ogni scansione partiva quindi lo script Python:

    exit 1, stderr vuoto, su stdout
    «The httpx command line client could not run because the required
     dependencies were not installed.»

L'area sicurezza web restava scoperta e nel log non c'era una causa, perche'
il messaggio non passa da stderr.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (REPO_ROOT / "workers" / "Dockerfile").read_text(encoding="utf-8")
REQUISITI = (REPO_ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8")

pytestmark = pytest.mark.security

# La cartella riservata agli strumenti: `pip` non ci scrive mai.
CARTELLA_STRUMENTI = "/opt/defenix/bin"


def _pacchetti_python() -> set[str]:
    nomi = set()
    for riga in REQUISITI.splitlines():
        riga = riga.split("#")[0].strip()
        if riga:
            nomi.add(re.split(r"[=<>!\[]", riga)[0].strip().lower())
    return nomi


def test_la_collisione_che_ha_rotto_httpx_esiste_ancora():
    """Il presupposto del test: se un giorno `httpx` uscisse dai requisiti,
    questi controlli perderebbero senso e va saputo."""
    assert "httpx" in _pacchetti_python()


def test_gli_strumenti_non_stanno_dove_scrive_pip():
    copie = re.findall(r"^COPY --from=tools \S+ (\S+)$", DOCKERFILE, re.MULTILINE)

    assert copie, "il Dockerfile non copia piu' gli strumenti: controllo da rivedere"
    for destinazione in copie:
        assert destinazione.rstrip("/") == CARTELLA_STRUMENTI, (
            f"strumenti copiati in {destinazione}: se e' una cartella in cui "
            "pip installa i propri script, il prossimo pip li sovrascrive")


def test_la_cartella_degli_strumenti_precede_quelle_di_pip():
    assegnazioni = re.findall(r"^ENV PATH=(\S+)$", DOCKERFILE, re.MULTILINE)

    assert assegnazioni, "PATH non e' impostato: l'ordine non e' garantito"
    voci = assegnazioni[-1].split(":")
    assert voci[0] == CARTELLA_STRUMENTI, (
        f"PATH inizia con {voci[0]}: lo strumento che risponde non e' il nostro")


def test_la_build_verifica_quale_binario_risponde():
    """Un controllo nell'immagine vale piu' di un test qui: intercetta anche
    le collisioni introdotte da un pacchetto aggiunto in futuro."""
    assert "command -v" in DOCKERFILE
    for strumento in ("subfinder", "httpx", "nuclei", "testssl.sh"):
        assert strumento in DOCKERFILE


def test_anche_il_runner_cerca_prima_nella_cartella_degli_strumenti():
    """Il worker parte con il PATH dell'immagine, ma il runner ne impone uno
    proprio quando la variabile non e' ereditata."""
    from adapters.runner import run_command  # noqa: F401

    sorgente = (REPO_ROOT / "adapters" / "runner.py").read_text(encoding="utf-8")
    percorso = re.search(r'env\.setdefault\("PATH", "([^"]+)"\)', sorgente)

    assert percorso, "il runner non impone piu' un PATH predefinito"
    assert percorso.group(1).split(":")[0] == CARTELLA_STRUMENTI
