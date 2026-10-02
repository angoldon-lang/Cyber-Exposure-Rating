"""«Non riuscito» ha due cause con due rimedi opposti.

`make strumenti` stampava «il worker non risponde» su qualunque uscita diversa
da zero. Ma il modo piu' probabile di fallire e' un altro: il worker risponde
benissimo e gira su un'immagine precedente, che quel sottocomando non lo
conosce — l'immagine contiene una copia del codice, e una modifica al
repository non la raggiunge finche' non viene ricostruita. Mandare a riavviare
un servizio sano, quando serve ricostruirlo, fa perdere tempo a chi ha appena
aggiornato.

I test sostituiscono `docker compose` con uno script che recita le risposte:
non serve un demone, e non si avvia niente.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parents[1]
SCRIPT = RADICE / "scripts" / "strumenti.sh"


def _finto_compose(tmp_path: Path, *, container: str, uscita_cli: int,
                   output_cli: str, versione_worker: str = "0.1.0") -> Path:
    """Uno script che si comporta come `docker compose` per i casi che servono."""
    percorso = tmp_path / "compose-finto"
    percorso.write_text(f'''#!/usr/bin/env bash
case "$1 $2" in
  "ps -q") printf '%s' {container!r}; exit 0 ;;
esac
# `exec -T worker sh -c 'cat /srv/VERSION'`
if printf '%s' "$*" | grep -q VERSION; then
  printf '%s\\n' {versione_worker!r}; exit 0
fi
# `exec -T worker python -m app.cli strumenti ...`
if printf '%s' "$*" | grep -q "app.cli strumenti"; then
  printf '%s\\n' {output_cli!r}; exit {uscita_cli}
fi
exit 0
''', encoding="utf-8")
    percorso.chmod(0o755)
    return percorso


def _esegui(compose: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT)],  # noqa: S607
        cwd=RADICE, env={"PATH": "/usr/bin:/bin", "COMPOSE": str(compose)},
        capture_output=True, text=True, timeout=60, check=False)


def test_un_worker_su_una_versione_precedente_va_ricostruito_non_riavviato(tmp_path):
    """E' il caso reale: l'immagine e' della versione prima, il comando non
    esiste ancora, e argparse risponde «invalid choice»."""
    compose = _finto_compose(
        tmp_path, container="abc123", uscita_cli=2, versione_worker="0.17.0",
        output_cli="defenix: error: argument command: invalid choice: 'strumenti' "
                   "(choose from 'init-db', 'seed')")

    esito = _esegui(compose)

    assert esito.returncode != 0
    assert "make aggiorna" in esito.stdout
    assert "0.17.0" in esito.stdout, "non dice quale versione sta girando"
    assert "worker-start" in esito.stdout, "il rimedio piu' rapido non e' nominato"
    assert "non risponde" not in esito.stdout, (
        "il worker risponde: dirlo guasto manda a cercare la cosa sbagliata")


def test_un_worker_spento_va_avviato(tmp_path):
    compose = _finto_compose(tmp_path, container="", uscita_cli=0, output_cli="")

    esito = _esegui(compose)

    assert esito.returncode != 0
    assert "worker-start" in esito.stdout
    assert "aggiorna" not in esito.stdout, (
        "un worker spento non ha bisogno di una ricostruzione")


def test_un_esito_riuscito_passa_senza_commenti(tmp_path):
    compose = _finto_compose(tmp_path, container="abc123", uscita_cli=0,
                             output_cli="  dns  operativo")

    esito = _esegui(compose)

    assert esito.returncode == 0
    assert "operativo" in esito.stdout
    assert "make" not in esito.stdout, "nessun rimedio da proporre quando va bene"


def test_un_guasto_di_altra_natura_non_viene_spiegato_a_caso(tmp_path):
    """Inventare una causa e' peggio che dire «guarda l'output»: la prima manda
    nella direzione sbagliata con sicurezza."""
    compose = _finto_compose(tmp_path, container="abc123", uscita_cli=1,
                             output_cli="Traceback: sqlalchemy.exc.OperationalError")

    esito = _esegui(compose)

    assert esito.returncode != 0
    assert "OperationalError" in esito.stdout
    assert "aggiorna" not in esito.stdout
    assert "doctor" in esito.stdout


@pytest.mark.parametrize("campo", ["strumenti", "worker-start", "aggiorna"])
def test_il_make_rimanda_allo_script_e_non_al_comando_diretto(campo):
    """Se il target tornasse a chiamare `compose exec` direttamente, tutta la
    diagnosi qui sopra non verrebbe piu' eseguita da nessuno."""
    makefile = (RADICE / "Makefile").read_text(encoding="utf-8")

    assert "bash scripts/strumenti.sh" in makefile
    assert campo in makefile
