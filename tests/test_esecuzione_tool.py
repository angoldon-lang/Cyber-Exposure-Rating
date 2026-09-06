"""Esecuzione dei tool esterni: il timeout deve valere davvero.

Un timeout di dieci minuti su testssl.sh e' arrivato a durarne oltre
duecento, bloccando la scansione per ore. La causa non e' il valore del
timeout ma cosa succede quando scade: `subprocess.run` uccide il figlio
diretto e poi rilegge le pipe fino alla fine del flusso. Un tool che lancia
altri processi lascia i nipoti vivi con le pipe aperte, e quella lettura non
finisce mai.
"""
from __future__ import annotations

import signal
import time
from pathlib import Path

import pytest

from adapters.runner import run_command

pytestmark = pytest.mark.security

# Il figlio diretto lancia un nipote che sopravvive e tiene aperte le pipe,
# poi resta in attesa. E' la forma di testssl.sh, che lancia `openssl`.
NIPOTE_CHE_SOPRAVVIVE = (
    "import subprocess, sys, time\n"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
    "sys.stdout.write('parziale\\n'); sys.stdout.flush()\n"
    "time.sleep(120)\n"
)


def _ancora_in_esecuzione(pid: int) -> bool:
    """Vero se il processo esiste ed e' ancora attivo.

    `os.kill(pid, 0)` non basta: riesce anche sugli zombie, cioe' su processi
    gia' terminati che nessuno ha ancora raccolto. Quando il padre diretto
    muore per primo, il nipote terminato resta zombie finche' non viene
    adottato e raccolto, e verrebbe scambiato per vivo.
    """
    try:
        stato = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return False
    for riga in stato.splitlines():
        if riga.startswith("State:"):
            return not riga.split()[1].startswith("Z")
    return True


def test_il_timeout_scade_quando_deve(tmp_path):
    """Regressione: il ritorno avveniva solo quando morivano i nipoti."""
    script = tmp_path / "con_nipote.py"
    script.write_text(NIPOTE_CHE_SOPRAVVIVE, encoding="utf-8")

    inizio = time.monotonic()
    esito = run_command("python3", [str(script)], timeout=2)
    durata = time.monotonic() - inizio

    assert esito.timed_out
    assert durata < 20, (
        f"il timeout di 2 secondi ha impiegato {durata:.1f}s: la lettura delle "
        "pipe attende i processi nipoti")


def test_nessun_discendente_sopravvive_al_timeout(tmp_path):
    """Un nipote lasciato vivo continua a consumare risorse e a parlare con
    l'esterno dopo che la scansione ha smesso di aspettarlo."""
    segnale = tmp_path / "vivo.txt"
    script = tmp_path / "traccia.py"
    script.write_text(
        "import subprocess, sys, time\n"
        f"figlio = subprocess.Popen([sys.executable, '-c', \"import time, pathlib; \"\n"
        f"    \"pathlib.Path(r'{segnale}').write_text(str(__import__('os').getpid())); \"\n"
        "    \"time.sleep(120)\"])\n"
        "time.sleep(120)\n", encoding="utf-8")

    esito = run_command("python3", [str(script)], timeout=3)
    assert esito.timed_out

    # Attesa breve: il gruppo viene terminato subito dopo la scadenza.
    for _ in range(20):
        if segnale.exists():
            break
        time.sleep(0.1)
    if not segnale.exists():
        pytest.skip("il nipote non ha fatto in tempo a registrarsi")

    pid = int(segnale.read_text().strip())
    time.sleep(0.5)
    assert not _ancora_in_esecuzione(pid), (
        f"il processo nipote {pid} e' sopravvissuto alla terminazione del gruppo")


def test_l_output_prodotto_prima_della_scadenza_non_si_perde(tmp_path):
    """Un tool interrotto ha spesso gia' scritto risultati utili."""
    script = tmp_path / "scrive_poi_dorme.py"
    script.write_text(
        "import sys, time\n"
        "sys.stdout.write('risultato-parziale\\n'); sys.stdout.flush()\n"
        "time.sleep(120)\n", encoding="utf-8")

    esito = run_command("python3", [str(script)], timeout=2)
    assert esito.timed_out
    assert b"risultato-parziale" in esito.stdout


def test_un_comando_normale_resta_invariato(tmp_path):
    script = tmp_path / "somma.py"
    script.write_text("print(1 + 1)\n", encoding="utf-8")
    esito = run_command("python3", [str(script)], timeout=10)
    assert not esito.timed_out
    assert esito.exit_code == 0
    assert esito.stdout.strip() == b"2"


def test_il_processo_gira_in_una_sessione_propria(tmp_path):
    """E' la condizione che rende terminabile l'intero albero: senza, il
    gruppo di processi sarebbe quello del worker Celery e terminarlo
    equivarrebbe a terminare il worker."""
    script = tmp_path / "sessione.py"
    script.write_text("import os\nprint(os.getpid() == os.getsid(0))\n", encoding="utf-8")
    esito = run_command("python3", [str(script)], timeout=10)
    assert esito.stdout.strip() == b"True"


def test_il_segnale_di_terminazione_e_progressivo():
    """Prima SIGTERM, per dare al tool modo di chiudere i file che scrive;
    SIGKILL solo se non basta."""
    import inspect

    from adapters import runner

    sorgente = inspect.getsource(runner._termina_gruppo)
    assert sorgente.index("SIGTERM") < sorgente.index("SIGKILL")
    assert "killpg" in sorgente


def test_il_gruppo_terminato_e_solo_quello_del_figlio():
    """`killpg` sul gruppo sbagliato ucciderebbe il worker."""
    import inspect

    from adapters import runner

    assert "os.getpgid(processo.pid)" in inspect.getsource(runner._termina_gruppo)
    assert signal.SIGKILL is not None
