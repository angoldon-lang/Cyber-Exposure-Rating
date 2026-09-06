"""Esecuzione sicura dei tool esterni.

Regole non negoziabili:
  * argomenti SEMPRE come array, mai concatenazione di stringhe;
  * nessuna shell (`shell=False`);
  * nessuna interpolazione dell'input utente negli argomenti senza validazione;
  * timeout, limite di output, limiti di memoria/CPU sul processo figlio;
  * directory temporanea dedicata e cancellata al termine;
  * ambiente minimale (nessun segreto ereditato per errore).
"""
from __future__ import annotations

import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Un argomento e' ammesso solo se composto da caratteri sicuri.
_SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9._:/@=,+\[\]-]{1,2048}$")
# Variabili d'ambiente propagate al processo figlio: nulla di piu'.
_ALLOWED_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR")

DEFAULT_MAX_OUTPUT_BYTES = 50 * 1024 * 1024


class UnsafeCommandError(ValueError):
    """L'argomento proposto non e' sicuro: l'esecuzione viene rifiutata."""


@dataclass
class CommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    duration_seconds: float
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def validate_argument(argument: str) -> str:
    """Valida un singolo argomento di comando.

    Anche se `shell=False` rende l'iniezione di shell impossibile, questa
    validazione blocca anche l'*argument injection* (un valore che inizia con
    `-` verrebbe interpretato come opzione dal tool).
    """
    if not isinstance(argument, str):
        raise UnsafeCommandError(f"Argomento non testuale: {argument!r}")
    if not argument:
        raise UnsafeCommandError("Argomento vuoto")
    if "\x00" in argument:
        raise UnsafeCommandError("Argomento contiene un byte nullo")
    if not _SAFE_ARG_RE.match(argument):
        raise UnsafeCommandError(f"Argomento con caratteri non ammessi: {argument!r}")
    return argument


def build_command(binary: str, args: Sequence[str], *, allow_flags: Sequence[str] = ()) -> list[str]:
    """Costruisce la lista di argomenti validando ogni elemento.

    `allow_flags` elenca le opzioni ammesse per quel tool: qualsiasi argomento
    che inizia con `-` e non e' nell'allowlist viene rifiutato.
    """
    resolved = shutil.which(binary)
    if resolved is None:
        raise FileNotFoundError(f"Binario non disponibile: {binary}")
    command = [resolved]
    allowed = set(allow_flags)
    for raw in args:
        argument = validate_argument(str(raw))
        if argument.startswith("-") and argument not in allowed:
            raise UnsafeCommandError(f"Opzione non consentita per {binary}: {argument!r}")
        command.append(argument)
    return command


def _child_limits(memory_mb: int, cpu_seconds: int) -> None:  # pragma: no cover - eseguito nel figlio
    """Applica i limiti di risorse nel processo figlio prima dell'exec."""
    resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (DEFAULT_MAX_OUTPUT_BYTES,) * 2)
    # La sessione separata la crea `start_new_session=True`, che agisce prima
    # di questa funzione: chiamare `os.setsid()` qui fallirebbe con EPERM,
    # perche' il processo e' gia' leader della propria sessione.


ATTESA_TERMINAZIONE_SECONDI = 5


def prima_riga(dati: bytes, massimo: int = 300) -> str:
    """Prima riga non vuota di stderr: quella che dice cosa e' andato storto."""
    for riga in (dati or b"").decode("utf-8", errors="replace").splitlines():
        if riga.strip():
            return riga.strip()[:massimo]
    return ""


def _termina_gruppo(processo: subprocess.Popen) -> tuple[bytes, bytes]:
    """Termina il processo e tutti i suoi discendenti, poi raccoglie l'output.

    Prima un SIGTERM al gruppo, per dare al tool la possibilita' di chiudere
    i file che sta scrivendo; se non basta, SIGKILL. La raccolta finale ha a
    sua volta un tempo massimo: se qualcosa tenesse ancora aperte le pipe,
    l'output parziale si perde, ma la scansione prosegue. E' il compromesso
    giusto: un output incompleto vale piu' di una scansione bloccata.
    """
    for segnale in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(processo.pid), segnale)
        except (ProcessLookupError, PermissionError):
            break
        try:
            processo.wait(timeout=ATTESA_TERMINAZIONE_SECONDI)
            break
        except subprocess.TimeoutExpired:
            continue

    try:
        return processo.communicate(timeout=ATTESA_TERMINAZIONE_SECONDI)
    except subprocess.TimeoutExpired:
        logger.warning("tool_output_perso", pid=processo.pid)
        processo.kill()
        return b"", b""


def run_command(
    binary: str,
    args: Sequence[str],
    *,
    allow_flags: Sequence[str] = (),
    timeout: int | None = None,
    cwd: Path | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    memory_limit_mb: int = 2048,
    cpu_seconds: int = 3000,
    stdin_data: bytes | None = None,
) -> CommandResult:
    """Esegue un tool esterno con tutte le protezioni attive."""
    import time

    command = build_command(binary, args, allow_flags=allow_flags)
    env = {key: os.environ[key] for key in _ALLOWED_ENV_KEYS if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    effective_timeout = timeout or settings.scan_default_timeout

    logger.info("tool_exec", binary=binary, arg_count=len(command) - 1, timeout=effective_timeout)
    started = time.monotonic()
    # `subprocess.run(timeout=...)` non basta. Alla scadenza uccide il figlio
    # diretto e poi rilegge le pipe fino alla fine del flusso: un tool che
    # lancia altri processi — testssl.sh lancia `openssl` — lascia i nipoti
    # vivi con le pipe aperte, e quella lettura non finisce mai. Un timeout di
    # dieci minuti e' arrivato cosi' a durarne oltre duecento.
    #
    # Il processo parte quindi in una sessione propria, e alla scadenza si
    # termina l'intero gruppo: nessun discendente resta a tenere aperte le
    # pipe.
    processo = subprocess.Popen(  # noqa: S603 - shell=False, argv validato
        command,
        stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
        env=env,
        shell=False,
        start_new_session=True,
        preexec_fn=lambda: _child_limits(memory_limit_mb, cpu_seconds),
    )
    try:
        stdout_grezzo, stderr_grezzo = processo.communicate(
            input=stdin_data, timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        stdout_grezzo, stderr_grezzo = _termina_gruppo(processo)
        durata = time.monotonic() - started
        logger.warning("tool_timeout", binary=binary, timeout=effective_timeout,
                       duration=round(durata, 1))
        return CommandResult(
            exit_code=-1,
            stdout=stdout_grezzo[:max_output_bytes],
            stderr=stderr_grezzo[:65536],
            timed_out=True,
            duration_seconds=durata,
        )

    completed = subprocess.CompletedProcess(
        command, processo.returncode, stdout_grezzo, stderr_grezzo)

    # Uno strumento che esce male senza produrre nulla e' indistinguibile, nei
    # log, da uno che ha funzionato e non ha trovato niente: entrambi
    # arrivavano come «riuscito, zero risultati». Il codice di uscita e la
    # prima riga di stderr vanno registrati, altrimenti un guasto resta
    # invisibile finche' qualcuno non nota che quell'area e' sempre vuota.
    if processo.returncode not in (0, None):
        # Anche stdout: diversi strumenti scrivono li' l'errore di
        # interpretazione degli argomenti, e senza quella riga il guasto
        # resta senza causa. E' la situazione in cui si trova httpx, che esce
        # con codice 1 senza scrivere nulla su stderr.
        logger.warning("tool_failed", binary=binary, exit_code=processo.returncode,
                       stderr=prima_riga(stderr_grezzo),
                       stdout=prima_riga(stdout_grezzo))

    duration = time.monotonic() - started
    stdout = completed.stdout or b""
    truncated = len(stdout) > max_output_bytes
    if truncated:
        logger.warning("tool_output_truncated", binary=binary, bytes=len(stdout))
        stdout = stdout[:max_output_bytes]
    return CommandResult(
        exit_code=completed.returncode,
        stdout=stdout,
        stderr=(completed.stderr or b"")[:65536],
        timed_out=False,
        duration_seconds=duration,
        truncated=truncated,
    )


def tool_version(binary: str, version_flag: str = "-version") -> str | None:
    """Legge la versione del tool. Registrata in ogni ToolRun per tracciabilita'."""
    try:
        result = run_command(binary, [version_flag], allow_flags=[version_flag], timeout=20)
    except (FileNotFoundError, UnsafeCommandError):
        return None
    output = (result.stdout or result.stderr).decode("utf-8", errors="replace").strip()
    return output.splitlines()[0][:64] if output else None


def is_available(binary: str) -> bool:
    return shutil.which(binary) is not None


class TemporaryWorkspace:
    """Directory temporanea con quota logica, cancellata sempre al termine."""

    def __init__(self, prefix: str = "defenix-") -> None:
        self.prefix = prefix
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self.path = Path(tempfile.mkdtemp(prefix=self.prefix))
        self.path.chmod(0o700)
        return self.path

    def __exit__(self, *_exc: object) -> None:
        if self.path and self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)
        self.path = None


def read_output_file(path: Path, max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES) -> bytes:
    """Legge un file di output prodotto da un tool applicando il limite di dimensione."""
    if not path.is_file():
        return b""
    size = path.stat().st_size
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
    if size > max_bytes:
        logger.warning("output_file_truncated", path=str(path), size=size, limit=max_bytes)
    return data
