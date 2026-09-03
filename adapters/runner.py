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
    os.setsid()


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
    try:
        completed = subprocess.run(  # noqa: S603 - shell=False, argv validato
            command,
            input=stdin_data,
            capture_output=True,
            timeout=effective_timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
            shell=False,
            check=False,
            preexec_fn=lambda: _child_limits(memory_limit_mb, cpu_seconds),
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        logger.warning("tool_timeout", binary=binary, timeout=effective_timeout)
        return CommandResult(
            exit_code=-1,
            stdout=(exc.stdout or b"")[:max_output_bytes],
            stderr=(exc.stderr or b"")[:65536],
            timed_out=True,
            duration_seconds=duration,
        )

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
