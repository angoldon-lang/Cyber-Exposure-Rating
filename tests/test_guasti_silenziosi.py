"""Uno strumento rotto non deve somigliare a un'area pulita.

`httpx` tornava «riuscito, zero risultati» sia quando funzionava e non
trovava nulla, sia quando il binario usciva in errore. Dal log non si
distinguevano, e un guasto restava invisibile finche' qualcuno non notava
che quell'area era sempre vuota.
"""
from __future__ import annotations

import re

import pytest

from adapters.base import AdapterStatus, BaseAdapter
from adapters.runner import CommandResult, prima_riga

pytestmark = pytest.mark.security

_SENZA_COLORI = re.compile(r"\x1b\[[0-9;]*m")


class _Strumento(BaseAdapter):
    key = "prova"
    coverage_areas = ()

    def check_available(self):  # noqa: ANN201
        return True, "disponibile"

    def execute(self):  # noqa: ANN201
        raise NotImplementedError


def _esito(**campi) -> CommandResult:  # noqa: ANN003
    predefiniti = {"exit_code": 0, "stdout": b"", "stderr": b"", "timed_out": False,
                   "duration_seconds": 1.0}
    return CommandResult(**{**predefiniti, **campi})


def test_uscita_in_errore_senza_risultati_e_un_fallimento(adapter_context):
    strumento = _Strumento(adapter_context)
    stato, motivo, impatto = strumento.esito_del_comando(
        _esito(exit_code=127, stderr=b"httpx: command not found\n"), prodotto=0)

    assert stato is AdapterStatus.FAILED
    assert "codice 127" in motivo and "command not found" in motivo
    assert impatto > 0, "un guasto deve ridurre la copertura dichiarata"


def test_uscita_in_errore_con_risultati_e_parziale(adapter_context):
    """Diversi strumenti usano un codice diverso da zero per dire «ho trovato
    qualcosa»: li' l'esito e' parziale, non fallito."""
    strumento = _Strumento(adapter_context)
    stato, motivo, _ = strumento.esito_del_comando(_esito(exit_code=1), prodotto=5)
    assert stato is AdapterStatus.PARTIAL
    assert motivo is not None


def test_zero_risultati_senza_errori_resta_un_successo(adapter_context):
    """Nessun host che risponde e' un esito legittimo, non un guasto."""
    strumento = _Strumento(adapter_context)
    stato, motivo, impatto = strumento.esito_del_comando(_esito(), prodotto=0)
    assert stato is AdapterStatus.SUCCESS
    assert motivo is None and impatto == 0.0


def test_il_timeout_senza_risultati_e_un_fallimento(adapter_context):
    strumento = _Strumento(adapter_context)
    stato, motivo, impatto = strumento.esito_del_comando(
        _esito(timed_out=True), prodotto=0)
    assert stato is AdapterStatus.FAILED
    assert "tempo massimo" in motivo
    assert impatto == strumento.coverage_weight


def test_lo_stderr_riportato_e_la_prima_riga_utile():
    assert prima_riga(b"\n\n  errore vero: file mancante\naltro\n") == (
        "errore vero: file mancante")
    assert prima_riga(b"") == ""


def test_il_messaggio_non_cresce_a_dismisura():
    """Lo stderr di un tool puo' essere lungo migliaia di righe."""
    assert len(prima_riga(b"x" * 5000)) <= 300


@pytest.mark.parametrize("modulo,funzione", [
    ("adapters.httpx_adapter", "HTTPXAdapter"),
    ("adapters.phase2", "NucleiAdapter"),
    ("adapters.phase2", "NaabuAdapter"),
])
def test_gli_strumenti_esterni_guardano_il_codice_di_uscita(modulo, funzione):
    """Regressione: l'esito era «riuscito» qualunque cosa fosse successo."""
    import importlib
    import inspect

    classe = getattr(importlib.import_module(modulo), funzione)
    sorgente = inspect.getsource(classe.execute)
    assert "esito_del_comando" in sorgente, (
        f"{funzione} non distingue un guasto da un'area vuota")


def test_il_comando_registra_il_guasto_nel_log(tmp_path, capsys):
    """Il log del worker e' spesso l'unica traccia disponibile.

    La registrazione passa da structlog e finisce su stdout, non dal modulo
    `logging`: va letta da li'.
    """
    from adapters.runner import run_command

    script = tmp_path / "fallisce.py"
    script.write_text("import sys\nsys.stderr.write('rotto\\n')\nsys.exit(3)\n",
                      encoding="utf-8")
    esito = run_command("python3", [str(script)], timeout=10)

    assert esito.exit_code == 3
    # Il renderer di structlog colora l'output quando il terminale lo
    # consente: le sequenze si infilano fra la chiave e il valore.
    registrato = _SENZA_COLORI.sub("", capsys.readouterr().out)
    assert "tool_failed" in registrato
    assert "exit_code=3" in registrato
    assert "rotto" in registrato, "senza lo stderr il guasto resta senza causa"
