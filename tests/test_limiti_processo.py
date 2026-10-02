"""I limiti di risorse dichiarati devono essere applicati, ma non fino a
impedire l'avvio degli strumenti.

`process_memory_limit_mb` era scritto in `config/tool_profiles.yaml` e non
veniva letto da nessuno: un limite che sembrava operativo e non lo era.
Applicarlo alla lettera e' pero' pericoloso, perche' `RLIMIT_AS` limita lo
spazio di indirizzamento *virtuale*: il runtime Go ne riserva molto piu' della
memoria che usa davvero, e sotto il gigabyte i binari di ProjectDiscovery
muoiono prima di eseguire una riga.
"""
from __future__ import annotations

import pytest

from adapters.runner import MINIMO_SPAZIO_INDIRIZZI_MB, limiti_del_processo

pytestmark = pytest.mark.security


def test_i_limiti_arrivano_dalla_configurazione():
    """Senza indicazioni esplicite valgono i limiti globali del profilo."""
    from adapters.registry import global_limits

    memoria, cpu = limiti_del_processo()
    attesi = global_limits()

    assert memoria == max(int(attesi["process_memory_limit_mb"]), MINIMO_SPAZIO_INDIRIZZI_MB)
    assert cpu == int(attesi["process_cpu_seconds"])


def test_un_limite_troppo_stretto_viene_alzato_alla_soglia():
    memoria, _ = limiti_del_processo(memoria_mb=256, cpu_secondi=60)
    assert memoria == MINIMO_SPAZIO_INDIRIZZI_MB


def test_la_soglia_resta_sopra_il_minimo_misurato():
    """La soglia non e' un numero di comodo e non va abbassata.

    Misura su httpx 1.6.9 (linux/amd64), stesso binario che gira nel worker:

        RLIMIT_AS  512 MB -> uscita 2, «fatal error: failed to reserve page
                             summary memory», nessun output
        RLIMIT_AS 1024 MB -> parte e produce risultati

    Il valore non e' verificabile con l'interprete Python — CPython parte
    anche con 128 MB, perche' il vincolo e' delle arene riservate dal runtime
    Go, non del kernel. Questo test presidia la costante: se qualcuno la
    abbassa per «stringere i limiti», ogni strumento ProjectDiscovery
    fallirebbe senza una causa leggibile.
    """
    assert MINIMO_SPAZIO_INDIRIZZI_MB >= 1024


# --------------------------------------------------------------------------
def test_il_tetto_ai_processi_non_e_un_limite_per_strumento():
    """`RLIMIT_NPROC` non e' un limite per processo: il kernel lo conta sui
    thread dell'UTENTE REALE, in tutto il contenitore.

    Applicato al singolo strumento sembrava una protezione e non lo era: il
    budget risultava gia' speso da Celery, dai suoi worker e dagli strumenti
    di un'altra scansione in corso, e il binario Go appena partito moriva
    creando il proprio terzo thread. Misurato: con 240 thread dello stesso
    utente aperti altrove, un figlio con limite 256 ne crea 14 e poi
    fallisce; con l'utente libero ne crea 60 senza errori.

    La protezione contro la moltiplicazione resta, ma sul contenitore, dove
    puo' funzionare e dall'interno non si alza.
    """
    from pathlib import Path

    import yaml

    radice = Path(__file__).resolve().parents[1]
    runner = (radice / "adapters" / "runner.py").read_text(encoding="utf-8")
    righe_attive = [r for r in runner.splitlines()
                    if "RLIMIT_NPROC" in r and not r.strip().startswith("#")]

    assert not righe_attive, (
        "RLIMIT_NPROC e' tornato fra i limiti del singolo strumento: "
        f"{righe_attive}")

    compose = yaml.safe_load((radice / "docker-compose.yml").read_text(encoding="utf-8"))
    assert tetto_ai_processi(compose["services"]["worker"]), (
        "tolto il limite per strumento, il contenitore resta senza tetto ai processi")


def tetto_ai_processi(servizio: dict) -> int | None:
    """Il tetto ai processi dichiarato da un servizio, da qualunque dei due posti.

    Per Compose `pids_limit` e `deploy.resources.limits.pids` sono lo stesso
    campo scritto in due modi.
    """
    nel_deploy = (servizio.get("deploy", {}).get("resources", {})
                  .get("limits", {}).get("pids"))
    return servizio.get("pids_limit") or nel_deploy


def test_il_tetto_ai_processi_e_scritto_allo_stesso_valore_nei_due_posti():
    """Compose considera `pids_limit` e `deploy.resources.limits.pids` lo stesso
    campo, e dalla 5.x rifiuta l'intero progetto se non coincidono: con il solo
    `pids_limit` legge «non impostato» nell'altro e si ferma con «can't set
    distinct values», senza avviare niente.

    Il valore sta percio' in entrambi. Il test controlla che restino uguali, e
    che nessun altro servizio ne dichiari uno solo: una modifica a meta' non
    rompe un test applicativo, rompe `make up`.
    """
    from pathlib import Path

    import yaml

    radice = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((radice / "docker-compose.yml").read_text(encoding="utf-8"))

    for nome, servizio in compose["services"].items():
        diretto = servizio.get("pids_limit")
        nel_deploy = (servizio.get("deploy", {}).get("resources", {})
                      .get("limits", {}).get("pids"))
        if diretto is None and nel_deploy is None:
            continue
        assert diretto == nel_deploy, (
            f"il servizio '{nome}' dichiara pids_limit={diretto} e "
            f"deploy.resources.limits.pids={nel_deploy}: Compose rifiuta il progetto")
