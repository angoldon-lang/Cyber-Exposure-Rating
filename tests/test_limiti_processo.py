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
