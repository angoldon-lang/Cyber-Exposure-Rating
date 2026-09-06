"""Una scansione deve finire.

Il tetto complessivo era dichiarato in `config/tool_profiles.yaml` e non
applicato da nessuna parte. Bastava uno strumento lento su molti bersagli —
testssl.sh su venticinque host, dieci minuti ciascuno, in sequenza — perche'
la scansione restasse in corso per ore, ferma sulla stessa percentuale,
senza che nulla fosse andato storto.
"""
from __future__ import annotations

import time

import pytest

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter

pytestmark = pytest.mark.security


class AdapterLento(BaseAdapter):
    key = "lento"
    display_name = "Strumento lento"
    is_passive = True
    coverage_areas = ()

    def check_available(self):  # noqa: ANN201
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        time.sleep(0.2)
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS)

    def mock(self) -> AdapterResult:
        return self.execute()


def _pipeline(budget: float):  # noqa: ANN202
    from app.workers.pipeline import ScanPipeline, ScanRequest

    pipeline = ScanPipeline(ScanRequest(
        scan_id="s", tenant_id="t", company_id="c", company_name="ACME",
        profile="public_passive", domains=["acme-test.example"], mock_mode=True))
    pipeline.budget_secondi = budget
    return pipeline


# --------------------------------------------------------- tetto complessivo
def test_il_tetto_e_letto_dalla_configurazione():
    """Il valore vive nella configurazione, non nel codice."""
    from adapters.registry import global_limits

    from app.workers.pipeline import ScanPipeline, ScanRequest

    atteso = float(global_limits()["max_wall_clock_seconds"])
    pipeline = ScanPipeline(ScanRequest(
        scan_id="s", tenant_id="t", company_id="c", company_name="ACME",
        profile="public_passive", domains=["acme-test.example"], mock_mode=True))
    assert pipeline.budget_secondi == atteso


def test_gli_strumenti_non_partiti_diventano_lacune_dichiarate():
    """La scansione finisce e il report dice cosa non e' stato controllato,
    invece di restare in corso indefinitamente."""
    pipeline = _pipeline(budget=60)
    pipeline._scadenza = time.monotonic() - 1  # tempo gia' esaurito

    contesto = pipeline.build_context()
    esito = pipeline._esegui_entro_il_budget(AdapterLento(contesto))

    assert esito.status is AdapterStatus.SKIPPED
    assert "tempo massimo della scansione" in (esito.error_message or "")
    assert esito.coverage_impact > 0, (
        "una lacuna che non riduce la copertura rende il rating fuorviante")


def test_uno_strumento_avviato_in_tempo_viene_eseguito():
    pipeline = _pipeline(budget=60)
    pipeline._scadenza = time.monotonic() + 60

    esito = pipeline._esegui_entro_il_budget(AdapterLento(pipeline.build_context()))
    assert esito.status is AdapterStatus.SUCCESS


def test_lo_strumento_non_riceve_piu_tempo_di_quanto_ne_resta():
    """Un timeout piu' lungo del tempo residuo sfonderebbe il tetto proprio
    sull'ultimo strumento."""
    pipeline = _pipeline(budget=60)
    pipeline._scadenza = time.monotonic() + 40

    contesto = pipeline.build_context()
    adattatore = AdapterLento(contesto)
    adattatore.config = {"timeout_seconds": 600}
    pipeline._esegui_entro_il_budget(adattatore)
    assert adattatore.config["timeout_seconds"] <= 40


def test_una_scansione_completa_resta_entro_il_tetto():
    """Verifica sull'esito, non sul meccanismo."""
    pipeline = _pipeline(budget=120)
    inizio = time.monotonic()
    esito = pipeline.run()
    assert time.monotonic() - inizio < 120
    assert esito.status in {"completed", "partial"}


# ------------------------------------------------------------------ testssl
def test_testssl_ha_un_tetto_proprio():
    """Senza, un solo strumento consuma da solo tutto il tempo della
    scansione e tutti gli altri diventano lacune."""
    from app.core.config import load_yaml_config

    definizione = load_yaml_config("tool_profiles")["tools"]["testssl"]
    budget = definizione["total_budget_seconds"]
    complessivo = load_yaml_config("tool_profiles")["global_limits"]["max_wall_clock_seconds"]

    assert budget < complessivo, (
        "il tetto dello strumento deve lasciare tempo agli altri")
    assert definizione["timeout_seconds"] * definizione["max_targets"] > budget, (
        "fixture non rappresentativa: senza il tetto lo strumento non sforerebbe")


def test_testssl_dichiara_gli_host_non_verificati():
    """Interrompere in silenzio farebbe sembrare controllati host che non lo
    sono: e' la differenza fra «TLS a posto» e «TLS non guardato»."""
    import inspect

    from adapters.testssl_adapter import TestSSLAdapter

    sorgente = inspect.getsource(TestSSLAdapter.execute)
    assert "non_analizzati" in sorgente
    assert "non sono stati verificati" in sorgente
    assert "(failures + non_analizzati)" in sorgente, (
        "gli host non analizzati devono pesare sulla copertura come quelli falliti")


# ------------------------------------------------------------------- broker
def test_il_broker_non_riconsegna_una_scansione_in_corso():
    """Redis riconsegna dopo un'ora: una scansione piu' lunga veniva
    riaccodata mentre era ancora in esecuzione."""
    from app.core.config import settings
    from app.workers.celery_app import celery_app

    visibilita = celery_app.conf.broker_transport_options["visibility_timeout"]
    assert visibilita > settings.celery_task_time_limit
