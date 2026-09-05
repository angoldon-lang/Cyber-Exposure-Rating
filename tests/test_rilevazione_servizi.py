"""Rilevazione dei servizi TCP sugli indirizzi autorizzati.

Naabu non pubblica binari per linux/arm64: sulle macchine Apple Silicon il
binario non e' nel worker, l'adapter si dichiara non disponibile e il port
scanning non parte mai. Il profilo Extended risultava completo senza aver mai
guardato una porta.
"""
from __future__ import annotations

import socket
import threading

import pytest

from adapters.base import AdapterStatus
from adapters.port_scan_adapter import PortScanAdapter

pytestmark = pytest.mark.security


@pytest.fixture
def porta_in_ascolto():
    """Un servizio vero su loopback: la sonda va provata contro un socket."""
    presa = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    presa.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    presa.bind(("127.0.0.1", 0))
    presa.listen(8)
    porta = presa.getsockname()[1]

    def accetta() -> None:
        while True:
            try:
                connessione, _ = presa.accept()
                connessione.close()
            except OSError:
                return

    thread = threading.Thread(target=accetta, daemon=True)
    thread.start()
    yield porta
    presa.close()


def _contesto_locale(adapter_context, porte: list[int]):  # noqa: ANN001
    """Perimetro che ammette il loopback, come farebbe un IP autorizzato."""
    from app.models.enums import ScopeEntryType
    from app.services.scope_guard import ScopeEntry, ScopeGuard

    adapter_context.profile = "verified_extended"
    adapter_context.mock_mode = False
    adapter_context.ip_addresses = ["127.0.0.1"]
    adapter_context.scope_guard = ScopeGuard(
        [ScopeEntry(ScopeEntryType.IP_ADDRESS.value, "127.0.0.1")], allow_private=True)
    adapter_context.tool_config = {
        "port_scan": {"default_ports": porte, "connect_timeout_seconds": 1.0,
                      "rate_limit_per_second": 1000, "timeout_seconds": 30}}
    return adapter_context


@pytest.fixture
def porta_sensibile(monkeypatch, porta_in_ascolto):
    """Fa considerare sensibile la porta effimera del test.

    Le porte effimere non sono nell'elenco dei servizi da segnalare: senza
    questo, i confronti fra evidenze girerebbero su insiemi vuoti e
    passerebbero comunque, senza verificare nulla.
    """
    from adapters.phase2 import NaabuAdapter

    monkeypatch.setitem(NaabuAdapter.SENSITIVE_PORTS, porta_in_ascolto, "Servizio di prova")
    return porta_in_ascolto


def _porta_chiusa() -> int:
    presa = socket.socket()
    presa.bind(("127.0.0.1", 0))
    porta = presa.getsockname()[1]
    presa.close()
    return porta


# ------------------------------------------------------------------ sonda
def test_riconosce_una_porta_aperta_e_una_chiusa(adapter_context, porta_in_ascolto):
    chiusa = _porta_chiusa()
    contesto = _contesto_locale(adapter_context, [porta_in_ascolto, chiusa])
    esito = PortScanAdapter(contesto).execute()

    assert esito.status is AdapterStatus.SUCCESS
    trovate = {int(a.attributes["port"]) for a in esito.assets}
    assert trovate == {porta_in_ascolto}, (
        f"attesa solo la porta {porta_in_ascolto}, trovate {sorted(trovate)}")


def test_le_evidenze_coincidono_con_quelle_di_naabu(adapter_context, porta_sensibile):
    """Le due fonti descrivono lo stesso fatto: se le impronte divergessero,
    lo stesso servizio esposto verrebbe detratto due volte dal rating."""
    from adapters.phase2 import NaabuAdapter

    contesto = _contesto_locale(adapter_context, [porta_sensibile])
    nostre = PortScanAdapter(contesto).execute()
    da_naabu, _ = NaabuAdapter(contesto)._build(
        [{"ip": "127.0.0.1", "port": porta_sensibile, "service": None, "product": None}])

    assert da_naabu, "fixture non rappresentativa: nessuna evidenza da confrontare"
    assert {e.fingerprint for e in nostre.evidences} == {e.fingerprint for e in da_naabu}


def test_una_porta_amministrativa_produce_un_rilievo_critico(adapter_context):
    """La porta 22 su un indirizzo pubblico e' l'esito che deve emergere."""
    from adapters.phase2 import NaabuAdapter

    evidenze, _ = NaabuAdapter(adapter_context)._build(
        [{"ip": "203.0.113.10", "port": 22, "service": None, "product": None}])
    assert [e.finding_type for e in evidenze] == ["remote_admin_service_exposed"]
    assert evidenze[0].severity == "critical"


# ------------------------------------------------------------ autorizzazione
def test_non_sonda_indirizzi_senza_autorizzazione(adapter_context, porta_in_ascolto):
    """L'autorizzazione resta l'unico cancello: questo adapter non ne apre un
    secondo. Senza voce di perimetro, nessuna connessione parte."""
    from app.services.scope_guard import ScopeGuard

    contesto = _contesto_locale(adapter_context, [porta_in_ascolto])
    contesto.scope_guard = ScopeGuard([], allow_private=True)
    esito = PortScanAdapter(contesto).execute()

    assert esito.status is AdapterStatus.SKIPPED
    assert "autorizzazione esplicita" in (esito.error_message or "")
    assert not esito.assets


def test_ammesso_solo_nel_profilo_extended(adapter_context):
    adapter_context.profile = "verified_standard"
    disponibile, motivo = PortScanAdapter(adapter_context).check_available()
    assert not disponibile
    assert "Verified Extended" in motivo


def test_uno_solo_dei_due_strumenti_gira(adapter_context, monkeypatch):
    """Farli girare entrambi raddoppierebbe le connessioni verso il cliente
    per ottenere gli stessi rilievi."""
    adapter_context.profile = "verified_extended"
    monkeypatch.setattr("adapters.runner.is_available", lambda _b: True)
    disponibile, motivo = PortScanAdapter(adapter_context).check_available()
    assert not disponibile
    assert "Naabu e' presente" in motivo

    monkeypatch.setattr("adapters.runner.is_available", lambda _b: False)
    assert PortScanAdapter(adapter_context).check_available()[0]


# ------------------------------------------------------------------ profili
def test_disponibile_nel_profilo_extended_e_solo_li():
    from adapters.registry import tools_for_profile

    assert "port_scan" in tools_for_profile("verified_extended")
    assert "port_scan" not in tools_for_profile("public_passive")
    assert "port_scan" not in tools_for_profile("verified_standard")


def test_la_pipeline_lo_esegue():
    import inspect

    from app.workers import pipeline

    assert '"port_scan"' in inspect.getsource(pipeline.ScanPipeline.run)


def test_le_porte_fuori_intervallo_sono_scartate(adapter_context):
    contesto = _contesto_locale(adapter_context, [0, 22, 70000, 443])
    assert PortScanAdapter(contesto).porte == (22, 443)


def test_la_provenienza_del_rilievo_e_lo_strumento_che_lo_ha_prodotto(adapter_context,
                                                                      porta_sensibile):
    """Dichiarare «rilevato da naabu» su una macchina dove Naabu non e'
    installato renderebbe il rilievo non verificabile."""
    contesto = _contesto_locale(adapter_context, [porta_sensibile])
    esito = PortScanAdapter(contesto).execute()
    assert esito.evidences
    assert {e.tool for e in esito.evidences} == {"port_scan"}
    assert {a.discovered_by for a in esito.assets} == {"port_scan"}


def test_riscrivere_la_provenienza_non_cambia_l_impronta(adapter_context, porta_sensibile):
    """La deduplicazione fra le due fonti dipende da questo: se l'impronta
    contenesse lo strumento, lo stesso servizio verrebbe contato due volte."""
    from adapters.phase2 import NaabuAdapter

    contesto = _contesto_locale(adapter_context, [porta_sensibile])
    aperte = [{"ip": "127.0.0.1", "port": porta_sensibile, "service": None, "product": None}]
    da_naabu, _ = NaabuAdapter(contesto)._build(aperte)
    nostre, _ = PortScanAdapter(contesto)._evidenze(aperte)

    assert da_naabu and nostre
    assert {e.fingerprint for e in nostre} == {e.fingerprint for e in da_naabu}
    assert {e.tool for e in nostre} != {e.tool for e in da_naabu}
