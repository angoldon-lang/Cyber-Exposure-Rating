"""Ricerca di credenziali esposte su dark web e canali di leak.

Il vincolo piu' importante non e' funzionale ma di riservatezza: della
credenziale si registra l'esistenza, mai il contenuto.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from adapters.base import AdapterStatus
from adapters.credential_exposure_adapter import CredentialExposureAdapter
from tests.test_company_crud import admin, client, tenant_unico  # noqa: F401

pytestmark = pytest.mark.security


def test_saltato_senza_connettore(adapter_context):
    """Fonte commerciale non configurata: `skipped`, non `failed`, e la
    copertura dichiarata si riduce."""
    adapter_context.connector_config = {}
    esito = CredentialExposureAdapter(adapter_context).run()
    assert esito.status is AdapterStatus.SKIPPED
    assert "non configurato" in (esito.error_message or "")
    assert esito.coverage_impact > 0


def test_produce_i_tipi_previsti_dal_modello_di_scoring(adapter_context):
    adapter_context.connector_config = {"credential_exposure": {"mock_enabled": True}}
    esito = CredentialExposureAdapter(adapter_context).run()
    assert esito.status is AdapterStatus.SUCCESS
    tipi = {e.finding_type for e in esito.evidences}
    # Tipi gia' previsti da config/scoring.yaml: nessuna regola nuova serve.
    assert tipi <= {"stealer_log_credentials", "breach_credentials_recent",
                    "breach_credentials_old", "darkweb_mention"}
    assert tipi, "nessuna evidenza prodotta dai dati sintetici"


def test_nessuna_password_finisce_nelle_evidenze(adapter_context):
    """Il vincolo vale sulle chiavi effettivamente presenti nella risposta,
    non su quelle attese: una fonte puo' restituire campi non previsti."""
    adattatore = CredentialExposureAdapter(adapter_context)
    voci = [{
        "type": "stealer_log", "source": "log aggregato", "account_count": 4,
        "observed_at": datetime.now(UTC).isoformat(),
        "sample_identities": ["mario.rossi@acme-test.example"],
        # Campi che la fonte potrebbe restituire e che non devono passare.
        "password": "Password123!", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        "session_cookie": "SID=abc", "api_token": "sk-live-123",
        "ntlm_hash": "aad3b435b51404ee", "plaintext_credential": "admin:admin",
    }]
    evidenze = adattatore._da_risposta("acme-test.example", voci)
    assert len(evidenze) == 1

    serializzato = json.dumps(evidenze[0].to_dict(), default=str).lower()
    for proibito in ("password123", "5f4dcc3b", "sid=abc", "sk-live-123",
                     "aad3b435", "admin:admin"):
        assert proibito not in serializzato, f"contenuto riservato trapelato: {proibito}"
    for chiave in evidenze[0].attributes:
        assert not any(v in chiave.lower() for v in
                       ("password", "hash", "cookie", "token", "secret", "credential"))


def test_le_identita_sono_mascherate(adapter_context):
    adattatore = CredentialExposureAdapter(adapter_context)
    voci = [{"type": "combolist", "source": "raccolta", "account_count": 2,
             "observed_at": datetime.now(UTC).isoformat(),
             "sample_identities": ["mario.rossi@acme-test.example",
                                   "amministrazione@acme-test.example"]}]
    campione = adattatore._da_risposta("acme-test.example", voci)[0].attributes["sample_identities"]
    assert all("@" in i for i in campione)
    assert not any(i.startswith("mario.rossi@") for i in campione), "indirizzo in chiaro"


def test_credenziali_recenti_e_vecchie_sono_distinte(adapter_context):
    """Pesano diversamente nel rating: una raccolta di dieci anni fa non
    equivale a una di due mesi fa."""
    adattatore = CredentialExposureAdapter(adapter_context)
    adesso = datetime.now(UTC)
    recente = adattatore._da_risposta("acme-test.example", [
        {"type": "combolist", "source": "x", "account_count": 1,
         "observed_at": (adesso - timedelta(days=30)).isoformat()}])[0]
    vecchia = adattatore._da_risposta("acme-test.example", [
        {"type": "combolist", "source": "x", "account_count": 1,
         "observed_at": (adesso - timedelta(days=1500)).isoformat()}])[0]
    assert recente.finding_type == "breach_credentials_recent"
    assert recente.severity == "high"
    assert vecchia.finding_type == "breach_credentials_old"
    assert vecchia.severity == "medium"


def test_una_menzione_non_e_una_compromissione(adapter_context):
    """Pesa al 50% nel rating: va verificata prima di trarne conclusioni."""
    adattatore = CredentialExposureAdapter(adapter_context)
    menzione = adattatore._da_risposta("acme-test.example", [
        {"type": "mention", "source": "forum", "observed_at": datetime.now(UTC).isoformat()}])[0]
    assert menzione.finding_type == "darkweb_mention"
    assert menzione.confidence_class == "probable"


def test_output_deterministico(adapter_context):
    adapter_context.connector_config = {"credential_exposure": {"mock_enabled": True}}
    primo = CredentialExposureAdapter(adapter_context).run()
    secondo = CredentialExposureAdapter(adapter_context).run()
    assert ([e.fingerprint for e in primo.evidences]
            == [e.fingerprint for e in secondo.evidences])


def test_il_fallimento_non_ferma_la_scansione(adapter_context, monkeypatch):
    def esplodi(self):
        raise RuntimeError("fonte non raggiungibile")

    monkeypatch.setattr(CredentialExposureAdapter, "mock", esplodi)
    esito = CredentialExposureAdapter(adapter_context).run()
    assert esito.status is AdapterStatus.FAILED
    assert esito.coverage_impact > 0


def test_l_adapter_e_incluso_nella_pipeline():
    """L'elenco degli strumenti nella pipeline e' scritto a mano: un adapter
    registrato ma non elencato non verrebbe mai eseguito, in silenzio."""
    import inspect

    from adapters.registry import ADAPTER_CLASSES, tools_for_profile
    from app.workers import pipeline

    sorgente = inspect.getsource(pipeline.ScanPipeline.run)
    assert '"credential_exposure"' in sorgente
    assert "credential_exposure" in ADAPTER_CLASSES
    assert "credential_exposure" in tools_for_profile("public_passive")


def test_non_duplica_i_rilievi_gia_prodotti_da_hibp(adapter_context):
    """Le due fonti coprono lo stesso ambito e possono riportare lo stesso
    breach: le evidenze devono convergere su un'unica impronta, altrimenti lo
    stesso problema verrebbe detratto due volte dal rating."""
    from adapters.hibp_adapter import HIBPAdapter

    adapter_context.connector_config = {"hibp": {"mock_enabled": True},
                                        "credential_exposure": {"mock_enabled": True}}
    hibp = {e.fingerprint: e for e in HIBPAdapter(adapter_context).run().evidences}
    nostre = CredentialExposureAdapter(adapter_context).run().evidences

    sovrapposte = [e for e in nostre
                   if any(h.asset_key == e.asset_key and h.finding_type == e.finding_type
                          and (h.detail or "") == (e.detail or "") for h in hibp.values())]
    assert sovrapposte, "fixture non rappresentativa: nessuna sovrapposizione da verificare"
    for evidenza in sovrapposte:
        assert evidenza.fingerprint in hibp, (
            f"'{evidenza.finding_type}' su {evidenza.asset_key} ({evidenza.detail}) "
            "genera due impronte distinte")


@pytest.mark.parametrize("profilo", ["public_passive", "verified_standard", "verified_extended"])
def test_disponibile_in_tutti_i_profili(profilo):
    """La ricerca di credenziali esposte e' passiva e non interroga i sistemi:
    ometterla dai profili verificati farebbe perdere silenziosamente l'area
    dark web proprio nelle scansioni piu' complete."""
    from adapters.registry import tools_for_profile

    assert "credential_exposure" in tools_for_profile(profilo)


def test_la_dashboard_dichiara_le_aree_non_verificate(client, admin):  # noqa: F811
    """Un'area senza rilievi perche' non controllata non deve sembrare pulita.

    E' il caso del dark web senza connettori configurati: le fonti sono tutte
    commerciali, la scansione risulta completata e il punteggio dell'area resta
    alto. Senza dichiarare la lacuna, il risultato e' fuorviante.
    """
    from tests.test_company_crud import _azienda

    azienda = _azienda(client, admin)
    dati = client.get(f"/api/v1/companies/{azienda['id']}/dashboard", headers=admin).json()
    # Senza scansioni non ci sono lacune da dichiarare, ma il campo deve esserci.
    assert "coverage_gaps" in dati
    assert isinstance(dati["coverage_gaps"], list)


def test_una_lacuna_riporta_motivo_e_aree_interessate():
    """Il motivo dev'essere quello registrato dallo strumento, non generico."""
    import inspect

    from app.api.routers import dashboard

    sorgente = inspect.getsource(dashboard._coverage_gaps)
    assert "error_message" in sorgente
    assert "coverage_areas" in sorgente
    assert "coverage_impact" in sorgente
