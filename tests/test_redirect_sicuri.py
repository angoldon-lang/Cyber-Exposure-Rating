"""Redirect verso fonti di intelligence: seguiti, ma sempre rivalutati.

Rifiutarli del tutto rendeva irraggiungibili servizi legittimi
(`api.ransomware.live` risponde 302, RDAP rimanda al registro competente);
seguirli alla cieca permetterebbe a una risposta di dirottare la richiesta
verso la rete interna.
"""
from __future__ import annotations

import httpx
import pytest

from adapters.http_sicuro import (
    RedirectNonConsentito,
    destinazione_consentita,
    get_seguendo_redirect,
)

pytestmark = pytest.mark.security


def _client(gestore) -> httpx.Client:  # noqa: ANN001
    return httpx.Client(transport=httpx.MockTransport(gestore), follow_redirects=False)


def test_segue_un_redirect_legittimo():
    """Il caso reale: 302 verso lo stesso servizio."""
    def gestore(richiesta: httpx.Request) -> httpx.Response:
        if richiesta.url.path == "/recentvictims":
            return httpx.Response(302, headers={"location": "https://api.ransomware.live/recent"})
        return httpx.Response(200, json={"ok": True})

    with _client(gestore) as client:
        risposta = get_seguendo_redirect(
            client, "https://api.ransomware.live/recentvictims")
    assert risposta.status_code == 200
    assert risposta.json() == {"ok": True}


@pytest.mark.parametrize("destinazione", [
    "http://127.0.0.1:8000/admin",
    "http://localhost/interno",
    "http://169.254.169.254/latest/meta-data/",   # metadata del cloud provider
    "http://10.0.0.5/interno",
    "http://192.168.1.1/",
])
def test_blocca_i_redirect_verso_destinazioni_interne(destinazione):
    """Una risposta non deve poter dirottare la richiesta dentro la rete."""
    def gestore(richiesta: httpx.Request) -> httpx.Response:
        if "ransomware.live" in str(richiesta.url):
            return httpx.Response(302, headers={"location": destinazione})
        raise AssertionError(f"il salto verso {richiesta.url} non doveva essere percorso")

    with _client(gestore) as client, pytest.raises(RedirectNonConsentito):
        get_seguendo_redirect(client, "https://api.ransomware.live/x")


def test_interrompe_gli_anelli_di_redirect():
    def gestore(richiesta: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://api.ransomware.live/anello"})

    with _client(gestore) as client, pytest.raises(RedirectNonConsentito) as errore:
        get_seguendo_redirect(client, "https://api.ransomware.live/anello")
    assert "redirect consecutivi" in str(errore.value)


def test_risolve_le_destinazioni_relative():
    def gestore(richiesta: httpx.Request) -> httpx.Response:
        if richiesta.url.path == "/a":
            return httpx.Response(301, headers={"location": "/b"})
        assert richiesta.url.path == "/b"
        return httpx.Response(200, json={"ok": True})

    with _client(gestore) as client:
        assert get_seguendo_redirect(
            client, "https://rdap.org/a").status_code == 200


def test_una_risposta_normale_non_e_toccata():
    def gestore(richiesta: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"domini": []})

    with _client(gestore) as client:
        assert get_seguendo_redirect(client, "https://rdap.org/x").json() == {"domini": []}


def test_blocca_un_nome_pubblico_che_risolve_alla_rete_interna(monkeypatch):
    """DNS rebinding: il nome sembra pubblico, l'indirizzo no.

    E' il caso che la validazione permissiva sui nomi non risolvibili poteva
    indebolire: quando il risolutore risponde, la risposta va guardata.
    """
    monkeypatch.setattr("adapters.http_sicuro.resolve_hostname",
                        lambda host: ["10.0.0.7"])
    consentito, motivo = destinazione_consentita("https://sembra-pubblico.example/x")
    assert not consentito
    assert "non pubblico" in motivo


def test_consente_un_nome_che_risolve_a_indirizzo_pubblico(monkeypatch):
    monkeypatch.setattr("adapters.http_sicuro.resolve_hostname",
                        lambda host: ["93.184.216.34"])
    consentito, _ = destinazione_consentita("https://api.ransomware.live/x")
    assert consentito


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://interno/",
    "https://utente:segreto@api.esempio.example/x",
    "https://localhost/interno",
    "https://metadata.google.internal/computeMetadata/v1/",
])
def test_destinazioni_sempre_rifiutate(url):
    consentito, _ = destinazione_consentita(url)
    assert not consentito, f"{url} non doveva essere consentito"


# --------------------------------------------------------------------------
# Evidenze grezze non conservate
# --------------------------------------------------------------------------
def test_la_perdita_di_evidenze_grezze_e_riportata(monkeypatch):
    """Un permesso mancante sul volume non deve restare confinato nei log.

    L'evidenza grezza dimostra da dove viene un rilievo: se non viene
    conservata, chi legge il dettaglio della scansione deve saperlo.
    """
    import errno
    import uuid as _uuid
    from types import SimpleNamespace

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.models import Base
    from app.models.scanning import Scan
    from app.services import persistence

    monkeypatch.setattr(persistence, "store_raw_output",
                        lambda *a, **k: (_ for _ in ()).throw(
                            OSError(errno.EACCES, "Permission denied")))

    motore = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool, future=True)
    Base.metadata.create_all(motore)
    with sessionmaker(bind=motore, future=True)() as db:
        scan = Scan(tenant_id=_uuid.uuid4(), company_id=_uuid.uuid4(),
                    profile_key="public_passive", status="running", mock_mode=True)
        db.add(scan)
        db.flush()

        esito = SimpleNamespace(
            tool_runs=[{"tool_key": "dns", "status": "success", "target_count": 1},
                       {"tool_key": "kev", "status": "success", "target_count": 0}],
            raw_outputs={"dns": b"contenuto grezzo", "kev": b"altro"})
        _, persi = persistence._persist_tool_runs(db, scan, esito)

    assert persi == ["dns", "kev"], "gli strumenti con evidenza persa vanno riportati tutti"
    motore.dispose()


def test_il_messaggio_indica_come_rimediare():
    """Chi legge il dettaglio deve sapere anche cosa fare."""
    import inspect

    from app.services import persistence

    sorgente = inspect.getsource(persistence.persist_outcome)
    assert "raw_evidence_not_stored" in sorgente
    assert "fix-evidence-perms" in sorgente
    assert "I rilievi restano validi" in sorgente
