"""Gli strumenti si configurano dall'interfaccia, e i valori restano dentro.

La schermata «Strumenti» descriveva cosa serviva senza permettere di
fornirlo: per attivare uno strumento occorreva accedere al server, modificare
`.env` e riavviare i contenitori. Chi usa la piattaforma non ha
necessariamente quell'accesso.

Conservare chiavi di terzi impone due vincoli che questi test presidiano: il
valore non lascia mai il server, e sul disco non c'e' in chiaro.
"""
from __future__ import annotations

import pytest

from app.core.segreti import cifra, decifra
from app.models.configurazione import ToolSetting
from app.services import tool_config
from tests.test_company_crud import admin, client, tenant_unico  # noqa: F401

pytestmark = pytest.mark.security

CHIAVE = "chiave-di-prova-molto-segreta-42"


# --------------------------------------------------------------------- cifra
def test_il_valore_non_finisce_in_chiaro_nel_database(db_session):
    tool_config.imposta(db_session, "HIBP_API_KEY", CHIAVE, utente_id=None)
    db_session.flush()

    riga = db_session.query(ToolSetting).filter_by(variable="HIBP_API_KEY").one()
    assert CHIAVE.encode() not in riga.value_encrypted
    assert decifra(riga.value_encrypted) == CHIAVE


def test_due_cifrature_dello_stesso_valore_sono_diverse():
    """Fernet include un vettore casuale: due righe uguali non si riconoscono
    come tali guardando il database."""
    assert cifra(CHIAVE) != cifra(CHIAVE)
    assert decifra(cifra(CHIAVE)) == CHIAVE


def test_un_valore_non_piu_decifrabile_non_fa_esplodere_la_schermata():
    """Succede se `JWT_SECRET_KEY` cambia: lo strumento risulta non
    configurato, che e' la verita', invece di rompere la pagina."""
    assert decifra(b"non-e-un-token-fernet") is None


# ------------------------------------------------------------------ priorita'
def test_il_valore_impostato_ha_la_precedenza_sull_ambiente(db_session, monkeypatch):
    """Chi salva una chiave nella schermata si aspetta che valga. Se
    prevalesse `.env`, la schermata direbbe «impostata» e lo strumento
    userebbe un'altra chiave."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "hibp_api_key", "quella-del-file-env")
    assert tool_config.valori_effettivi(db_session)["HIBP_API_KEY"] == "quella-del-file-env"
    assert tool_config.origine(db_session)["HIBP_API_KEY"] == "ambiente"

    tool_config.imposta(db_session, "HIBP_API_KEY", CHIAVE, utente_id=None)
    db_session.flush()

    assert tool_config.valori_effettivi(db_session)["HIBP_API_KEY"] == CHIAVE
    assert tool_config.origine(db_session)["HIBP_API_KEY"] == "interfaccia"


def test_rimuovendo_il_valore_torna_quello_dell_ambiente(db_session, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "hibp_api_key", "quella-del-file-env")
    tool_config.imposta(db_session, "HIBP_API_KEY", CHIAVE, utente_id=None)
    db_session.flush()
    assert tool_config.rimuovi(db_session, "HIBP_API_KEY") is True
    db_session.flush()

    assert tool_config.valori_effettivi(db_session)["HIBP_API_KEY"] == "quella-del-file-env"


# ------------------------------------------------------------------ allowlist
def test_si_scrivono_solo_le_variabili_previste(db_session):
    """Senza elenco chiuso l'endpoint diventerebbe una scrittura arbitraria
    nella configurazione della piattaforma."""
    with pytest.raises(ValueError):
        tool_config.imposta(db_session, "DATABASE_URL",
                            "postgresql://altrove", utente_id=None)
    with pytest.raises(ValueError):
        tool_config.imposta(db_session, "JWT_SECRET_KEY", "x", utente_id=None)


def test_un_valore_vuoto_viene_rifiutato(db_session):
    with pytest.raises(ValueError):
        tool_config.imposta(db_session, "HIBP_API_KEY", "   ", utente_id=None)


# ------------------------------------------------------------------------ API
def test_l_api_non_restituisce_mai_il_valore(client, admin):  # noqa: F811
    risposta = client.put("/api/v1/tool-status/HIBP_API_KEY",
                          json={"value": CHIAVE}, headers=admin)
    assert risposta.status_code == 204, risposta.text

    stato = client.get("/api/v1/tool-status", headers=admin)
    assert stato.status_code == 200
    assert CHIAVE not in stato.text, "la chiave e' tornata indietro dall'API"

    strumenti = {s["key"]: s for s in stato.json()["tools"]}
    requisito = next(r for r in strumenti["hibp"]["requirements"]
                     if r["variable"] == "HIBP_API_KEY")
    assert requisito["present"] is True
    assert requisito["source"] == "interfaccia"
    assert "value" not in requisito


def test_l_api_rifiuta_una_variabile_non_prevista(client, admin):  # noqa: F811
    risposta = client.put("/api/v1/tool-status/DATABASE_URL",
                          json={"value": "postgresql://altrove"}, headers=admin)
    assert risposta.status_code == 400


def test_il_registro_di_audit_non_contiene_il_valore(client, admin):  # noqa: F811
    """Un registro di audit lo leggono piu' persone di quante debbano vedere
    una chiave."""
    from sqlalchemy import select

    from app.models.audit import AuditLog

    client.put("/api/v1/tool-status/HIBP_API_KEY", json={"value": CHIAVE},
               headers=admin)

    with client.session_factory() as db:
        righe = db.execute(select(AuditLog).where(
            AuditLog.entity_type == "tool_setting")).scalars().all()
    assert righe, "l'operazione non e' stata registrata"
    for riga in righe:
        assert CHIAVE not in (riga.message or "")
        assert "HIBP_API_KEY" in (riga.message or "")


def test_serve_il_permesso_di_scrittura_sui_connettori(client):  # noqa: F811
    risposta = client.put("/api/v1/tool-status/HIBP_API_KEY", json={"value": CHIAVE})
    assert risposta.status_code in (401, 403)
