"""Gli strumenti si configurano dall'interfaccia, e i valori restano dentro.

La schermata «Strumenti» descriveva cosa serviva senza permettere di
fornirlo: per attivare uno strumento occorreva accedere al server, modificare
`.env` e riavviare i contenitori. Chi usa la piattaforma non ha
necessariamente quell'accesso.

Conservare chiavi di terzi impone due vincoli che questi test presidiano: il
valore non lascia mai il server, e sul disco non c'e' in chiaro.
"""
from __future__ import annotations

from pathlib import Path

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


# ---------------------------------------------------------------------------
# Disfare una configurazione salvata
# ---------------------------------------------------------------------------
def test_si_puo_cancellare_un_valore_salvato_per_far_tornare_valido_env(db_session):
    """Il database ha la precedenza su `.env`. Senza un modo di cancellare, un
    indirizzo sbagliato salvato una volta dall'interfaccia resta in vigore per
    sempre, e l'unico rimedio era accedere a quella schermata -- cioe' proprio
    cio' che una configurazione sbagliata puo' impedire.
    """
    from app.services.tool_config import imposta, origine, rimuovi, valori_effettivi

    imposta(db_session, "SPIDERFOOT_URL", "http://127.0.0.1:5001/", utente_id=None)
    db_session.flush()
    assert origine(db_session)["SPIDERFOOT_URL"] == "interfaccia"

    assert rimuovi(db_session, "SPIDERFOOT_URL") is True
    db_session.flush()

    assert "SPIDERFOOT_URL" not in origine(db_session)
    assert "SPIDERFOOT_URL" not in valori_effettivi(db_session)


def test_cancellare_cio_che_non_era_salvato_lo_dice(db_session):
    """Restituire «fatto» farebbe credere di aver risolto, quando il valore in
    vigore arriva da `.env` e va corretto la'."""
    from app.services.tool_config import rimuovi

    assert rimuovi(db_session, "SPIDERFOOT_URL") is False


def test_il_comando_rifiuta_una_variabile_fuori_elenco():
    """L'elenco chiuso e' la stessa difesa della scrittura: senza, il comando
    diventerebbe una cancellazione arbitraria nella configurazione."""
    from app.services.tool_config import PER_NOME

    assert "PIPPO" not in PER_NOME
    cli = (Path(__file__).resolve().parents[1] / "backend" / "app" / "cli.py"
           ).read_text(encoding="utf-8")
    assert "dimentica not in PER_NOME" in cli


def test_una_chiave_del_contenitore_non_si_puo_salvare(db_session):
    """La precedenza rende questa scrittura un guasto, non una comodita': un
    valore nel database vince su `.env`, quindi il worker userebbe questa
    chiave e il contenitore la sua -- due chiavi diverse, e l'API risponde
    401 come se lo strumento fosse rotto. L'interfaccia non offre il campo,
    ma l'API resterebbe aperta."""
    import pytest

    from app.services import tool_config

    with pytest.raises(ValueError) as errore:
        tool_config.imposta(db_session, "THEHARVESTER_API_KEY", "una-chiave",
                            utente_id=None)

    assert ".env" in str(errore.value)
    assert "precedenza" in str(errore.value)


def test_una_riga_vecchia_nel_database_non_vince_sul_file(db_session):
    """Chi aveva impostato ZAP_API_KEY dall'interfaccia prima che la
    schermata smettesse di offrirlo ha una riga salvata che, per la regola
    della precedenza, vincerebbe su `.env` -- e il worker userebbe una
    chiave diversa da quella del demone. La riga si ignora, invece di
    lasciare due valori entrambi «impostati» e un 401 inspiegabile."""
    from datetime import UTC, datetime

    from app.core.segreti import cifra
    from app.models.configurazione import ToolSetting
    from app.services import tool_config

    db_session.add(ToolSetting(variable="ZAP_API_KEY",
                               value_encrypted=cifra("chiave-vecchia"),
                               updated_at=datetime.now(UTC)))
    db_session.flush()

    effettivi = tool_config.valori_effettivi(db_session)

    assert effettivi.get("ZAP_API_KEY") != "chiave-vecchia"
    assert tool_config.origine(db_session).get("ZAP_API_KEY") != "interfaccia"
