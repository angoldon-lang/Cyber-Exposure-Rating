"""Gestione completa dell'azienda: modifica, archiviazione e cancellazione.

I test coprono i vincoli che rendono l'operazione sicura in un prodotto
multi-tenant: permessi, isolamento fra tenant, conferma esplicita della
cancellazione definitiva e tracciamento nel registro di audit.
"""
from __future__ import annotations

import uuid

import pytest

from tests.test_api import PASSWORD, _crea_utente, _login, client  # noqa: F401

pytestmark = pytest.mark.security


def _azienda(client, headers, slug: str | None = None) -> dict:  # noqa: F811
    slug = slug or f"acme-{uuid.uuid4().hex[:6]}"
    risposta = client.post("/api/v1/companies", headers=headers, json={
        "legal_name": "ACME Prova S.r.l.", "slug": slug, "country": "IT",
        "sector": "Manifatturiero"})
    assert risposta.status_code == 201, risposta.text
    return risposta.json()


def _utente_nel_tenant(db, tenant, email: str, role_name: str):
    """Aggiunge un utente a un tenant gia' esistente.

    Serve perche' i controlli sui permessi si vedono solo fra utenti dello
    stesso tenant: da tenant diversi la risposta e' 404, non 403, per non
    rivelare l'esistenza delle risorse altrui.
    """
    from app.core.rbac import ROLE_PERMISSIONS
    from app.core.security import hash_password
    from app.models.organization import Role, User

    ruolo = db.query(Role).filter(Role.name == role_name).one_or_none()
    if ruolo is None:
        ruolo = Role(name=role_name, permissions_json=sorted(ROLE_PERMISSIONS[role_name]))
        db.add(ruolo)
        db.flush()
    utente = User(tenant_id=tenant.id, email=email, full_name=email,
                  hashed_password=hash_password(PASSWORD), is_active=True)
    utente.roles.append(ruolo)
    db.add(utente)
    db.flush()
    return utente


@pytest.fixture
def tenant_unico(client):  # noqa: F811
    """Un tenant con i quattro ruoli che servono ai test."""
    with client.session_factory() as db:
        tenant, _, _ = _crea_utente(db, tenant_name="Tenant",
                                    email="admin@prova.example",
                                    role_name="platform_administrator")
        for email, ruolo in (("analista@prova.example", "security_analyst"),
                             ("cliente@prova.example", "customer_viewer")):
            _utente_nel_tenant(db, tenant, email, ruolo)
        db.commit()
    return tenant


@pytest.fixture
def admin(client, tenant_unico):  # noqa: F811
    return _login(client, "admin@prova.example")


@pytest.fixture
def analista(client, tenant_unico):  # noqa: F811
    return _login(client, "analista@prova.example")


@pytest.fixture
def cliente(client, tenant_unico):  # noqa: F811
    return _login(client, "cliente@prova.example")


# --------------------------------------------------------------------------
# Modifica
# --------------------------------------------------------------------------
def test_modifica_dei_dati_anagrafici(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    risposta = client.patch(f"/api/v1/companies/{azienda['id']}", headers=admin,
                            json={"legal_name": "ACME Rinominata S.p.A.",
                                  "sector": "Energia", "notes": "cliente storico"})
    assert risposta.status_code == 200, risposta.text
    aggiornata = risposta.json()
    assert aggiornata["legal_name"] == "ACME Rinominata S.p.A."
    assert aggiornata["sector"] == "Energia"
    # Lo slug non e' modificabile: e' l'identificativo stabile dell'azienda.
    assert aggiornata["slug"] == azienda["slug"]


def test_un_visualizzatore_non_puo_modificare(client, admin, cliente):  # noqa: F811
    azienda = _azienda(client, admin)
    risposta = client.patch(f"/api/v1/companies/{azienda['id']}", headers=cliente,
                            json={"legal_name": "Tentativo"})
    assert risposta.status_code == 403


# --------------------------------------------------------------------------
# Archiviazione
# --------------------------------------------------------------------------
def test_archiviazione_conserva_lo_storico(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    assert client.delete(f"/api/v1/companies/{azienda['id']}",
                         headers=admin).status_code == 204

    dettaglio = client.get(f"/api/v1/companies/{azienda['id']}", headers=admin)
    assert dettaglio.status_code == 200, "l'archiviazione non deve cancellare nulla"
    assert dettaglio.json()["is_active"] is False


def test_archiviare_due_volte_e_un_conflitto(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    client.delete(f"/api/v1/companies/{azienda['id']}", headers=admin)
    assert client.delete(f"/api/v1/companies/{azienda['id']}",
                         headers=admin).status_code == 409


def test_riattivazione(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    client.delete(f"/api/v1/companies/{azienda['id']}", headers=admin)
    risposta = client.patch(f"/api/v1/companies/{azienda['id']}", headers=admin,
                            json={"is_active": True})
    assert risposta.status_code == 200
    assert risposta.json()["is_active"] is True


# --------------------------------------------------------------------------
# Cancellazione definitiva
# --------------------------------------------------------------------------
def test_cancellazione_richiede_lo_slug_corretto(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    risposta = client.post(f"/api/v1/companies/{azienda['id']}/purge", headers=admin,
                           json={"confirm_slug": "slug-sbagliato", "reason": "prova"})
    assert risposta.status_code == 400
    assert azienda["slug"] in risposta.json()["detail"]
    assert client.get(f"/api/v1/companies/{azienda['id']}",
                      headers=admin).status_code == 200, "non deve aver cancellato nulla"


def test_cancellazione_riservata_al_platform_administrator(client, admin, analista):  # noqa: F811
    azienda = _azienda(client, admin)
    risposta = client.post(f"/api/v1/companies/{azienda['id']}/purge", headers=analista,
                           json={"confirm_slug": azienda["slug"], "reason": "prova"})
    assert risposta.status_code == 403


def test_cancellazione_definitiva_rimuove_i_dati_collegati(client, admin):  # noqa: F811
    """La cancellazione deve svuotare tutte le tabelle collegate all'azienda,
    non solo la riga principale: righe orfane sopravvissute a una richiesta di
    cancellazione sarebbero un problema, non un dettaglio."""
    from sqlalchemy import func, select

    from app.models.scope import Brand, Domain

    azienda = _azienda(client, admin)
    client.post(f"/api/v1/companies/{azienda['id']}/domains", headers=admin,
                json={"name": "acme-prova.example", "is_primary": True})
    with client.session_factory() as db:
        db.add(Brand(tenant_id=uuid.UUID(azienda["tenant_id"]),
                     company_id=uuid.UUID(azienda["id"]), name="ACME",
                     keywords_json=["acme"], monitor_lookalikes=True))
        db.commit()

    risposta = client.post(f"/api/v1/companies/{azienda['id']}/purge", headers=admin,
                           json={"confirm_slug": azienda["slug"],
                                 "reason": "richiesta di cancellazione del cliente"})
    assert risposta.status_code == 200, risposta.text
    esito = risposta.json()
    assert esito["deleted_rows"]["domains"] == 1
    assert esito["deleted_rows"]["brands"] == 1
    assert esito["total_rows"] >= 2

    assert client.get(f"/api/v1/companies/{azienda['id']}", headers=admin).status_code == 404
    with client.session_factory() as db:
        for modello in (Domain, Brand):
            rimaste = db.execute(select(func.count()).select_from(modello).where(
                modello.company_id == uuid.UUID(azienda["id"]))).scalar_one()
            assert rimaste == 0, f"righe orfane in {modello.__tablename__}"


def test_la_cancellazione_resta_nel_registro_di_audit(client, admin):  # noqa: F811
    """I dati spariscono, la prova che sono stati cancellati no."""
    from sqlalchemy import select

    from app.models.audit import AuditLog

    azienda = _azienda(client, admin)
    client.post(f"/api/v1/companies/{azienda['id']}/purge", headers=admin,
                json={"confirm_slug": azienda["slug"], "reason": "cessato contratto"})

    with client.session_factory() as db:
        righe = db.execute(select(AuditLog).where(
            AuditLog.entity_id == azienda["id"])).scalars().all()
    assert any("cessato contratto" in (r.message or "") for r in righe), \
        "la motivazione deve restare tracciata"


# --------------------------------------------------------------------------
# Isolamento fra tenant
# --------------------------------------------------------------------------
def test_non_si_cancella_l_azienda_di_un_altro_tenant(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="Altro", email="altro@prova.example",
                     role_name="platform_administrator")
        db.commit()
    estraneo = _login(client, "altro@prova.example")

    # 404 e non 403: non si rivela l'esistenza di risorse di altri tenant.
    assert client.delete(f"/api/v1/companies/{azienda['id']}",
                         headers=estraneo).status_code == 404
    assert client.post(f"/api/v1/companies/{azienda['id']}/purge", headers=estraneo,
                       json={"confirm_slug": azienda["slug"],
                             "reason": "x"}).status_code == 404
    assert client.get(f"/api/v1/companies/{azienda['id']}", headers=admin).status_code == 200


# --------------------------------------------------------------------------
# Domini e perimetro
# --------------------------------------------------------------------------
def test_aggiunta_e_rimozione_di_un_dominio(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    creato = client.post(f"/api/v1/companies/{azienda['id']}/domains", headers=admin,
                         json={"name": "acme-prova.example", "is_primary": True})
    assert creato.status_code == 201, creato.text
    dominio = creato.json()

    elenco = client.get(f"/api/v1/companies/{azienda['id']}/domains", headers=admin).json()
    assert [d["name"] for d in elenco] == ["acme-prova.example"]

    assert client.delete(f"/api/v1/companies/{azienda['id']}/domains/{dominio['id']}",
                         headers=admin).status_code == 204
    assert client.get(f"/api/v1/companies/{azienda['id']}/domains",
                      headers=admin).json() == []


def test_un_dominio_autorizzato_non_si_rimuove(client, admin):  # noqa: F811
    """Rimuoverlo scollegherebbe il perimetro registrato da quello autorizzato
    per iscritto: va prima revocata l'autorizzazione."""
    azienda = _azienda(client, admin)
    dominio = client.post(f"/api/v1/companies/{azienda['id']}/domains", headers=admin,
                          json={"name": "acme-prova.example", "is_primary": True}).json()
    autorizzazione = client.post(f"/api/v1/companies/{azienda['id']}/authorizations",
                                 headers=admin, json={
        "granting_subject_name": "Mario Rossi",
        "valid_from": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z",
        "allowed_profiles": ["public_passive"],
        "scopes": [{"entry_type": "domain", "value": "acme-prova.example",
                    "action": "include"}]})
    assert autorizzazione.status_code == 201, autorizzazione.text

    bloccato = client.delete(f"/api/v1/companies/{azienda['id']}/domains/{dominio['id']}",
                             headers=admin)
    assert bloccato.status_code == 409
    assert "autorizzazione attiva" in bloccato.json()["detail"]

    # Revocata l'autorizzazione, la rimozione e' consentita.
    client.post(f"/api/v1/companies/{azienda['id']}/authorizations/"
                f"{autorizzazione.json()['id']}/revoke", headers=admin,
                json={"reason": "contratto concluso"})
    assert client.delete(f"/api/v1/companies/{azienda['id']}/domains/{dominio['id']}",
                         headers=admin).status_code == 204


def test_aggiunta_e_rimozione_di_una_voce_di_perimetro(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    creata = client.post(f"/api/v1/companies/{azienda['id']}/scopes", headers=admin,
                         json={"entry_type": "cidr", "value": "203.0.113.0/24",
                               "action": "include", "note": "rete pubblica"})
    assert creata.status_code == 201, creata.text

    assert client.delete(f"/api/v1/companies/{azienda['id']}/scopes/{creata.json()['id']}",
                         headers=admin).status_code == 204
    assert client.get(f"/api/v1/companies/{azienda['id']}/scopes",
                      headers=admin).json() == []


def test_non_si_rimuove_il_perimetro_di_un_altra_azienda(client, admin):  # noqa: F811
    prima = _azienda(client, admin)
    seconda = _azienda(client, admin)
    voce = client.post(f"/api/v1/companies/{prima['id']}/scopes", headers=admin,
                       json={"entry_type": "domain", "value": "prima.example"}).json()

    # Identificativo valido, ma appartenente a un'altra azienda.
    assert client.delete(f"/api/v1/companies/{seconda['id']}/scopes/{voce['id']}",
                         headers=admin).status_code == 404
    assert len(client.get(f"/api/v1/companies/{prima['id']}/scopes",
                          headers=admin).json()) == 1


def test_un_visualizzatore_non_puo_rimuovere_domini(client, admin, cliente):  # noqa: F811
    azienda = _azienda(client, admin)
    dominio = client.post(f"/api/v1/companies/{azienda['id']}/domains", headers=admin,
                          json={"name": "acme-prova.example"}).json()
    assert client.delete(f"/api/v1/companies/{azienda['id']}/domains/{dominio['id']}",
                         headers=cliente).status_code == 403
