"""Ritrovare le utenze, e rientrare quando la password e' perduta.

Era una situazione senza uscita, e nel codice non per dimenticanza ma per
costruzione: nel database ci sono solo hash, il file delle credenziali
dimostrative si legge una volta sola dopo il seed e vive su un volume, e
`seed` salta le utenze che esistono gia' — quindi rieseguirlo non ristampa
nulla. Perso quel file, l'unico rimedio era un UPDATE a mano sul database.

Non e' un'elevazione di privilegio: per eseguire il comando serve una shell
sul server, che da' gia' accesso al database. Cio' che il test presidia e' che
resti un'operazione tracciata, che non inventi utenze e che non prometta di
recuperare una password che non esiste piu'.
"""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from sqlalchemy import select

from app.cli import utenze
from app.core.security import verify_password
from app.models.audit import AuditLog
from app.models.enums import RoleName
from app.models.organization import Role, Tenant, User


@pytest.fixture
def con_utenze(db_session, monkeypatch):
    """Due utenze in due tenant, piu' una senza password locale (OIDC)."""
    tenant = Tenant(name="Tenant di prova", slug="prova")
    altro = Tenant(name="Altro tenant", slug="altro")
    db_session.add_all([tenant, altro])
    db_session.flush()

    ruolo = Role(name=RoleName.SECURITY_ANALYST.value, description="Analista",
                 permissions_json=[])
    db_session.add(ruolo)
    db_session.flush()

    from app.core.security import hash_password
    analista = User(tenant_id=tenant.id, email="analista@prova.example",
                    full_name="Analista", hashed_password=hash_password("vecchia"),
                    is_active=True)
    analista.roles.append(ruolo)
    federata = User(tenant_id=altro.id, email="federata@altro.example",
                    full_name="Da OIDC", hashed_password=None, is_active=True)
    db_session.add_all([analista, federata])
    db_session.commit()

    @contextmanager
    def sessione():
        yield db_session

    monkeypatch.setattr("app.cli.session_scope", sessione)
    return db_session


# --------------------------------------------------------------------------
# Elencare
# --------------------------------------------------------------------------
def test_elenca_le_utenze_di_tutti_i_tenant(con_utenze):
    """La domanda che precede tutte le altre — «quali utenze esistono?» — non
    aveva risposta da nessuna parte se non interrogando il database a mano."""
    esito = utenze()

    indirizzi = {r["email"] for r in esito["users"]}
    assert indirizzi == {"analista@prova.example", "federata@altro.example"}
    assert esito["total"] == 2
    assert {r["tenant"] for r in esito["users"]} == {"prova", "altro"}


def test_dichiara_chi_non_ha_una_password_locale(con_utenze):
    """Con `auth_mode=oidc` l'autenticazione la fa Keycloak e l'hash resta
    nullo: senza dirlo, si cerca una password che per quell'utenza non
    esiste."""
    per_email = {r["email"]: r for r in utenze()["users"]}

    assert per_email["analista@prova.example"]["local_password"] is True
    assert per_email["federata@altro.example"]["local_password"] is False


def test_riporta_ruoli_e_stato(con_utenze):
    per_email = {r["email"]: r for r in utenze()["users"]}

    assert per_email["analista@prova.example"]["roles"] == ["security_analyst"]
    assert per_email["analista@prova.example"]["active"] is True


# --------------------------------------------------------------------------
# Reimpostare
# --------------------------------------------------------------------------
def test_la_password_reimpostata_autentica(con_utenze):
    esito = utenze(reimposta="analista@prova.example")
    nuova = esito["reset"]["password"]

    utente = con_utenze.execute(
        select(User).where(User.email == "analista@prova.example")).scalar_one()

    assert verify_password(nuova, utente.hashed_password)
    assert not verify_password("vecchia", utente.hashed_password), (
        "la password precedente funziona ancora")


def test_la_password_non_viene_mai_riletta_ma_sostituita(con_utenze):
    """Il comando non puo' «ritrovare» una password: nel database c'e' un hash.
    Due reimpostazioni di seguito devono dare due valori diversi, altrimenti
    da qualche parte ne esisterebbe una copia."""
    prima = utenze(reimposta="analista@prova.example")["reset"]["password"]
    dopo = utenze(reimposta="analista@prova.example")["reset"]["password"]

    assert prima != dopo


def test_la_reimpostazione_finisce_nell_audit_log(con_utenze):
    """Rientrare in un'utenza altrui e' un'operazione che deve lasciare
    traccia, anche quando la esegue chi ha legittimamente accesso al server."""
    utenze(reimposta="analista@prova.example")

    righe = con_utenze.execute(
        select(AuditLog).where(AuditLog.action == "user_password_reset_cli")).scalars().all()

    assert len(righe) == 1
    assert righe[0].entity_type == "user"
    assert righe[0].actor_email == "analista@prova.example"


def test_un_indirizzo_inesistente_non_crea_niente(con_utenze):
    """Un comando che creasse l'utenza richiesta sarebbe un modo silenzioso di
    aggiungere un accesso a una piattaforma multi-tenant."""
    esito = utenze(reimposta="estraneo@example.com")

    assert esito["reset"] is None
    assert "estraneo@example.com" in esito["error"]
    assert con_utenze.execute(
        select(User).where(User.email == "estraneo@example.com")).scalar_one_or_none() is None


def test_l_elenco_aiuta_a_trovare_l_indirizzo_giusto(con_utenze):
    """Chi sbaglia l'indirizzo lo sbaglia perche' non lo ricorda: ripeterglielo
    «non trovato» e basta lo lascia dov'era."""
    esito = utenze(reimposta="analista@prova.exampl")  # una lettera in meno

    assert "analista@prova.example" in esito["error"]


def test_con_oidc_non_si_imposta_una_password_che_non_verrebbe_usata(
        con_utenze, monkeypatch):
    """Impostarla darebbe l'impressione di aver risolto: l'accesso continuerebbe
    a passare da Keycloak e a essere rifiutato."""
    monkeypatch.setattr("app.cli.settings.auth_mode", "oidc")

    esito = utenze(reimposta="analista@prova.example")

    assert esito["reset"] is None
    assert "Keycloak" in esito["error"]

    utente = con_utenze.execute(
        select(User).where(User.email == "analista@prova.example")).scalar_one()
    assert verify_password("vecchia", utente.hashed_password), (
        "la password locale e' stata cambiata nonostante OIDC")


# --------------------------------------------------------------------------
# Il percorso documentato
# --------------------------------------------------------------------------
def test_il_comando_e_raggiungibile_dal_makefile():
    """Chi non riesce ad accedere non legge il codice della CLI: cerca un
    target."""
    from pathlib import Path

    makefile = (Path(__file__).resolve().parents[1] / "Makefile").read_text(encoding="utf-8")

    assert "app.cli utenze" in makefile
    assert "--reimposta" in makefile
    # `run --rm` e non `exec`: serve anche quando l'API non e' avviata, che e'
    # proprio la situazione di chi non riesce ad accedere.
    assert "run --rm api python -m app.cli utenze" in makefile


# --------------------------------------------------------------------------
# «Credenziali non valide» con le credenziali giuste
# --------------------------------------------------------------------------
def _tentativo(db, *, email, riuscito, ip="172.18.0.1"):
    from app.models.enums import AuditAction
    from app.services.audit import record_audit

    record_audit(db, action=(AuditAction.LOGIN.value if riuscito
                             else AuditAction.LOGIN_FAILED.value),
                 actor_email=email, actor_ip=ip,
                 outcome="success" if riuscito else "failure")
    db.commit()


def test_mostra_l_indirizzo_arrivato_davvero_al_server(con_utenze):
    """E' il modo piu' rapido di smentire «le credenziali sono giuste»: il
    server ha ricevuto `prova.exemple`, non `prova.example`. Senza vederlo si
    cerca altrove per mezz'ora.
    """
    _tentativo(con_utenze, email="analista@prova.exemple", riuscito=False)

    tentativi = utenze()["attempts"]

    assert tentativi, "i tentativi di accesso non vengono riportati"
    assert tentativi[0]["email"] == "analista@prova.exemple"
    assert tentativi[0]["outcome"] == "failure"
    assert tentativi[0]["ip"] == "172.18.0.1"


def test_i_tentativi_sono_dal_piu_recente(con_utenze):
    """Chi guarda ha appena provato: il suo tentativo deve stare in cima."""
    _tentativo(con_utenze, email="vecchio@prova.example", riuscito=False)
    _tentativo(con_utenze, email="appena.ora@prova.example", riuscito=False)

    assert utenze()["attempts"][0]["email"] == "appena.ora@prova.example"


def test_un_accesso_riuscito_si_distingue_da_uno_respinto(con_utenze):
    _tentativo(con_utenze, email="analista@prova.example", riuscito=True)

    assert utenze()["attempts"][0]["outcome"] == "success"


def test_nessun_tentativo_registrato_e_un_informazione(con_utenze):
    """Se chi ha appena provato non trova il proprio tentativo, la richiesta
    non e' arrivata all'API: e' una causa diversa da una password sbagliata, e
    la piu' difficile da indovinare."""
    esito = utenze()

    assert esito["attempts"] == []


def test_i_tentativi_compaiono_anche_quando_si_reimposta(con_utenze):
    """Chi reimposta la password sta diagnosticando: togliergli il contesto
    proprio in quel momento lo obbligherebbe a un secondo comando."""
    _tentativo(con_utenze, email="analista@prova.example", riuscito=False)

    esito = utenze(reimposta="analista@prova.example")

    assert esito["reset"] is not None
    assert esito["attempts"]
