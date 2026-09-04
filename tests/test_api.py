"""Test dell'API: autenticazione, RBAC e segregazione multi-tenant."""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

pytestmark = pytest.mark.security

PASSWORD = "Password-di-test-1!"


@pytest.fixture
def client(tmp_path):
    """Applicazione con database SQLite isolato per il test."""
    from app.core.db import get_db
    from app.main import app
    from app.models import Base

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)

    def override():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    with TestClient(app) as test_client:
        test_client.session_factory = factory  # type: ignore[attr-defined]
        yield test_client
    app.dependency_overrides.clear()
    engine.dispose()


def _crea_utente(db, *, tenant_name: str, email: str, role_name: str,
                 company_name: str | None = None):
    from app.core.rbac import ROLE_PERMISSIONS
    from app.core.security import hash_password
    from app.models.organization import Company, Role, Tenant, User

    tenant = Tenant(name=tenant_name, slug=f"{tenant_name.lower()}-{uuid.uuid4().hex[:6]}")
    db.add(tenant)
    db.flush()

    role = db.query(Role).filter(Role.name == role_name).one_or_none()
    if role is None:
        role = Role(name=role_name, permissions_json=sorted(ROLE_PERMISSIONS[role_name]))
        db.add(role)
        db.flush()

    user = User(tenant_id=tenant.id, email=email, full_name=email,
                hashed_password=hash_password(PASSWORD), is_active=True)
    user.roles.append(role)
    db.add(user)

    company = None
    if company_name:
        company = Company(tenant_id=tenant.id, legal_name=company_name,
                          slug=f"c-{uuid.uuid4().hex[:6]}")
        db.add(company)
    db.flush()
    return tenant, user, company


def _login(client, email: str) -> dict[str, str]:
    response = client.post("/api/v1/auth/login",
                           json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


# --------------------------------------------------------------------------
# Endpoint pubblici
# --------------------------------------------------------------------------
def test_health(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] in {"ok", "degraded"}


def test_disclaimer_dichiara_i_limiti(client):
    payload = client.get("/api/v1/meta/disclaimer").json()
    assert "penetration test" in payload["it"]
    assert "certificazione" in payload["it"]


def test_modello_di_scoring_pubblicato(client):
    payload = client.get("/api/v1/meta/scoring-model").json()
    assert len(payload["categories"]) == 5
    assert sum(c["weight"] for c in payload["categories"]) == pytest.approx(1.0)
    assert payload["confidence_multipliers"]["confirmed"] == 1.0
    assert payload["confidence_multipliers"]["inferred"] == 0.0


def test_profili_espongono_le_azioni_vietate(client):
    payload = client.get("/api/v1/meta/profiles").json()
    assert "port_scanning" in payload["public_passive"]["forbidden_actions"]
    assert "credential_stuffing" in payload["verified_extended"]["forbidden_actions"]


def test_header_di_sicurezza_presenti(client):
    response = client.get("/api/v1/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


# --------------------------------------------------------------------------
# Autenticazione
# --------------------------------------------------------------------------
def test_endpoint_protetti_senza_token(client):
    for path in ("/api/v1/companies", "/api/v1/portfolio", "/api/v1/audit"):
        assert client.get(path).status_code == 401


def test_token_non_valido_rifiutato(client):
    response = client.get("/api/v1/companies",
                          headers={"Authorization": "Bearer non.un.token"})
    assert response.status_code == 401


def test_login_con_password_errata(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="T1", email="a@acme.example",
                     role_name="security_analyst")
        db.commit()
    response = client.post("/api/v1/auth/login",
                           json={"email": "a@acme.example", "password": "sbagliata"})
    assert response.status_code == 401
    # Il messaggio non deve rivelare se l'utente esiste.
    assert "Credenziali non valide" in response.text


def test_login_utente_inesistente_stessa_risposta(client):
    response = client.post("/api/v1/auth/login",
                           json={"email": "nessuno@acme.example", "password": "x"})
    assert response.status_code == 401
    assert "Credenziali non valide" in response.text


def test_profilo_utente_riporta_i_permessi(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="T1", email="analyst@acme.example",
                     role_name="security_analyst")
        db.commit()
    payload = client.get("/api/v1/auth/me",
                         headers=_login(client, "analyst@acme.example")).json()
    assert "security_analyst" in payload["roles"]
    assert "scan:start_passive" in payload["permissions"]
    assert "scan:start_extended" not in payload["permissions"]


# --------------------------------------------------------------------------
# Segregazione multi-tenant
# --------------------------------------------------------------------------
def test_tenant_non_vede_le_aziende_altrui(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="Alfa", email="alfa@acme.example",
                     role_name="tenant_administrator", company_name="Azienda Alfa")
        _crea_utente(db, tenant_name="Beta", email="beta@acme.example",
                     role_name="tenant_administrator", company_name="Azienda Beta")
        db.commit()

    alfa = client.get("/api/v1/companies", headers=_login(client, "alfa@acme.example")).json()
    assert [c["legal_name"] for c in alfa["items"]] == ["Azienda Alfa"]

    beta = client.get("/api/v1/companies", headers=_login(client, "beta@acme.example")).json()
    assert [c["legal_name"] for c in beta["items"]] == ["Azienda Beta"]


def test_accesso_diretto_a_azienda_altrui_negato(client):
    with client.session_factory() as db:
        _, _, alfa_company = _crea_utente(
            db, tenant_name="Alfa", email="alfa2@acme.example",
            role_name="tenant_administrator", company_name="Azienda Alfa")
        _crea_utente(db, tenant_name="Beta", email="beta2@acme.example",
                     role_name="tenant_administrator", company_name="Azienda Beta")
        alfa_id = str(alfa_company.id)
        db.commit()

    headers = _login(client, "beta2@acme.example")
    # 404 e non 403: non si rivela l'esistenza di risorse di altri tenant.
    assert client.get(f"/api/v1/companies/{alfa_id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/companies/{alfa_id}/dashboard",
                      headers=headers).status_code == 404
    assert client.get(f"/api/v1/companies/{alfa_id}/domains",
                      headers=headers).status_code == 404


def test_portfolio_limitato_al_proprio_tenant(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="Alfa", email="alfa3@acme.example",
                     role_name="tenant_administrator", company_name="Azienda Alfa")
        _crea_utente(db, tenant_name="Beta", email="beta3@acme.example",
                     role_name="tenant_administrator", company_name="Azienda Beta")
        db.commit()
    payload = client.get("/api/v1/portfolio",
                         headers=_login(client, "alfa3@acme.example")).json()
    assert payload["total_companies"] == 1


# --------------------------------------------------------------------------
# RBAC
# --------------------------------------------------------------------------
@pytest.mark.parametrize(("role", "profile", "expected"), [
    ("security_analyst", "public_passive", True),
    ("security_analyst", "verified_standard", True),
    ("security_analyst", "verified_extended", False),
    ("sales_account_manager", "public_passive", True),
    ("sales_account_manager", "verified_standard", False),
    ("sales_account_manager", "verified_extended", False),
    ("customer_viewer", "public_passive", False),
    ("read_only_auditor", "public_passive", False),
    ("tenant_administrator", "verified_extended", True),
])
def test_permessi_di_avvio_scansione(client, role, profile, expected):
    email = f"{role}-{profile}@acme.example"
    with client.session_factory() as db:
        _, _, company = _crea_utente(db, tenant_name=f"T-{role}-{profile}", email=email,
                                     role_name=role, company_name="Azienda")
        company_id = str(company.id)
        db.commit()

    response = client.post(f"/api/v1/companies/{company_id}/scans",
                           headers=_login(client, email), json={"profile": profile})
    if expected:
        # Il permesso c'e': il rifiuto puo' arrivare solo dal gate di
        # autorizzazione (403 con l'elenco dei motivi) oppure la scansione parte.
        assert response.status_code in {202, 403}
        if response.status_code == 403:
            assert "reasons" in response.text
    else:
        assert response.status_code == 403
        assert "Permesso mancante" in response.text


@pytest.mark.parametrize("role", ["customer_viewer", "sales_account_manager"])
def test_audit_log_riservato(client, role):
    email = f"{role}-audit@acme.example"
    with client.session_factory() as db:
        _crea_utente(db, tenant_name=f"T-{role}-audit", email=email, role_name=role)
        db.commit()
    assert client.get("/api/v1/audit", headers=_login(client, email)).status_code == 403


def test_auditor_puo_leggere_audit(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="T-auditor", email="auditor@acme.example",
                     role_name="read_only_auditor")
        db.commit()
    assert client.get("/api/v1/audit",
                      headers=_login(client, "auditor@acme.example")).status_code == 200


def test_solo_platform_admin_gestisce_i_tenant(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="T-admin", email="tadmin@acme.example",
                     role_name="tenant_administrator")
        _crea_utente(db, tenant_name="P-admin", email="padmin@acme.example",
                     role_name="platform_administrator")
        db.commit()
    assert client.get("/api/v1/tenants",
                      headers=_login(client, "tadmin@acme.example")).status_code == 403
    assert client.get("/api/v1/tenants",
                      headers=_login(client, "padmin@acme.example")).status_code == 200


def test_viewer_non_puo_creare_aziende(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="T-viewer", email="viewer@acme.example",
                     role_name="customer_viewer")
        db.commit()
    response = client.post("/api/v1/companies",
                           headers=_login(client, "viewer@acme.example"),
                           json={"legal_name": "Nuova", "slug": "nuova"})
    assert response.status_code == 403


# --------------------------------------------------------------------------
# Validazione dell'input
# --------------------------------------------------------------------------
@pytest.mark.parametrize("dominio", [
    "non valido", "esempio.com; rm -rf /", "$(whoami).example",
    "-oProxyCommand=evil.example", "a" * 300 + ".example",
])
def test_domini_malevoli_rifiutati(client, dominio):
    with client.session_factory() as db:
        _, _, company = _crea_utente(db, tenant_name="T-dom", email="dom@acme.example",
                                     role_name="security_analyst", company_name="Azienda")
        company_id = str(company.id)
        db.commit()
    response = client.post(f"/api/v1/companies/{company_id}/domains",
                           headers=_login(client, "dom@acme.example"),
                           json={"name": dominio})
    assert response.status_code == 422


def test_cidr_troppo_ampio_rifiutato(client):
    with client.session_factory() as db:
        _, _, company = _crea_utente(db, tenant_name="T-cidr", email="cidr@acme.example",
                                     role_name="tenant_administrator", company_name="Azienda")
        company_id = str(company.id)
        db.commit()
    response = client.post(f"/api/v1/companies/{company_id}/scopes",
                           headers=_login(client, "cidr@acme.example"),
                           json={"entry_type": "cidr", "value": "10.0.0.0/8",
                                 "action": "include"})
    assert response.status_code == 422


def test_profilo_di_scansione_sconosciuto_rifiutato(client):
    with client.session_factory() as db:
        _, _, company = _crea_utente(db, tenant_name="T-prof", email="prof@acme.example",
                                     role_name="tenant_administrator", company_name="Azienda")
        company_id = str(company.id)
        db.commit()
    response = client.post(f"/api/v1/companies/{company_id}/scans",
                           headers=_login(client, "prof@acme.example"),
                           json={"profile": "full_exploit"})
    assert response.status_code == 422


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------
def test_login_registrato_nell_audit(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="T-audit2", email="audit2@acme.example",
                     role_name="tenant_administrator")
        db.commit()
    headers = _login(client, "audit2@acme.example")
    azioni = {e["action"] for e in client.get("/api/v1/audit", headers=headers).json()["items"]}
    assert "login" in azioni


def test_scansione_rifiutata_registrata(client):
    with client.session_factory() as db:
        _, _, company = _crea_utente(db, tenant_name="T-blocked", email="blocked@acme.example",
                                     role_name="tenant_administrator", company_name="Azienda")
        company_id = str(company.id)
        db.commit()
    headers = _login(client, "blocked@acme.example")
    client.post(f"/api/v1/companies/{company_id}/scans", headers=headers,
                json={"profile": "verified_extended"})
    azioni = {e["action"] for e in client.get("/api/v1/audit", headers=headers).json()["items"]}
    assert "scan_blocked" in azioni


def test_integrita_della_catena_di_audit(client):
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="T-chain", email="chain@acme.example",
                     role_name="tenant_administrator")
        db.commit()
    headers = _login(client, "chain@acme.example")
    payload = client.get("/api/v1/audit/integrity", headers=headers).json()
    assert payload["intact"]
    assert payload["broken"] == []
