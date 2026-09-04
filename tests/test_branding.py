"""Personalizzazione dei report: marchio, logo e testi liberi."""
from __future__ import annotations

import pytest

from tests.test_api import PASSWORD, _crea_utente, _login, client  # noqa: F401

pytestmark = pytest.mark.security

PNG_MINIMO = (b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
JPEG_MINIMO = (b"\xff\xd8\xff" + b"\x00" * 64)


@pytest.fixture
def admin(client):  # noqa: F811
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="Tenant", email="admin@branding.example",
                     role_name="tenant_administrator")
        db.commit()
    return _login(client, "admin@branding.example")


@pytest.fixture
def cliente(client):  # noqa: F811
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="Cliente", email="cliente@branding.example",
                     role_name="customer_viewer")
        db.commit()
    return _login(client, "cliente@branding.example")


def test_personalizzazione_vuota_alla_prima_lettura(client, admin):  # noqa: F811
    dati = client.get("/api/v1/branding", headers=admin).json()
    assert dati["brand_name"] is None
    assert dati["has_logo"] is False


def test_salvataggio_e_rilettura(client, admin):  # noqa: F811
    risposta = client.put("/api/v1/branding", headers=admin, json={
        "brand_name": "Remarck", "brand_owner": "Remarck S.r.l.",
        "primary_color": "#1f4e79", "report_intro_it": "Analisi svolta per conto del cliente."})
    assert risposta.status_code == 200, risposta.text
    assert risposta.json()["brand_name"] == "Remarck"
    assert client.get("/api/v1/branding", headers=admin).json()["primary_color"] == "#1f4e79"


def test_colore_arbitrario_rifiutato(client, admin):  # noqa: F811
    """Il colore finisce nel foglio di stile del report: un valore libero
    permetterebbe di iniettare altre proprieta' CSS."""
    risposta = client.put("/api/v1/branding", headers=admin,
                          json={"primary_color": "red; background: url(http://x)"})
    assert risposta.status_code == 422


def test_un_visualizzatore_non_puo_personalizzare(client, admin, cliente):  # noqa: F811
    assert client.put("/api/v1/branding", headers=cliente,
                      json={"brand_name": "Tentativo"}).status_code == 403
    # La lettura resta consentita: serve a mostrare il marchio nell'interfaccia.
    assert client.get("/api/v1/branding", headers=cliente).status_code == 200


# --------------------------------------------------------------------------
# Logo
# --------------------------------------------------------------------------
def test_caricamento_e_lettura_del_logo(client, admin):  # noqa: F811
    risposta = client.post("/api/v1/branding/logo", headers=admin,
                           files={"file": ("logo.png", PNG_MINIMO, "image/png")})
    assert risposta.status_code == 200, risposta.text
    assert risposta.json()["has_logo"] is True

    scaricato = client.get("/api/v1/branding/logo", headers=admin)
    assert scaricato.status_code == 200
    assert scaricato.headers["content-type"].startswith("image/png")
    assert scaricato.content == PNG_MINIMO


def test_svg_rifiutato(client, admin):  # noqa: F811
    """Un SVG e' un documento XML che puo' contenere script, e il logo finisce
    in report distribuiti a terzi."""
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    risposta = client.post("/api/v1/branding/logo", headers=admin,
                           files={"file": ("logo.svg", svg, "image/svg+xml")})
    assert risposta.status_code == 415
    assert "SVG" in risposta.json()["detail"]


def test_il_tipo_dichiarato_dal_client_non_fa_fede(client, admin):  # noqa: F811
    """Contenuto arbitrario ribattezzato PNG: si verifica la firma del file."""
    risposta = client.post("/api/v1/branding/logo", headers=admin,
                           files={"file": ("finto.png", b"#!/bin/sh\nrm -rf /", "image/png")})
    assert risposta.status_code == 415


def test_logo_troppo_grande_rifiutato(client, admin):  # noqa: F811
    grande = b"\x89PNG\r\n\x1a\n" + b"\x00" * (2 * 1024 * 1024 + 10)
    risposta = client.post("/api/v1/branding/logo", headers=admin,
                           files={"file": ("grande.png", grande, "image/png")})
    assert risposta.status_code == 413


def test_rimozione_del_logo(client, admin):  # noqa: F811
    client.post("/api/v1/branding/logo", headers=admin,
                files={"file": ("logo.jpg", JPEG_MINIMO, "image/jpeg")})
    assert client.delete("/api/v1/branding/logo", headers=admin).status_code == 204
    assert client.get("/api/v1/branding/logo", headers=admin).status_code == 404


def test_la_personalizzazione_non_attraversa_i_tenant(client, admin):  # noqa: F811
    """Ogni tenant vede solo la propria: e' il marchio con cui firma i report."""
    client.put("/api/v1/branding", headers=admin, json={"brand_name": "Remarck"})
    with client.session_factory() as db:
        _crea_utente(db, tenant_name="Altro", email="altro@branding.example",
                     role_name="tenant_administrator")
        db.commit()
    altro = _login(client, "altro@branding.example")
    assert client.get("/api/v1/branding", headers=altro).json()["brand_name"] is None
    assert client.get("/api/v1/branding", headers=admin).json()["brand_name"] == "Remarck"
