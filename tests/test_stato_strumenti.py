"""Cosa manca a ciascuno strumento per funzionare.

Il motivo per cui uno strumento resta saltato compariva solo nel log del
worker. Chi deve porvi rimedio ha bisogno di sapere quale variabile
impostare, se la fonte costi qualcosa e dove procurarsi la chiave.
"""
from __future__ import annotations

import pytest

from app.services.tool_status import stato_strumenti
from tests.test_company_crud import admin, client, tenant_unico  # noqa: F401

pytestmark = pytest.mark.security


def _per_chiave() -> dict[str, dict]:
    return {s["key"]: s for s in stato_strumenti()}


def test_ogni_strumento_del_catalogo_e_elencato():
    from app.core.config import load_yaml_config

    attesi = set(load_yaml_config("tool_profiles")["tools"])
    assert set(_per_chiave()) == attesi


def test_uno_strumento_senza_dipendenze_risulta_pronto():
    stato = _per_chiave()["dns"]
    assert stato["configured"] is True
    assert stato["reason"] is None
    assert stato["requirements"] == []


def test_uno_strumento_a_pagamento_lo_dichiara():
    """Sapere che una fonte costa cambia la decisione: senza, si cerca una
    configurazione che non esiste."""
    stato = _per_chiave()["hibp"]
    assert stato["configured"] is False
    assert "HIBP_API_KEY" in stato["reason"]
    requisito = stato["requirements"][0]
    assert requisito["free"] is False
    assert requisito["where"].startswith("https://")


def test_una_dipendenza_dell_immagine_non_si_risolve_con_una_variabile():
    """Suggerire una variabile inesistente manderebbe a cercare a vuoto."""
    for chiave in ("naabu", "zap_baseline", "amass_passive"):
        stato = _per_chiave()[chiave]
        assert stato["configured"] is False
        assert stato["requirements"] == []
        assert stato["reason"]


def test_naabu_dichiara_chi_lo_sostituisce():
    assert "port_scan" in _per_chiave()["naabu"]["reason"]


def test_gli_strumenti_da_sistemare_vengono_per_primi():
    """E' l'elenco di cosa c'e' da fare: sepolto in fondo non lo si legge."""
    esiti = stato_strumenti()
    primi = [s["configured"] for s in esiti]
    assert primi == sorted(primi), "gli strumenti pronti precedono quelli da sistemare"


def test_nessun_valore_di_chiave_viene_restituito(monkeypatch):
    """La schermata dice cosa manca, non conserva segreti."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "hibp_api_key", "chiave-segretissima")
    testo = str(stato_strumenti())
    assert "chiave-segretissima" not in testo
    assert _per_chiave()["hibp"]["requirements"][0]["present"] is True


def test_l_endpoint_risponde_a_un_utente_autenticato(client, admin):  # noqa: F811
    risposta = client.get("/api/v1/tool-status", headers=admin)
    assert risposta.status_code == 200, risposta.text
    assert any(s["key"] == "spiderfoot" for s in risposta.json())


def test_l_endpoint_richiede_l_autenticazione(client):  # noqa: F811
    assert client.get("/api/v1/tool-status").status_code == 401
