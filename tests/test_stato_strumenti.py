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


def test_nessuno_strumento_e_irrisolvibile_per_architettura_amd64():
    """L'elenco delle dipendenze non risolvibili si e' svuotato, e va detto.

    `amass` e' entrato nell'immagine (versione 3.23.3, l'ultima con output
    JSON); `zap_baseline` non richiede piu' un runtime Docker dentro il
    worker, perche' il demone ZAP e' un servizio a se' comandato via API.
    Resta solo `naabu`, e solo dove non esistono binari per l'architettura:
    lo verifica `test_naabu_dipende_dall_architettura`.
    """
    from app.services import tool_status

    assert tool_status._dipendenze_nel_worker() == {} or set(
        tool_status._dipendenze_nel_worker()) == {"naabu"}


def test_naabu_dichiara_chi_lo_sostituisce(monkeypatch):
    """Dove manca, deve dire che al suo posto lavora `port_scan`."""
    from app.services import tool_status

    monkeypatch.setattr(tool_status.platform, "machine", lambda: "aarch64")
    assert "port_scan" in tool_status._dipendenze_nel_worker()["naabu"]


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
    """La risposta non e' piu' una lista: accanto agli strumenti dice se i
    valori si possono conservare, perche' senza quel materiale i campi della
    schermata vanno mostrati disabilitati invece di fallire al salvataggio."""
    risposta = client.get("/api/v1/tool-status", headers=admin)
    assert risposta.status_code == 200, risposta.text

    corpo = risposta.json()
    assert any(s["key"] == "spiderfoot" for s in corpo["tools"])
    assert isinstance(corpo["can_store"], bool)


def test_l_endpoint_richiede_l_autenticazione(client):  # noqa: F811
    assert client.get("/api/v1/tool-status").status_code == 401


def test_uno_strumento_in_attesa_di_un_dato_non_e_da_configurare():
    """`email_header` non ha variabili: aspetta un'intestazione dall'analista.

    Elencarlo fra le configurazioni mancanti manda a cercare una variabile
    che non esiste, ed e' esattamente cio' che faceva sembrare «da
    configurare» meta' del catalogo.
    """
    stato = _per_chiave()["email_header"]

    assert stato["configured"] is True
    assert stato["kind"] == "uso"
    assert stato["requirements"] == []
    assert stato["reason"] and "intestazione" in stato["reason"]


def test_port_scan_spiega_da_cosa_dipende():
    stato = _per_chiave()["port_scan"]
    assert stato["kind"] == "uso"
    assert "verificat" in (stato["reason"] or "")


def test_zap_si_configura_come_un_servizio_qualsiasi():
    """Era dichiarato irrisolvibile perche' avviare l'immagine ZAP avrebbe
    richiesto il socket Docker dentro il worker. Il demone e' ora un servizio
    a se', e si configura con indirizzo e chiave come SpiderFoot."""
    stato = _per_chiave()["zap_baseline"]

    assert stato["kind"] == "configurazione"
    assert {r["variable"] for r in stato["requirements"]} == {"ZAP_URL", "ZAP_API_KEY"}
    assert any(r["secret"] for r in stato["requirements"]), "la chiave e' un segreto"


def test_amass_e_nell_immagine():
    """Non compare piu' fra cio' che manca: il binario c'e'."""
    stato = _per_chiave()["amass_passive"]

    assert stato["configured"] is True
    assert stato["requirements"] == []


def test_naabu_dipende_dall_architettura(monkeypatch):
    """Su amd64 naabu c'e': dichiararlo mancante ovunque mandava a cercare un
    problema che su quella architettura non esiste."""
    from app.services import tool_status

    monkeypatch.setattr(tool_status.platform, "machine", lambda: "x86_64")
    assert "naabu" not in tool_status._dipendenze_nel_worker()

    monkeypatch.setattr(tool_status.platform, "machine", lambda: "aarch64")
    assert "naabu" in tool_status._dipendenze_nel_worker()


def test_ogni_strumento_non_pronto_dice_perche():
    """Nessuna riga senza spiegazione: era il motivo per cui il registro
    andava letto a mano."""
    senza_motivo = [s["key"] for s in stato_strumenti()
                    if (not s["configured"] or s["kind"] == "uso") and not s["reason"]]
    assert senza_motivo == []
