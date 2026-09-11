"""La form e il backend devono accettare le stesse cose.

Creando un'azienda con identificativo «ag» il pulsante si abilitava, la
richiesta partiva e il backend la rifiutava: la sua espressione regolare
chiede almeno tre caratteri, quella della form ne accettava anche uno. Il
messaggio mostrato era «Richiesta non valida», che non dice quale campo.

Senza test runner nel frontend, la regola si presidia da qui: le due
espressioni regolari sono testo, e il testo si puo' confrontare.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.organization import SLUG_PATTERN, CompanyCreate

REPO_ROOT = Path(__file__).resolve().parents[1]
FORM = (REPO_ROOT / "frontend" / "src" / "pages" / "CompanyManage.tsx").read_text(encoding="utf-8")
CLIENT = (REPO_ROOT / "frontend" / "src" / "api" / "client.ts").read_text(encoding="utf-8")

pytestmark = pytest.mark.security


def _regex_dello_slug_nella_form() -> str:
    trovata = re.search(r"const slugValido = /(.+?)/\.test", FORM)
    assert trovata, "la form non valida piu' lo slug: il backend lo farebbe al suo posto"
    return trovata.group(1)


def test_la_form_usa_la_stessa_regola_del_backend_per_lo_slug():
    assert _regex_dello_slug_nella_form() == SLUG_PATTERN


@pytest.mark.parametrize("slug", ["a", "ag", "-ag", "ag-", "AG", "a g"])
def test_gli_slug_che_il_backend_rifiuta_non_passano_la_form(slug):
    """Se la form li accettasse, il pulsante si abiliterebbe su dati che
    l'API rifiuta: e' esattamente il caso che produceva l'errore."""
    with pytest.raises(ValidationError):
        CompanyCreate(legal_name="Prova Srl", slug=slug)

    assert not re.fullmatch(_regex_dello_slug_nella_form(), slug)


@pytest.mark.parametrize("slug", ["ag-srl", "acme", "a1b", "a" * 64])
def test_gli_slug_validi_passano_entrambi(slug):
    CompanyCreate(legal_name="Prova Srl", slug=slug)
    assert re.fullmatch(_regex_dello_slug_nella_form(), slug)


def test_un_paese_vuoto_viene_inviato_come_assente():
    """`country` ha un minimo di due caratteri: la stringa vuota e' un
    errore, l'assenza no. La form non lo normalizzava."""
    with pytest.raises(ValidationError):
        CompanyCreate(legal_name="Prova Srl", slug="prova-srl", country="")
    CompanyCreate(legal_name="Prova Srl", slug="prova-srl", country=None)

    assert "country: valori.country || null" in FORM, (
        "senza questa normalizzazione un paese svuotato viene inviato come "
        '"" e la creazione fallisce')


def test_il_client_traduce_il_dettaglio_di_validazione():
    """L'API manda sempre quale campo non va: restava inutilizzato perche'
    e' un array e il client cercava una stringa."""
    assert "messaggioDiValidazione" in CLIENT
    for campo in ("legal_name", "slug", "country"):
        assert f"{campo}:" in CLIENT, f"manca il nome leggibile per {campo}"
