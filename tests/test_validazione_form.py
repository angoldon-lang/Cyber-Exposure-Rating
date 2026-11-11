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


# ---------------------------------------------------------------------------
# «Sessione scaduta» davanti alla schermata di accesso
# ---------------------------------------------------------------------------
def test_il_401_dell_accesso_non_viene_chiamato_sessione_scaduta():
    """Il client traduceva ogni 401 in «Sessione scaduta», compreso quello di
    `/auth/login` -- che e' la risposta a credenziali sbagliate.

    Chi sbagliava la password leggeva «sessione scaduta» stando davanti alla
    schermata di accesso, dove nessuna sessione esiste, e andava a cercare un
    problema di token invece di una password errata. Il backend risponde
    «Credenziali non valide», ed e' quel messaggio che deve arrivare.
    """
    chiamata = re.search(r"login:[^;]*?request<TokenResponse>\((.*?)\),\n",
                         CLIENT, re.DOTALL)
    assert chiamata, "la chiamata di accesso non e' piu' riconoscibile nel client"

    assert "autenticazione: true" in chiamata.group(1), (
        "la richiesta di accesso non si sottrae alla traduzione generica del 401: "
        "il suo «credenziali non valide» tornerebbe a chiamarsi «sessione scaduta»")


def test_il_401_senza_token_non_parla_di_scadenza():
    """Senza token non c'era niente da scadere. Dirlo comunque confonde una
    sessione mai aperta con una finita."""
    assert "Autenticazione richiesta" in CLIENT, (
        "il caso «nessun token» non e' distinto da quello della sessione scaduta")
    # Il messaggio sulla scadenza deve restare condizionato alla presenza del token.
    assert re.search(r"token\s*\n?\s*\?\s*'Sessione scaduta", CLIENT), (
        "«Sessione scaduta» non e' piu' condizionato alla presenza di un token")


def test_la_traduzione_generica_del_401_resta_per_le_altre_richieste():
    """Il comportamento utile non va perso: un token scaduto durante l'uso deve
    continuare a essere ripulito e dichiarato."""
    assert "auth.clear()" in CLIENT
    assert "Sessione scaduta" in CLIENT
