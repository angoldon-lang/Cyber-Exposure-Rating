"""Test del percorso di installazione documentato.

Un errore in `.env.example` o in `docker-compose.yml` non fa fallire nessun
test applicativo, ma impedisce l'avvio a chi segue le istruzioni del README.
Questi test presidiano proprio quel percorso.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = REPO_ROOT / ".env.example"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

# Chiave=valore, escluse righe vuote e commenti.
ASSIGNMENT = re.compile(r"^(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>.*)$")


def _entries() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        match = ASSIGNMENT.match(line)
        if match:
            entries[match["key"]] = match["value"]
    return entries


def test_env_example_senza_commenti_a_fine_riga():
    """Il parser `.env` di Compose non riconosce i commenti a fine riga.

    `CHIAVE=valore  # nota` assegna alla variabile l'intera stringa commento
    compresa: un segreto lasciato vuoto risulterebbe valorizzato con il testo
    del commento, aggirando i controlli `:?` del compose file.
    """
    colpevoli = {k: v for k, v in _entries().items() if "#" in v}
    assert not colpevoli, (
        "commento a fine riga: il valore includerebbe il commento -> "
        f"{colpevoli}")


def test_segreti_obbligatori_restano_vuoti_nell_esempio():
    """Nessun segreto preimpostato: il file di esempio non deve essere usabile
    cosi' com'e', altrimenti si finisce in esercizio con una chiave nota."""
    entries = _entries()
    for chiave in ("POSTGRES_PASSWORD", "JWT_SECRET_KEY", "EVIDENCE_ENCRYPTION_KEY",
                   "KEYCLOAK_ADMIN_PASSWORD", "HIBP_API_KEY"):
        assert entries.get(chiave, "") == "", f"{chiave} ha un valore di default"


def test_env_example_copre_le_variabili_richieste_dal_compose():
    """Ogni `${VAR:?...}` del compose deve esistere in `.env.example`, altrimenti
    l'utente scopre la variabile mancante solo al primo `docker compose up`."""
    testo = COMPOSE_FILE.read_text(encoding="utf-8")
    richieste = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", testo))
    assert richieste, "nessuna variabile obbligatoria trovata nel compose file"
    mancanti = richieste - set(_entries())
    assert not mancanti, f"variabili obbligatorie assenti da .env.example: {mancanti}"


def test_profili_opzionali_non_bloccano_l_installazione_base():
    """Compose interpola l'intero file a prescindere dai profili attivi: una
    variabile obbligatoria dichiarata da un servizio opzionale impedirebbe
    l'avvio anche a chi quel servizio non lo usa."""
    import yaml

    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    opzionali = {nome: definizione
                 for nome, definizione in compose["services"].items()
                 if definizione.get("profiles")}
    assert opzionali, "nessun servizio con profilo trovato"
    for nome, definizione in opzionali.items():
        obbligatorie = re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", yaml.safe_dump(definizione))
        assert not obbligatorie, (
            f"il servizio opzionale '{nome}' (profili {definizione['profiles']}) "
            f"dichiara {obbligatorie} come obbligatorie: bloccherebbe anche "
            "l'installazione base")


@pytest.mark.parametrize("variabile", ["ALLOW_PRIVATE_IP_SCANNING", "SCAN_MOCK_MODE"])
def test_default_prudenti(variabile):
    """L'esempio non deve invogliare configurazioni pericolose: la scansione di
    reti private resta disabilitata e la modalita' simulata resta attiva."""
    valore = _entries()[variabile]
    atteso = "false" if variabile == "ALLOW_PRIVATE_IP_SCANNING" else "true"
    assert valore == atteso, f"{variabile}={valore}, atteso {atteso}"


def test_cors_origins_dell_esempio_e_leggibile_dalle_impostazioni(monkeypatch, tmp_path):
    """`CORS_ORIGINS` e' un elenco separato da virgole: pydantic-settings tenta
    di decodificarlo come JSON se il campo non e' annotato `NoDecode`, e l'API
    non parte affatto."""
    from app.core.config import Settings

    monkeypatch.setenv("CORS_ORIGINS", _entries()["CORS_ORIGINS"])
    settings = Settings(_env_file=None)
    assert settings.cors_origins == ["http://localhost:8080", "http://localhost:5173"]
