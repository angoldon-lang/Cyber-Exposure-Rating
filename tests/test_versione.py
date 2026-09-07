"""Il numero di versione deve essere uno solo.

Compariva in `backend/app/core/config.py` e in `frontend/package.json`:
due copie destinate a divergere alla prima modifica di una sola delle due, e
a quel punto «quale versione sta girando?» non ha piu' risposta. La sorgente
e' il file `VERSION` alla radice del repository.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VERSIONE = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()

pytestmark = pytest.mark.security


def test_il_file_version_contiene_un_numero_semantico():
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", VERSIONE), VERSIONE


def test_il_backend_legge_il_file_version():
    from app.core.config import versione_della_piattaforma

    assert versione_della_piattaforma() == VERSIONE


def test_le_impostazioni_espongono_quella_versione():
    from app.core.config import settings

    assert settings.app_version == VERSIONE


def test_package_json_dichiara_la_stessa_versione():
    """npm vuole il numero nel proprio file: se diverge, i due artefatti
    dichiarano versioni diverse della stessa piattaforma."""
    pacchetto = json.loads((REPO_ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    assert pacchetto["version"] == VERSIONE


def test_ogni_immagine_porta_con_se_il_file_version():
    """Nell'immagine il repository non c'e': senza questa copia il numero
    tornerebbe «sconosciuta» proprio dove serve leggerlo."""
    # Il frontend non fa eccezione per distrazione: prende il numero da
    # package.json, che npm richiede comunque, e il test qui sopra impedisce
    # ai due di divergere.
    for dockerfile in ("backend/Dockerfile", "workers/Dockerfile"):
        testo = (REPO_ROOT / dockerfile).read_text(encoding="utf-8")
        assert re.search(r"^COPY (--chown=\S+ )?VERSION ", testo, re.MULTILINE), dockerfile


def test_il_report_dichiara_la_versione_della_piattaforma():
    """Un report circola per mesi: senza il numero, un risultato diverso da
    una rilevazione successiva non e' spiegabile."""
    modello = (REPO_ROOT / "reporting" / "templates" / "executive.html.j2").read_text(encoding="utf-8")
    assert "platform_version" in modello
