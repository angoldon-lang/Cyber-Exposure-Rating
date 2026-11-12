"""Un comando di diagnosi che sbaglia costa piu' di uno che manca.

`make diagnosi` dichiarava due cose false su un'installazione sana:

  * «Strumenti: ASSENTE -> ricostruire il frontend», sempre, perche' cercava
    nel bundle la frase «Dopo aver modificato», che dall'interfaccia era
    sparita da qualche versione. Nessuna ricostruzione poteva farla comparire:
    chi seguiva il consiglio ricostruiva a vuoto, e all'infinito;
  * «NESSUN Cache-Control -> immagine del frontend non aggiornata» anche
    quando il server non era stato raggiunto affatto. `curl -sfI` tace su
    qualunque guasto, e il ramo di fallimento ne attribuiva uno solo.

La prima e' la classe di difetto che questi test presidiano: una frase scritta
a mano in uno script, che invecchia da sola e senza rumore. Qui si verifica che
ogni frase cercata nel bundle esista ancora nel codice del frontend, cosi' che
a cambiare un titolo fallisca il test invece del comando.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parents[1]
SCRIPT = (RADICE / "scripts" / "diagnosi.sh").read_text(encoding="utf-8")
SORGENTI = RADICE / "frontend" / "src"


def _frasi_cercate() -> list[tuple[str, str]]:
    """(nome della scheda, frase cercata nel bundle), dall'elenco nello script."""
    blocco = re.search(r"^SCHEDE=\((.*?)^\)", SCRIPT, re.S | re.M)
    assert blocco, "l'elenco delle schede non e' piu' riconoscibile in diagnosi.sh"
    voci = re.findall(r'"([^"|]+)\|([^"]+)"', blocco.group(1))
    assert voci, "nessuna scheda dichiarata"
    return voci


def _testo_del_frontend() -> str:
    pezzi = [p.read_text(encoding="utf-8")
             for p in SORGENTI.rglob("*.tsx")]
    pezzi += [p.read_text(encoding="utf-8") for p in SORGENTI.rglob("*.ts")]
    return "\n".join(pezzi)


@pytest.mark.parametrize("nome,frase", _frasi_cercate())
def test_ogni_frase_cercata_esiste_ancora_nel_frontend(nome, frase):
    """E' il test che mancava. Senza, una frase riscritta nell'interfaccia
    rende la scheda «ASSENTE» per sempre, e la diagnosi manda a ricostruire
    un'immagine che e' giusta."""
    assert frase in _testo_del_frontend(), (
        f"diagnosi.sh cerca «{frase}» per la scheda «{nome}», ma quella frase "
        "non esiste piu' nel frontend: la scheda risulterebbe assente a ogni "
        "esecuzione. Aggiornare l'elenco SCHEDE in scripts/diagnosi.sh.")


def test_le_frasi_sono_abbastanza_specifiche():
    """Una frase troppo corta comparirebbe nel bundle per caso, e la diagnosi
    direbbe «presente» di una scheda assente -- l'errore opposto, piu' difficile
    da notare."""
    for nome, frase in _frasi_cercate():
        assert len(frase) >= 15, f"«{frase}» ({nome}) e' troppo generica"


def test_la_porta_viene_letta_dal_file_di_configurazione():
    """Make non esporta `.env`: interrogando la 8080 per abitudine, chi ha
    spostato il frontend su un'altra porta leggeva «immagine non aggiornata»
    invece di «non ti ho trovato»."""
    assert re.search(r"grep -E '\^FRONTEND_PORT='", SCRIPT), (
        "la porta non viene piu' letta da .env")
    assert "${porta:-8080}" in SCRIPT or "porta=${porta:-8080}" in SCRIPT, (
        "manca il valore predefinito della porta")


def test_un_server_non_raggiunto_non_viene_chiamato_immagine_vecchia():
    """Sono due guasti con due rimedi diversi: ricostruire, e avviare."""
    assert "NON RAGGIUNTO" in SCRIPT, (
        "il caso «non ho raggiunto il server» non e' distinto da quello "
        "dell'header mancante")
    # La riga sull'header mancante deve restare, per il caso in cui il server
    # risponda davvero senza Cache-Control.
    assert "NESSUN Cache-Control" in SCRIPT


def test_il_confronto_nel_bundle_e_letterale():
    """Le frasi contengono spazi e punteggiatura: interpretate come espressione
    regolare, una di esse potrebbe non trovarsi piu' per un carattere speciale
    aggiunto domani."""
    assert "grep -qlF" in SCRIPT, "il confronto nel bundle non e' letterale (-F)"


def test_il_make_rimanda_allo_script():
    """Se il target tornasse inline, le frasi uscirebbero dal controllo del
    test e ricomincerebbero a invecchiare in silenzio."""
    makefile = (RADICE / "Makefile").read_text(encoding="utf-8")

    assert "bash scripts/diagnosi.sh" in makefile
    assert "Dopo aver modificato" not in makefile, (
        "la frase invecchiata e' tornata nel Makefile")


def test_la_cache_si_misura_su_entrambi_gli_indirizzi():
    """`location = /index.html` vale per `/` soltanto se nginx rifa' la scelta
    della location dopo il `try_files`. Dedurlo e' facile e sbagliarlo
    altrettanto: interrogando i due indirizzi, la differenza si vede invece di
    essere supposta -- e distingue una configurazione da correggere da un
    servizio spento o da un'immagine vecchia, che sono tre rimedi diversi."""
    assert 'cache_di "/"' in SCRIPT
    assert 'cache_di "/index.html"' in SCRIPT
    assert "frontend/nginx.conf" in SCRIPT, (
        "il caso «la regola non si applica a /» non indica dove si corregge")
