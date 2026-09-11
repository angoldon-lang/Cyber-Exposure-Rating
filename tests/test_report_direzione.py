"""Il rapporto per la direzione deve restare di poche pagine.

L'esecutivo conteneva il perimetro analizzato, l'inventario dell'esposizione
e la copertura degli strumenti: materiale che serve a chi verifica il lavoro,
non a chi deve decidere. Quelle sezioni sono passate nell'allegato tecnico, e
al loro posto c'e' un radar delle aree tematiche, che dice in un colpo
d'occhio dove l'esposizione e' concentrata.
"""
from __future__ import annotations

import io
import re

import pytest

from reporting import service as rs
from reporting.radar import COLORE_PREDEFINITO, grafico_radar
from tests.test_reports import _context

pytestmark = pytest.mark.slow

# Le aree del modello di rating: sono otto, il radar le mostra tutte.
AREE = [
    {"label_it": "Superficie di attacco esposta", "weight": 0.2, "score": 62,
     "finding_count": 9, "critical_count": 0, "high_count": 2},
    {"label_it": "Sicurezza web", "weight": 0.2, "score": 41,
     "finding_count": 14, "critical_count": 1, "high_count": 3},
    {"label_it": "Sicurezza e-mail e DNS", "weight": 0.15, "score": 88,
     "finding_count": 2, "critical_count": 0, "high_count": 0},
    {"label_it": "Vulnerabilita' note", "weight": 0.15, "score": 30,
     "finding_count": 21, "critical_count": 4, "high_count": 6},
    {"label_it": "Esposizione delle credenziali", "weight": 0.1, "score": 95,
     "finding_count": 1, "critical_count": 0, "high_count": 0},
    {"label_it": "Minacce ransomware", "weight": 0.1, "score": 100,
     "finding_count": 0, "critical_count": 0, "high_count": 0},
    {"label_it": "Abuso del marchio", "weight": 0.1, "score": 74,
     "finding_count": 3, "critical_count": 0, "high_count": 1},
]


def _pagine(pdf: bytes) -> list[str]:
    import pypdf

    return [p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(pdf)).pages]


def test_l_esecutivo_resta_di_poche_pagine():
    pagine = _pagine(rs.generate_pdf(_context(), include_technical=False).content)
    assert len(pagine) <= 6, f"{len(pagine)} pagine: non e' piu' un documento per la direzione"


def test_la_copertina_sta_in_una_pagina():
    """Era alta quanto un A4 intero e sbordava: il blocco finale finiva su un
    secondo foglio quasi vuoto, con lo sfondo pieno."""
    pagine = _pagine(rs.generate_pdf(_context(), include_technical=False).content)

    assert "Distribuzione limitata" in pagine[0], "la copertina non e' completa"
    assert "Distribuzione limitata" not in pagine[1], "la copertina sborda sulla seconda pagina"


@pytest.mark.parametrize("sezione", [
    "Perimetro della valutazione",
    "Esposizione osservata",
    "Copertura degli strumenti",
])
def test_le_sezioni_tecniche_non_sono_nell_esecutivo(sezione):
    testo = "".join(_pagine(rs.generate_pdf(_context(), include_technical=False).content))
    assert sezione not in testo


@pytest.mark.parametrize("sezione", [
    "Perimetro della valutazione",
    "Esposizione osservata",
    "Copertura degli strumenti",
])
def test_le_sezioni_tecniche_sono_nell_allegato(sezione):
    """Spostate, non perse: chi verifica il lavoro deve ancora trovarle."""
    testo = "".join(_pagine(rs.generate_pdf(_context(), include_technical=True).content))
    assert sezione in testo


def test_l_esecutivo_rimanda_all_allegato():
    testo = "".join(_pagine(rs.generate_pdf(_context(), include_technical=False).content))
    assert "allegato tecnico" in testo


# --------------------------------------------------------------------------
def test_il_radar_compare_nel_rapporto():
    # Le aree le calcola `build_context` dal rating: qui si sostituiscono
    # dopo, perche' l'oggetto da provare e' il modello, non il motore.
    contesto = _context()
    contesto.categories = AREE
    testo = rs.generate_html(contesto, include_technical=False).content.decode("utf-8")

    assert "<svg" in testo and 'class="radar"' in testo
    for area in AREE:
        assert area["label_it"].split()[0] in testo


def test_sotto_le_tre_aree_il_radar_non_si_disegna():
    """Con due assi il radar degenera in un segmento: non aggiunge nulla alla
    tabella accanto, e un grafico che non dice niente e' peggio di nessuno."""
    assert grafico_radar(AREE[:2]) == ""
    assert grafico_radar([]) == ""


def test_il_radar_e_xml_valido():
    """Finisce dentro un PDF: un SVG malformato farebbe fallire la
    generazione, non solo il disegno."""
    import xml.etree.ElementTree as ET

    ET.fromstring(grafico_radar(AREE))


def test_i_punteggi_finiscono_sugli_assi_giusti():
    """Un'area a 100 tocca il bordo, una a 0 sta nel centro: se il disegno
    non rispettasse la scala, il grafico mentirebbe."""
    svg = grafico_radar([
        {"label_it": "Piena", "score": 100},
        {"label_it": "Vuota", "score": 0},
        {"label_it": "Meta", "score": 50},
    ])
    vertici = re.search(r'class="area" points="([^"]+)"', svg)
    assert vertici
    punti = [tuple(float(v) for v in coppia.split(",")) for coppia in vertici.group(1).split()]

    centro = (260.0, 168.0)
    distanze = [((x - centro[0]) ** 2 + (y - centro[1]) ** 2) ** 0.5 for x, y in punti]
    assert distanze[0] == pytest.approx(130.0, abs=0.2)   # 100 -> raggio pieno
    assert distanze[1] == pytest.approx(0.0, abs=0.2)     # 0   -> centro
    assert distanze[2] == pytest.approx(65.0, abs=0.2)    # 50  -> meta'


def test_un_colore_non_valido_non_entra_nel_foglio_di_stile():
    """Il colore arriva dalla personalizzazione del tenant e finisce in un
    blocco <style>, che non passa dall'autoescape dei template."""
    velenoso = '#fff"/><script>alert(1)</script><g fill="'
    svg = grafico_radar(AREE, colore=velenoso)

    assert "<script" not in svg
    assert COLORE_PREDEFINITO in svg
