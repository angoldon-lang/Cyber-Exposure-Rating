"""La sezione di contesto apre il rapporto per la direzione.

Sono due pagine di dati di settore che spiegano perche' l'esposizione esterna
vada misurata: la finestra fra divulgazione e sfruttamento, dove si concentra
il rischio realmente sfruttabile, quanto pesa l'esposizione collegata a
identita' privilegiate.

Attiva salvo diversa indicazione, e togliibile dalla personalizzazione: chi
consegna a un destinatario che quel contesto lo ha gia' preferisce due pagine
in meno.
"""
from __future__ import annotations

import io
import xml.etree.ElementTree as ET

import pytest

from reporting import service as rs
from reporting.figure_contesto import dove_sta_il_rischio, finestra_di_sfruttamento
from tests.test_reports import _context

pytestmark = pytest.mark.slow


def _testo(pdf: bytes) -> str:
    import pypdf

    return "".join(p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)


def _pagine(pdf: bytes) -> int:
    import pypdf

    return len(pypdf.PdfReader(io.BytesIO(pdf)).pages)


def _contesto(attiva: bool):  # noqa: ANN202
    contesto = _context()
    contesto.brand = {**contesto.brand, "show_context_section": attiva}
    return contesto


def test_la_sezione_compare_quando_attiva():
    testo = _testo(rs.generate_pdf(_contesto(True), include_technical=False).content)

    assert "Perche" in testo and "questa valutazione" in testo
    assert "finestra di reazione" in testo
    assert "Cosa misura questo documento" in testo


def test_la_spunta_la_toglie_davvero():
    """Togliere la spunta deve togliere le pagine, non nascondere il titolo."""
    con = rs.generate_pdf(_contesto(True), include_technical=False).content
    senza = rs.generate_pdf(_contesto(False), include_technical=False).content

    assert "questa valutazione" not in _testo(senza)
    assert _pagine(senza) < _pagine(con)


def test_e_attiva_per_chi_non_ha_mai_toccato_la_personalizzazione():
    """Un tenant senza riga di personalizzazione non deve perdere la sezione."""
    contesto = _context()
    contesto.brand = {k: v for k, v in contesto.brand.items() if k != "show_context_section"}

    assert "questa valutazione" in _testo(
        rs.generate_pdf(contesto, include_technical=False).content)


def test_non_finisce_nell_allegato_tecnico():
    """L'allegato lo legge chi verifica il lavoro: li' il contesto e' gia' dato."""
    modello = (rs.render_html(_contesto(True), "technical.html.j2"))

    assert "questa valutazione" not in modello


# ------------------------------------------------------------------- figure
@pytest.mark.parametrize("figura", [finestra_di_sfruttamento, dove_sta_il_rischio])
def test_le_figure_sono_svg_validi(figura):
    """Finiscono dentro un PDF: un SVG malformato farebbe fallire la
    generazione, non solo il disegno."""
    ET.fromstring(figura())


def test_la_fonte_dei_dati_e_citata():
    """I dati sono di terzi. Citarli con la fonte e' prassi; ometterla no."""
    testo = _testo(rs.generate_pdf(_contesto(True), include_technical=False).content)

    assert "Wiz Research" in testo
    assert "The State of Cloud Risk 2026" in testo


def test_le_figure_non_contengono_marchi_di_terzi():
    """Il disegno e' nostro: le figure originali portano il marchio di un
    fornitore concorrente e non sono riutilizzabili."""
    for figura in (finestra_di_sfruttamento(), dove_sta_il_rischio()):
        assert "WIZ" not in figura.upper()


def test_la_scala_logaritmica_e_dichiarata():
    """Fra 2,3 anni e 21,5 giorni ci sono due ordini di grandezza: senza
    dirlo, l'altezza delle barre sarebbe fuorviante."""
    testo = _testo(rs.generate_pdf(_contesto(True), include_technical=False).content)

    assert "logaritmica" in testo
