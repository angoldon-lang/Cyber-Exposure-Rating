"""Impaginazione del PDF: i margini devono valere su tutte le pagine.

L'esecutivo e l'allegato tecnico sono documenti distinti, renderizzati
separatamente e con le pagine concatenate. Una regola scritta come
`@page :first` colpisce percio' la prima pagina di ciascuno dei due, non solo
la copertina.
"""
from __future__ import annotations

import io

import pytest

from tests.test_reports import _context

pytestmark = pytest.mark.slow

# Margine di pagina dichiarato nel foglio di stile.
MARGINE_MM = 16.0


def _bordi_sinistri_mm(contesto, modello: str) -> list[float]:
    """Il bordo sinistro del testo, pagina per pagina, in millimetri.

    La misura viene dall'albero di caselle di WeasyPrint, non dal PDF gia'
    scritto. Leggerla dal PDF significa ricomporre la posizione da due
    matrici, e per il testo annidato in un SVG quella ricomposizione non
    torna: il controllo segnalava a 12 e a 15 mm figure che, misurate al
    raster, stanno a 16. Qui la posizione la dichiara il motore di
    impaginazione, e le figure non compaiono affatto — un SVG e' una casella
    sostituita, il suo testo non sta nell'albero. E' esattamente cio' che
    serve: il margine da controllare e' quello del testo impaginato, non
    quello degli elementi dentro un disegno, che dipende dalla larghezza
    della figura.
    """
    from weasyprint import HTML
    from weasyprint.formatting_structure import boxes

    from reporting import service as rs

    def testi(casella):  # noqa: ANN001, ANN202
        if isinstance(casella, boxes.TextBox) and casella.text.strip():
            yield casella
        for figlia in getattr(casella, "children", ()):
            yield from testi(figlia)

    documento = HTML(string=rs.render_html(contesto, modello)).render()
    bordi: list[float] = []
    for pagina in documento.pages:
        trovati = [casella.position_x for casella in testi(pagina._page_box)]
        # WeasyPrint lavora in pixel CSS: 96 per pollice.
        bordi.append(min(trovati) / 96 * 25.4 if trovati else MARGINE_MM)
    return bordi


def test_l_allegato_tecnico_rispetta_i_margini():
    """Senza la correzione il testo dell'allegato partiva da 0 mm: attaccato al
    bordo del foglio."""
    for numero, bordo in enumerate(_bordi_sinistri_mm(_context(), "technical.html.j2"), 1):
        assert bordo >= MARGINE_MM - 0.5, (
            f"pagina {numero} dell'allegato: il testo inizia a {bordo:.1f} mm "
            f"invece di almeno {MARGINE_MM} mm")


def test_tutte_le_pagine_di_contenuto_rispettano_i_margini():
    """La copertina e' l'unica eccezione ammessa: occupa l'intera pagina e ha
    un suo margine interno."""
    bordi = _bordi_sinistri_mm(_context(), "executive.html.j2")

    fuori = [f"pagina {numero}: {bordo:.1f} mm"
             for numero, bordo in enumerate(bordi, 1)
             if numero > 1 and bordo < MARGINE_MM - 0.5]
    assert not fuori, "pagine con testo oltre il margine: " + ", ".join(fuori)


def test_la_copertina_usa_una_pagina_denominata():
    """La regola dev'essere legata alla copertina, non alla prima pagina del
    documento: i due documenti concatenati ne hanno una ciascuno."""
    from pathlib import Path

    css = (Path(__file__).resolve().parents[1]
           / "reporting" / "templates" / "base.css").read_text(encoding="utf-8")
    assert "@page copertina" in css
    assert ".cover { page: copertina; }" in css
    assert "@page :first" not in css, (
        "`:first` colpisce anche la prima pagina dell'allegato tecnico")


def test_l_apertura_sta_in_una_pagina():
    """Dopo la copertina, l'apertura del rapporto deve stare in un foglio
    solo: risultato, aree e perimetro.

    E' il punto in cui la pagina e' piena. Se un giorno non ci sta piu', va
    accorciata, non lasciata sbordare su un foglio quasi vuoto."""
    import pypdf

    from reporting import service as rs

    lettore = pypdf.PdfReader(
        io.BytesIO(rs.generate_pdf(_context(), include_technical=False).content))
    apertura = lettore.pages[1].extract_text() or ""

    assert "ACME Test S.p.A." in apertura
    assert "Il risultato in due righe" in apertura
    assert "Il perimetro osservato" in apertura, "l'apertura non sta piu' in una pagina"


def test_il_foglio_di_stile_non_passa_dall_autoescape():
    """L'autoescape trasformava ogni virgoletta del CSS in `&#34;`.

    Il documento continuava a uscire, e sembrava giusto: ma ogni stringa fra
    virgolette era rotta. `content: "Pagina "` non produceva nulla, quindi
    testatina e numerazione non c'erano; `font-family: "DejaVu Sans"` cadeva
    sul ripiego generico, quindi il documento non usava nemmeno i caratteri
    dichiarati. Un guasto silenzioso, durato finche' qualcuno non ha contato
    le pagine stampate."""
    from reporting import service as rs

    html = rs.render_html(_context(), "executive.html.j2")
    stile = html.split("<style>", 1)[1].split("</style>", 1)[0]

    assert "&#34;" not in stile and "&quot;" not in stile
    assert '"DejaVu Sans"' in stile


def test_ogni_pagina_e_numerata_e_intestata():
    """Un documento che circola senza numero di pagina non si cita e non si
    ricompone se qualcuno lo stampa e lo sfoglia.

    La numerazione riparte da uno sull'allegato, perche' i due documenti sono
    renderizzati separatamente: per questo l'allegato lo dichiara nel piede,
    invece di presentare un secondo «pagina 1 di 4» senza spiegazione."""
    import pypdf

    from reporting import service as rs

    lettore = pypdf.PdfReader(
        io.BytesIO(rs.generate_pdf(_context(), include_technical=True).content))

    piedi = []
    for numero, pagina in enumerate(lettore.pages, 1):
        testo = " ".join((pagina.extract_text() or "").split())
        if numero == 1:
            continue  # la copertina non porta piede: e' una pagina a tutto sfondo
        assert "Documento riservato" in testo, f"pagina {numero} senza la riserva"
        assert "ACME" in testo, f"pagina {numero} senza il nome dell'organizzazione"
        piedi.append("Allegato tecnico - pagina" if "Allegato tecnico - pagina" in testo
                     else "Pagina" if "Pagina" in testo else "")

    assert "" not in piedi, "ci sono pagine senza numerazione"
    assert "Pagina" in piedi and "Allegato tecnico - pagina" in piedi
    # Prima l'esecutivo, poi l'allegato: mai alternati.
    assert piedi == sorted(piedi, key=lambda voce: voce.startswith("Allegato"))
