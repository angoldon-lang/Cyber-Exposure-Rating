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


def _bordo_sinistro_mm(pagina) -> float | None:  # noqa: ANN001
    posizioni: list[float] = []

    def visita(testo, _cm, tm, _font, _size):  # noqa: ANN001
        if testo.strip():
            posizioni.append(tm[4])

    pagina.extract_text(visitor_text=visita)
    return min(posizioni) / 72 * 25.4 if posizioni else None


def test_l_allegato_tecnico_rispetta_i_margini():
    """Senza la correzione il testo dell'allegato partiva da 0 mm: attaccato al
    bordo del foglio."""
    import pypdf

    from reporting import service as rs

    pdf = rs.generate_pdf(_context(), include_technical=True)
    lettore = pypdf.PdfReader(io.BytesIO(pdf.content))

    pagina_allegato = next(
        (p for p in lettore.pages if "Allegato tecnico" in (p.extract_text() or "")), None)
    assert pagina_allegato is not None, "l'allegato tecnico non e' nel documento"

    bordo = _bordo_sinistro_mm(pagina_allegato)
    assert bordo is not None
    assert bordo >= MARGINE_MM - 0.5, (
        f"il testo dell'allegato inizia a {bordo:.1f} mm invece di almeno {MARGINE_MM} mm")


def test_tutte_le_pagine_di_contenuto_rispettano_i_margini():
    """La copertina e' l'unica eccezione ammessa: occupa l'intera pagina."""
    import pypdf

    from reporting import service as rs

    pdf = rs.generate_pdf(_context(), include_technical=True)
    lettore = pypdf.PdfReader(io.BytesIO(pdf.content))

    fuori_margine = []
    for numero, pagina in enumerate(lettore.pages, 1):
        testo = pagina.extract_text() or ""
        if numero == 1 or "Exposure Rating" in testo[:120] and numero == 1:
            continue  # copertina
        bordo = _bordo_sinistro_mm(pagina)
        if bordo is not None and bordo < MARGINE_MM - 0.5:
            fuori_margine.append(f"pagina {numero}: {bordo:.1f} mm")

    assert not fuori_margine, "pagine con testo oltre il margine: " + ", ".join(fuori_margine)


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
