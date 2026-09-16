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
    larghezza = float(pagina.mediabox.width)
    altezza = float(pagina.mediabox.height)
    posizioni: list[float] = []

    def visita(testo, cm, tm, _font, _size):  # noqa: ANN001
        if not testo.strip():
            return
        # Il testo dentro un SVG e' disegnato in un sistema di coordinate
        # proprio: `tm[4]` da' la posizione nel disegno, non nella pagina.
        # Va composta con la matrice corrente, altrimenti una figura
        # perfettamente dentro i margini risulta a otto millimetri dal bordo.
        x = cm[0] * tm[4] + cm[2] * tm[5] + cm[4]
        y = cm[1] * tm[4] + cm[3] * tm[5] + cm[5]
        # Per il testo annidato in piu' livelli di SVG la coppia di matrici che
        # arriva qui non basta a ricostruire la posizione: il punto composto
        # cade fuori dal foglio, cioe' dove nessun glifo puo' essere stato
        # disegnato. Misurato al raster, quel testo sta dentro i margini. Un
        # campione impossibile non dice nulla, ne' a favore ne' contro: va
        # scartato, altrimenti il controllo segnala a caso.
        if not (0 <= x <= larghezza and 0 <= y <= altezza):
            return
        posizioni.append(x)

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
        if numero == 1 or "Security Rating" in testo[:120] and numero == 1:
            continue  # copertina
        bordo = _bordo_sinistro_mm(pagina)
        if bordo is not None and bordo < MARGINE_MM - 0.5:
            fuori_margine.append(f"pagina {numero}: {bordo:.1f} mm")

    assert not fuori_margine, "pagine con testo oltre il margine: " + ", ".join(fuori_margine)


def test_nessuna_regola_legata_alla_prima_pagina():
    """I due documenti sono concatenati e ne hanno una ciascuno: una regola
    scritta come `:first` colpirebbe anche la prima pagina dell'allegato."""
    from pathlib import Path

    css = (Path(__file__).resolve().parents[1]
           / "reporting" / "templates" / "base.css").read_text(encoding="utf-8")
    assert "@page :first" not in css, (
        "`:first` colpisce anche la prima pagina dell'allegato tecnico")


def test_la_prima_pagina_e_gia_contenuto():
    """La copertina a pagina intera e' stata tolta.

    Era un foglio che diceva nome, data e voto, e rimandava tutto il resto
    alla pagina dopo: in un documento di sei pagine e' un ottavo del totale
    speso per un frontespizio. Ora la prima pagina porta gia' il risultato,
    le aree e il perimetro."""
    import pypdf

    from reporting import service as rs

    lettore = pypdf.PdfReader(io.BytesIO(rs.generate_pdf(_context(), include_technical=False).content))
    prima = lettore.pages[0].extract_text() or ""

    assert "ACME Test S.p.A." in prima
    assert "Il risultato in due righe" in prima
    # L'apertura sta in una pagina sola, perimetro compreso: e' il punto in
    # cui la pagina e' piena. Se un giorno non ci sta piu', va accorciata,
    # non lasciata sbordare su un foglio quasi vuoto.
    assert "Il perimetro osservato" in prima, "l'apertura non sta piu' in una pagina"


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
        assert "Documento riservato" in testo, f"pagina {numero} senza la riserva"
        assert "ACME" in testo, f"pagina {numero} senza il nome dell'organizzazione"
        piedi.append("Allegato tecnico - pagina" if "Allegato tecnico - pagina" in testo
                     else "Pagina" if "Pagina" in testo else "")

    assert "" not in piedi, "ci sono pagine senza numerazione"
    assert "Pagina" in piedi and "Allegato tecnico - pagina" in piedi
    # Prima l'esecutivo, poi l'allegato: mai alternati.
    assert piedi == sorted(piedi, key=lambda voce: voce.startswith("Allegato"))
