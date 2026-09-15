"""Un report su dati sintetici deve dichiararlo.

`Scan.mock_mode` esisteva da sempre, ma il report non ne faceva nulla: un
documento dimostrativo era indistinguibile da una valutazione reale. Prima o
poi uno finisce allegato a un'offerta, o viene letto come se descrivesse
davvero l'organizzazione.
"""
from __future__ import annotations

import io

import pytest

from reporting import service as rs
from tests.test_reports import _context

pytestmark = pytest.mark.slow


def _pagine(pdf: bytes) -> list[str]:
    import pypdf

    return [p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(pdf)).pages]


def _contesto(dimostrativo: bool):  # noqa: ANN202
    contesto = _context()
    contesto.is_demo = dimostrativo
    return contesto


def test_la_copertina_lo_dichiara():
    pagine = _pagine(rs.generate_pdf(_contesto(True), include_technical=False).content)

    assert "dimostrativo" in pagine[0].lower()


def test_la_filigrana_e_su_ogni_pagina():
    """Un documento si stampa e si sfoglia anche a partire dal mezzo: la sola
    copertina non basta."""
    pagine = _pagine(rs.generate_pdf(_contesto(True), include_technical=True).content)

    senza = [n for n, testo in enumerate(pagine, 1) if "DIMOSTRATIVI" not in testo]
    assert not senza, f"pagine senza filigrana: {senza}"


def test_l_allegato_tecnico_lo_dichiara():
    testo = "".join(_pagine(rs.generate_pdf(_contesto(True), include_technical=True).content))

    assert "Documento dimostrativo" in testo


def test_un_report_reale_non_porta_alcun_marchio():
    """E' la meta' che conta di piu': se comparisse su una valutazione vera,
    il marchio perderebbe ogni significato."""
    testo = "".join(_pagine(rs.generate_pdf(_contesto(False), include_technical=True).content))

    assert "DIMOSTRATIVI" not in testo
    assert "dimostrativo" not in testo.lower()


def test_il_contrassegno_arriva_dalla_scansione():
    """Non e' una scelta di chi genera il report: e' un fatto della
    scansione, e viene da li'."""
    from reporting.context import build_context

    def _minimo(mock: bool):  # noqa: ANN202
        base = _context()
        return build_context(
            company={"legal_name": base.company_name, "vat_number": None},
            scan={"profile_key": base.profile_key, "scope_snapshot": {}, "mock_mode": mock},
            score={"overall_score": 50, "rating_class": "C", "confidence": {"value": 80},
                   "is_provisional": False, "categories": []},
            findings=[], remediation_plan=[], quick_win_items=[], comparison=None,
            coverage_matrix=[], exposure={})

    assert _minimo(True).is_demo is True
    assert _minimo(False).is_demo is False
