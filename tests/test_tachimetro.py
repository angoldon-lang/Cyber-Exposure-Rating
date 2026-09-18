"""Il quadrante del punteggio complessivo.

«69/100, classe C» e' esatto e non dice niente a colpo d'occhio: bisogna
sapere a memoria dove cadono le soglie. Il quadrante lo mostra, ma solo se
le sue bande coincidono con le classi del modello di rating: un disegno che
colorasse di verde un punteggio che la lettera dichiara insufficiente
direbbe una cosa diversa dal testo stampato sotto.
"""
from __future__ import annotations

import math
import re
import xml.etree.ElementTree as ET

import pytest

from app.core.config import load_yaml_config
from reporting import tachimetro as tm


def _classi() -> list[dict]:
    return load_yaml_config("scoring")["classes"]


def test_ogni_classe_ha_il_suo_colore():
    """Una classe senza colore finirebbe grigia sul quadrante, cioe' priva
    del solo segnale che il quadrante aggiunge al numero."""
    for classe in _classi():
        assert tm.colore_della_classe(classe["code"]) != tm._COLORE_IGNOTO


def test_le_bande_coprono_la_scala_senza_buchi():
    bande = tm._bande()

    assert bande[0]["min"] == 0
    assert bande[-1]["max"] == 100
    for precedente, successiva in zip(bande, bande[1:], strict=False):
        assert successiva["min"] == precedente["max"] + 1, (
            f"fra {precedente['code']} e {successiva['code']} la scala si interrompe")


def test_il_colore_va_dal_rosso_al_verde():
    """Il verso conta: un quadrante con il verde a sinistra direbbe il
    contrario di quel che si legge."""
    ordinate = sorted(_classi(), key=lambda c: c["min"])
    rosso, verde = (tm.colore_della_classe(ordinate[0]["code"]),
                    tm.colore_della_classe(ordinate[-1]["code"]))

    def canali(colore: str) -> tuple[int, int]:
        return int(colore[1:3], 16), int(colore[3:5], 16)

    assert canali(rosso)[0] > canali(rosso)[1], "la banda peggiore non e' rossa"
    assert canali(verde)[1] > canali(verde)[0], "la banda migliore non e' verde"


def test_l_ago_punta_dove_dice_il_numero():
    """Se l'ago non seguisse la scala, il disegno mentirebbe: e' il segnale
    che si guarda per primo."""
    for punteggio, atteso in ((0, math.pi), (50, math.pi / 2), (100, 0.0)):
        assert tm._angolo(punteggio) == pytest.approx(atteso, abs=1e-9)

    # A meta' scala l'ago e' verticale: stessa ascissa del perno.
    punta = tm._punto(tm._angolo(50), tm.RAGGIO)
    assert punta[0] == pytest.approx(tm.CENTRO[0], abs=0.01)
    assert punta[1] < tm.CENTRO[1], "il quadrante e' disegnato capovolto"


def test_un_punteggio_fuori_scala_non_esce_dal_quadrante():
    for fuori in (-40, 140):
        assert 0.0 <= tm._angolo(fuori) <= math.pi


def test_il_quadrante_e_xml_valido():
    """Finisce dentro un PDF: un SVG malformato farebbe fallire la
    generazione, non solo il disegno."""
    for punteggio in (0, 39, 69, 85, 100, None):
        ET.fromstring(tm.quadrante(punteggio, classe="C", etichetta="Esposizione significativa"))


def test_il_numero_resta_scritto_sul_disegno():
    """Il colore non puo' essere l'unico segnale: il documento si stampa in
    bianco e nero, e non tutti distinguono il rosso dal verde."""
    svg = tm.quadrante(69, classe="C", etichetta="Esposizione significativa")

    assert ">69<" in svg.replace(" ", "") or "69" in re.sub(r"<[^>]+>", "", svg)
    testo = re.sub(r"<[^>]+>", " ", svg)
    assert "Classe C" in testo
    assert "Esposizione significativa" in testo
    # Le soglie sono scritte sul quadrante, non solo colorate.
    for soglia in ("40", "55", "70", "85"):
        assert soglia in testo


def test_la_valutazione_provvisoria_non_ha_ago():
    """Un ago fermo su un numero suggerirebbe una misura che non e' stata
    fatta."""
    svg = tm.quadrante(None)

    assert "<polygon" not in svg
    assert "non disponibile" in re.sub(r"<[^>]+>", " ", svg)


def test_l_etichetta_della_classe_non_puo_chiudere_un_tag():
    """Il sottotitolo finisce in un SVG inserito nel modello con `|safe`."""
    svg = tm.quadrante(50, classe="C", etichetta='</text><script>alert(1)</script>')

    assert "<script" not in svg
    ET.fromstring(svg)


@pytest.mark.slow
def test_il_quadrante_compare_in_copertina_e_nel_corpo():
    from tests.test_reports import _context

    from reporting import service as rs

    html = rs.generate_html(_context(), include_technical=False).content.decode("utf-8")

    assert html.count('class="tachimetro"') == 2, (
        "il quadrante deve comparire in copertina e nel riquadro del risultato")
    # In copertina il fondo e' scuro: l'inchiostro deve essere chiaro.
    copertina = html.split('class="rating-block"', 1)[1]
    assert 'fill="#ffffff"' in copertina
