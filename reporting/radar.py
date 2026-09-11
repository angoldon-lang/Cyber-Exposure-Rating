"""Diagramma radar dei punteggi per area tematica.

Il rapporto per la direzione elenca le aree in tabella: leggerle una per una
non dice dove l'esposizione sia concentrata, che e' la sola domanda a cui la
direzione deve rispondere. Un radar la mostra in un colpo d'occhio.

SVG calcolato qui, non una libreria di grafici: WeasyPrint lo compone come
vettoriale nel PDF, senza font esterni, senza JavaScript e senza risorse da
risolvere durante la generazione. Il documento resta un file solo.
"""
from __future__ import annotations

import math
import re
from typing import Any

# Il colore arriva dalla personalizzazione del tenant e finisce dentro un
# blocco <style>, che non passa dall'autoescape dei template: va riverificato
# qui, non solo dove viene salvato.
_COLORE_AMMESSO = re.compile(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})")
COLORE_PREDEFINITO = "#1f4e79"

LIVELLI = (25, 50, 75, 100)
RAGGIO = 130.0
# Il margine laterale non e' estetico: un'etichetta ancorata a sinistra si
# allunga verso l'esterno, e con un riquadro stretto il testo viene tagliato
# dal bordo dell'SVG. «Minacce ransomware» spariva a meta'.
CENTRO = 260.0, 168.0
ALTEZZA = 348
LARGHEZZA = 520


def _punto(indice: int, totale: int, valore: float) -> tuple[float, float]:
    """Coordinate del punto sull'asse `indice` a `valore` su cento.

    Si parte da mezzogiorno e si gira in senso orario: e' il verso con cui si
    legge un quadrante, e mette la prima area in alto invece che a destra.
    """
    angolo = -math.pi / 2 + (2 * math.pi * indice / totale)
    distanza = RAGGIO * max(0.0, min(valore, 100.0)) / 100.0
    return (CENTRO[0] + distanza * math.cos(angolo),
            CENTRO[1] + distanza * math.sin(angolo))


def _poligono(totale: int, valore: float) -> str:
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in
                    (_punto(i, totale, valore) for i in range(totale)))


def _etichetta(indice: int, totale: int, testo: str) -> str:
    """Etichetta d'asse, ancorata dal lato in cui si allontana dal centro."""
    x, y = _punto(indice, totale, 118)
    if x > CENTRO[0] + 6:
        ancora = "start"
    elif x < CENTRO[0] - 6:
        ancora = "end"
    else:
        ancora = "middle"

    # Le etichette lunghe mandano il testo fuori pagina: si spezzano sugli
    # spazi in righe di lunghezza ragionevole.
    righe: list[str] = []
    corrente = ""
    for parola in testo.split():
        if not corrente or len(corrente) + len(parola) + 1 <= 14:
            # `not corrente`: una parola piu' lunga del limite deve comunque
            # finire su una riga. Senza questa condizione si apriva una riga
            # vuota e l'ultima parola veniva poi scartata dal taglio:
            # «Vulnerabilita' note» si leggeva «Vulnerabilita'».
            corrente = f"{corrente} {parola}".strip()
        else:
            righe.append(corrente)
            corrente = parola
    if corrente:
        righe.append(corrente)
    # Tre righe, non due: con due, «Superficie di attacco esposta» perdeva
    # «esposta» e l'etichetta diceva un'altra cosa.
    righe = righe[:3]

    # Sopra il centro il blocco va alzato di tutta la propria altezza, cosi'
    # non copre il grafico.
    scarto = -4.0 if y < CENTRO[1] else 10.0
    if y < CENTRO[1] and len(righe) > 1:
        scarto -= 9.0 * (len(righe) - 1)

    parti = [f'<text x="{x:.1f}" y="{y + scarto:.1f}" text-anchor="{ancora}" class="asse">']
    for numero, riga in enumerate(righe):
        dy = 0 if numero == 0 else 9
        parti.append(f'<tspan x="{x:.1f}" dy="{dy}">{_xml(riga)}</tspan>')
    parti.append("</text>")
    return "".join(parti)


def _xml(testo: str) -> str:
    return (testo.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def grafico_radar(categorie: list[dict[str, Any]], *,
                  colore: str = COLORE_PREDEFINITO) -> str:
    """SVG del radar, o stringa vuota se non c'e' niente da disegnare.

    Sotto le tre aree un radar degenera in un triangolo o in un segmento, che
    non aggiunge nulla alla tabella accanto: in quel caso non si disegna.
    """
    aree = [c for c in categorie if c.get("label_it")]
    if len(aree) < 3:
        return ""
    if not _COLORE_AMMESSO.fullmatch(colore or ""):
        colore = COLORE_PREDEFINITO

    totale = len(aree)
    parti: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{LARGHEZZA}" height="{ALTEZZA}" '
        f'viewBox="0 0 {LARGHEZZA} {ALTEZZA}" class="radar">',
        "<style>"
        ".griglia{fill:none;stroke:#c8cdd4;stroke-width:.6}"
        ".raggio{stroke:#c8cdd4;stroke-width:.6}"
        f".area{{fill:{colore};fill-opacity:.18;stroke:{colore};stroke-width:1.6;"
        "stroke-linejoin:round}"
        f".nodo{{fill:{colore}}}"
        ".asse{font-family:inherit;font-size:7.5pt;fill:#3d4450}"
        ".livello{font-family:inherit;font-size:6.5pt;fill:#9aa1ab}"
        "</style>",
    ]

    for livello in LIVELLI:
        parti.append(f'<polygon class="griglia" points="{_poligono(totale, livello)}"/>')
    # Il 100 in alto dice che l'asse cresce verso l'esterno: senza, un
    # poligono piccolo si puo' leggere come «poco esposto».
    parti.append(f'<text x="{CENTRO[0] + 3:.1f}" y="{CENTRO[1] - RAGGIO + 8:.1f}" '
                 'class="livello">100</text>')

    for indice, area in enumerate(aree):
        x, y = _punto(indice, totale, 100)
        parti.append(f'<line class="raggio" x1="{CENTRO[0]:.1f}" y1="{CENTRO[1]:.1f}" '
                     f'x2="{x:.1f}" y2="{y:.1f}"/>')

    punteggi = [float(area.get("score") or 0.0) for area in aree]
    vertici = [_punto(i, totale, valore) for i, valore in enumerate(punteggi)]
    parti.append('<polygon class="area" points="'
                 + " ".join(f"{x:.1f},{y:.1f}" for x, y in vertici) + '"/>')
    for x, y in vertici:
        parti.append(f'<circle class="nodo" cx="{x:.1f}" cy="{y:.1f}" r="2.2"/>')

    for indice, area in enumerate(aree):
        parti.append(_etichetta(indice, totale, str(area["label_it"])))

    parti.append("</svg>")
    return "".join(parti)
