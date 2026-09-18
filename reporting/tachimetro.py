"""Indicatore a quadrante del punteggio complessivo.

«69/100, classe C» e' esatto e non dice niente a colpo d'occhio: bisogna
sapere a memoria dove cadono le soglie per capire se 69 sia un buon numero.
Un quadrante lo mostra: l'ago su un arco che va dal rosso al verde dice
subito in che parte della scala si sta.

Il colore non e' l'unico segnale. Le soglie delle classi sono marcate sul
quadrante, la classe e' scritta sotto e il numero resta al centro: il
disegno regge anche stampato in bianco e nero, o letto da chi non distingue
il rosso dal verde.

SVG calcolato qui, come il radar: WeasyPrint lo compone come vettoriale nel
PDF, senza font esterni, senza JavaScript e senza risorse da risolvere
durante la generazione.
"""
from __future__ import annotations

import math

# Le bande coincidono con le classi di `config/scoring.yaml`: un quadrante che
# cambiasse colore a soglie proprie direbbe una cosa diversa dalla lettera
# stampata sotto. Tenerle qui duplicate sarebbe un disallineamento in attesa
# di accadere, percio' vengono lette dalla configurazione.
_COLORI_CLASSE = {
    "E": "#b91c1c",   # rosso
    "D": "#ea580c",   # arancio
    "C": "#d99a00",   # giallo
    "B": "#7ba428",   # verde chiaro
    "A": "#1d7a3a",   # verde
}
_COLORE_IGNOTO = "#9ca3af"

LARGHEZZA = 420
# Il numero sta SOTTO il perno, fuori dal semicerchio. Messo al centro
# dell'arco finiva sotto l'ago ogni volta che il punteggio cadeva a meta'
# scala: due segni che si contendono lo stesso pixel, e il piu' importante
# dei due e' il numero.
ALTEZZA = 298
# L'ordinata del perno lascia sopra l'arco lo spazio dell'etichetta di soglia
# piu' alta, quella al culmine: a 180 la sua cima finiva tagliata dal bordo
# dell'SVG.
CENTRO = 210.0, 192.0
RAGGIO = 150.0
SPESSORE = 26.0

# L'arco copre mezzo giro: da sinistra (0) a destra (100). Un quadrante
# completo costringerebbe a cercare dove comincia la scala.
_ANGOLO_ZERO = math.pi
_ANGOLO_CENTO = 0.0


def _bande() -> list[dict]:
    from app.core.config import load_yaml_config

    classi = load_yaml_config("scoring")["classes"]
    return sorted(
        ({"code": str(c["code"]), "min": float(c["min"]), "max": float(c["max"])}
         for c in classi),
        key=lambda c: c["min"])


def _angolo(valore: float) -> float:
    quota = max(0.0, min(valore, 100.0)) / 100.0
    return _ANGOLO_ZERO + (_ANGOLO_CENTO - _ANGOLO_ZERO) * quota


def _punto(angolo: float, raggio: float) -> tuple[float, float]:
    # L'asse y dell'SVG cresce verso il basso: il seno va sottratto, altrimenti
    # il quadrante si disegna capovolto sotto l'asse.
    return CENTRO[0] + raggio * math.cos(angolo), CENTRO[1] - raggio * math.sin(angolo)


def _arco(da: float, a: float, raggio: float) -> str:
    """Comando SVG per l'arco fra due punteggi, sul raggio dato."""
    x1, y1 = _punto(_angolo(da), raggio)
    x2, y2 = _punto(_angolo(a), raggio)
    # `sweep-flag` a 1: si procede in senso orario, da sinistra verso destra.
    return f"M {x1:.1f},{y1:.1f} A {raggio:.1f},{raggio:.1f} 0 0 1 {x2:.1f},{y2:.1f}"


def colore_della_classe(classe: str) -> str:
    return _COLORI_CLASSE.get(str(classe).upper(), _COLORE_IGNOTO)


def quadrante(punteggio: float | None, *, classe: str = "",
              etichetta: str = "", su_fondo_scuro: bool = False) -> str:
    """Quadrante del punteggio complessivo.

    `punteggio` a `None` disegna la scala senza ago: e' il caso della
    valutazione provvisoria, dove un ago fermo su un numero suggerirebbe una
    misura che non e' stata fatta.
    """
    inchiostro = "#ffffff" if su_fondo_scuro else "#12161c"
    tenue = "#b9d4e6" if su_fondo_scuro else "#5c6470"

    parti: list[str] = [
        f'<svg class="tachimetro" xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {LARGHEZZA} {ALTEZZA}" role="img" '
        f'aria-label="Punteggio {punteggio if punteggio is not None else "non disponibile"} '
        f'su cento">',
        '<g fill="none" stroke-linecap="butt">',
    ]

    # Le bande colorate coprono l'arco per intero: nessun fondo sotto, che
    # affiorerebbe per mezzo pixel lungo il bordo esterno.
    for banda in _bande():
        # `max` e' inclusivo nella configurazione (A va da 85 a 100): l'arco
        # deve arrivare al punto in cui comincia la banda successiva, non a
        # uno in meno, altrimenti restano cinque righe bianche sul quadrante.
        fine = banda["max"] + (0.0 if banda["max"] >= 100.0 else 1.0)
        parti.append(
            f'<path d="{_arco(banda["min"], fine, RAGGIO)}" '
            f'stroke="{colore_della_classe(banda["code"])}" stroke-width="{SPESSORE}"/>')
    parti.append("</g>")

    # Le soglie: dove finisce una classe e comincia l'altra.
    for banda in _bande()[1:]:
        angolo = _angolo(banda["min"])
        x1, y1 = _punto(angolo, RAGGIO - SPESSORE / 2)
        x2, y2 = _punto(angolo, RAGGIO + SPESSORE / 2)
        parti.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                     f'stroke="#ffffff" stroke-width="1.5" opacity=".75"/>')
        xt, yt = _punto(angolo, RAGGIO + SPESSORE / 2 + 12)
        parti.append(f'<text x="{xt:.1f}" y="{yt:.1f}" text-anchor="middle" '
                     f'font-size="11" fill="{tenue}" '
                     f'font-family="DejaVu Sans, Helvetica, sans-serif">'
                     f'{banda["min"]:.0f}</text>')

    # Gli estremi della scala.
    for valore, ancora in ((0, "end"), (100, "start")):
        x, y = _punto(_angolo(valore), RAGGIO + SPESSORE / 2 + 12)
        parti.append(f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{ancora}" '
                     f'font-size="11" fill="{tenue}" '
                     f'font-family="DejaVu Sans, Helvetica, sans-serif">{valore}</text>')

    if punteggio is not None:
        angolo = _angolo(float(punteggio))
        punta = _punto(angolo, RAGGIO - SPESSORE - 10)
        # La coda dell'ago sta dall'altra parte del perno: senza, l'ago sembra
        # spuntare dal nulla.
        coda_sinistra = _punto(angolo + math.pi / 2, 7)
        coda_destra = _punto(angolo - math.pi / 2, 7)
        parti.append(
            f'<polygon points="{punta[0]:.1f},{punta[1]:.1f} '
            f'{coda_sinistra[0]:.1f},{coda_sinistra[1]:.1f} '
            f'{coda_destra[0]:.1f},{coda_destra[1]:.1f}" fill="{inchiostro}"/>')
        parti.append(f'<circle cx="{CENTRO[0]:.1f}" cy="{CENTRO[1]:.1f}" r="9" '
                     f'fill="{inchiostro}"/>')
        parti.append(
            f'<text x="{CENTRO[0]:.1f}" y="{CENTRO[1] + 62:.1f}" text-anchor="middle" '
            f'font-size="56" font-weight="700" fill="{inchiostro}" '
            f'font-family="DejaVu Serif, Georgia, serif">{float(punteggio):.0f}'
            f'<tspan font-size="21" font-weight="400" fill="{tenue}">/100</tspan></text>')
    else:
        parti.append(
            f'<text x="{CENTRO[0]:.1f}" y="{CENTRO[1] + 56:.1f}" text-anchor="middle" '
            f'font-size="27" fill="{tenue}" '
            f'font-family="DejaVu Serif, Georgia, serif">non disponibile</text>')

    sottotitolo = " \u2014 ".join(
        x for x in ((f"Classe {classe}" if classe else ""), etichetta) if x)
    if sottotitolo:
        parti.append(
            f'<text x="{CENTRO[0]:.1f}" y="{CENTRO[1] + 92:.1f}" text-anchor="middle" '
            f'font-size="17" fill="{inchiostro}" '
            f'font-family="DejaVu Serif, Georgia, serif">{_pulito(sottotitolo)}</text>')

    parti.append("</svg>")
    return "".join(parti)


def _pulito(testo: str) -> str:
    """Il sottotitolo finisce in un SVG che il modello inserisce con `|safe`.

    Arriva dalla configurazione del rating, non da Internet, ma il testo di
    una classe e' pur sempre un dato: neutralizzare i caratteri che chiudono
    un tag costa una riga ed evita di doverci ripensare il giorno in cui
    quelle etichette diventeranno modificabili dal tenant.
    """
    return (testo.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
