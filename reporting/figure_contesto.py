"""Figure della sezione di contesto del rapporto per la direzione.

I dati provengono da una ricerca pubblica di terzi e sono citati con la
fonte, come si fa in qualsiasi documento professionale. Il disegno e' nostro:
le figure originali non sono riutilizzabili — sono materiale protetto e
portano il marchio di un fornitore concorrente, che non ha alcun motivo di
comparire in un documento consegnato a un cliente.

SVG calcolato, come per il radar: WeasyPrint lo compone come vettoriale nel
PDF, senza font esterni ne' risorse da risolvere durante la generazione.
"""
from __future__ import annotations

BLU = "#1f4e79"
BLU_CHIARO = "#4a86b8"
GRIGIO = "#9aa1ab"
INCHIOSTRO = "#12161c"


def finestra_di_sfruttamento() -> str:
    """Quanto tempo passa fra la pubblicazione di una falla e il suo uso.

    Barre in scala logaritmica: fra 2,3 anni e 21,5 giorni ci sono due ordini
    di grandezza, e in scala lineare le colonne recenti sparirebbero.
    """
    import math

    anni = [("2018", 840), ("2019", 620), ("2020", 475), ("2021", 304),
            ("2022", 262), ("2023", 128), ("2024", 53), ("2025", 21.5)]
    # L'etichetta dell'ultima barra si allunga oltre il centro della barra
    # stessa: senza margine a destra, «21,5 giorni» veniva tagliato dal bordo.
    larghezza, altezza = 560, 210
    base_y, sinistra, destra = 160.0, 48.0, 505.0
    passo = (destra - sinistra) / (len(anni) - 1)

    def y(giorni: float) -> float:
        # log10 fra 10 e 1000 giorni mappato sull'altezza disponibile
        frazione = (math.log10(giorni) - 1.0) / 2.0
        return base_y - frazione * 118.0

    # Nessun `width`/`height` fisso: con il solo `viewBox` la dimensione la
    # decide il foglio di stile, e il contenuto scala insieme al riquadro.
    # Con gli attributi, il disegno usciva dal margine di pagina.
    parti = [f'<svg xmlns="http://www.w3.org/2000/svg" '
             f'viewBox="0 0 {larghezza} {altezza}" '
             f'preserveAspectRatio="xMidYMid meet">',
             "<style>"
             f".barra{{fill:{BLU};opacity:.85}}"
             f".etichetta{{font-family:inherit;font-size:7pt;fill:{INCHIOSTRO};font-weight:700}}"
             f".anno{{font-family:inherit;font-size:7pt;fill:{GRIGIO}}}"
             f".asse{{stroke:#dfe3e8;stroke-width:.8}}"
             "</style>"]

    parti.append(f'<line class="asse" x1="{sinistra - 16}" y1="{base_y}" '
                 f'x2="{destra + 16}" y2="{base_y}"/>')

    for indice, (anno, giorni) in enumerate(anni):
        x = sinistra + indice * passo
        cima = y(giorni)
        parti.append(f'<rect class="barra" x="{x - 15:.1f}" y="{cima:.1f}" '
                     f'width="30" height="{base_y - cima:.1f}" rx="2"/>')
        testo = ("2,3 anni" if giorni > 730 else
                 "1,7 anni" if giorni > 550 else
                 "1,3 anni" if giorni > 400 else
                 "10 mesi" if giorni > 280 else
                 "8,6 mesi" if giorni > 200 else
                 "4,2 mesi" if giorni > 90 else
                 "53 giorni" if giorni > 30 else "21,5 giorni")
        parti.append(f'<text class="etichetta" x="{x:.1f}" y="{cima - 5:.1f}" '
                     f'text-anchor="middle">{testo}</text>')
        parti.append(f'<text class="anno" x="{x:.1f}" y="{base_y + 13:.1f}" '
                     f'text-anchor="middle">{anno}</text>')

    parti.append("</svg>")
    return "".join(parti)


def dove_sta_il_rischio() -> str:
    """Come si distribuisce il rischio realmente sfruttabile."""
    voci = [("Informazioni esposte", 33, BLU),
            ("Credenziali e segreti", 23, "#2f6ea8"),
            ("Accessi non autorizzati", 22, BLU_CHIARO),
            ("Esecuzione di codice", 9, "#b45309"),
            ("Altro", 13, GRIGIO)]
    # Spazio sopra la barra: la graffa e la sua didascalia salgono di 20
    # unita', e con la barra a 20 il testo veniva tagliato dal bordo alto.
    larghezza, altezza = 520, 158
    x0, x1, y_barra, spessore = 8.0, 512.0, 30.0, 34.0
    scala = (x1 - x0) / 100.0

    # Nessun `width`/`height` fisso: con il solo `viewBox` la dimensione la
    # decide il foglio di stile, e il contenuto scala insieme al riquadro.
    # Con gli attributi, il disegno usciva dal margine di pagina.
    parti = [f'<svg xmlns="http://www.w3.org/2000/svg" '
             f'viewBox="0 0 {larghezza} {altezza}" '
             f'preserveAspectRatio="xMidYMid meet">',
             "<style>"
             ".quota{font-family:inherit;font-size:9pt;font-weight:700;fill:#fff}"
             f".voce{{font-family:inherit;font-size:7.5pt;fill:{INCHIOSTRO}}}"
             f".graffa{{stroke:{BLU};stroke-width:1.2;fill:none}}"
             f".nota{{font-family:inherit;font-size:7.5pt;fill:{BLU};font-weight:700}}"
             "</style>"]

    corrente = x0
    for _, quota, colore in voci:
        w = quota * scala
        parti.append(f'<rect x="{corrente:.1f}" y="{y_barra}" width="{w - 1.5:.1f}" '
                     f'height="{spessore}" fill="{colore}" rx="2"/>')
        if quota >= 9:
            parti.append(f'<text class="quota" x="{corrente + w / 2:.1f}" '
                         f'y="{y_barra + 22:.1f}" text-anchor="middle">{quota}%</text>')
        corrente += w

    # Graffa sui primi tre segmenti: e' il 78 per cento che conta.
    fine_tre = x0 + 78 * scala
    parti.append(f'<path class="graffa" d="M{x0:.1f} {y_barra - 6} v-5 H{fine_tre:.1f} v5"/>')
    parti.append(f'<text class="nota" x="{(x0 + fine_tre) / 2:.1f}" y="{y_barra - 14:.1f}" '
                 'text-anchor="middle">78% &#8212; esposizione, credenziali, accessi</text>')

    # Legenda su due colonne.
    for indice, (nome, quota, colore) in enumerate(voci):
        colonna, riga = indice % 2, indice // 2
        lx = 8 + colonna * 258
        ly = 78 + riga * 18
        parti.append(f'<rect x="{lx}" y="{ly - 7}" width="9" height="9" fill="{colore}" rx="1.5"/>')
        parti.append(f'<text class="voce" x="{lx + 15}" y="{ly + 1}">{nome} &#183; {quota}%</text>')

    parti.append("</svg>")
    return "".join(parti)
