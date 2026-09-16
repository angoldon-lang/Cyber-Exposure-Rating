"""Traduzione della valutazione nella lingua di chi decide.

Il motore produce punteggi, rilievi e un piano di rimedio: materiale corretto
e illeggibile per un imprenditore. Questo modulo non calcola nulla e non
introduce fatti nuovi — rimappa cio' che il motore ha gia' deciso sui testi di
`config/narrativa_direzione.yaml`, che sono la parte editoriale del prodotto e
si correggono senza toccare il codice.

Il rapporto tecnico resta la fonte: quando le due formulazioni divergono, fa
fede quello. La nota metodologica del rapporto per la direzione lo dichiara.
"""
from __future__ import annotations

from typing import Any

from app.core.config import load_yaml_config

# Quando intervenire, dedotto dalla priorita' del piano di rimedio. «p1» in un
# documento per la direzione non significa niente; «Subito» si'.
QUANDO_IT = {
    "p1": "Subito",
    "p2": "Entro 2 settimane",
    "p3": "Entro 1-2 mesi",
    "p4": "Pianificabile",
}

# Le etichette di gravita' del rapporto tecnico ripetono la scala CVSS. Qui
# servono quattro parole che si leggano da sole.
GRAVITA_IT = {
    "critical": "CRITICA",
    "high": "GRAVE",
    "medium": "MEDIA",
    "low": "BASSA",
    "info": "INFORMATIVA",
}
_ORDINE_GRAVITA = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_ORDINE_PRIORITA = {"p1": 0, "p2": 1, "p3": 2, "p4": 3}

# Interventi che si esauriscono in configurazioni gia' alla portata di chi
# amministra i sistemi: se il piano contiene solo questi, vale la pena dirlo.
_IMPEGNO_LEGGERO = {"xs", "s"}

# Oltre questo numero l'elenco dei rilievi non si legge piu': i restanti
# restano nell'allegato tecnico, che esiste per quello.
MAX_RILIEVI_ESPOSTI = 6

# Sopra questo punteggio l'area si considera senza rilievi che contino.
SOGLIA_AREA_PULITA = 90.0

# In un testo discorsivo i numeri piccoli si scrivono a lettere. «Uno» si
# accorda: davanti a un nome femminile e' «una», e scriverlo al maschile si
# nota subito («su uno aree»).
_NUMERI_IT = ["zero", "uno", "due", "tre", "quattro", "cinque",
              "sei", "sette", "otto", "nove", "dieci"]


def _lettere(numero: int, *, femminile: bool = False) -> str:
    if not (0 <= numero < len(_NUMERI_IT)):
        return str(numero)
    parola = _NUMERI_IT[numero]
    return "una" if femminile and parola == "uno" else parola


def _narrativa() -> dict[str, Any]:
    return load_yaml_config("narrativa_direzione")


def _testo(valore: Any) -> str:
    """YAML `>-` conserva gli a capo del sorgente: qui servono frasi."""
    return " ".join(str(valore or "").split())


# ---------------------------------------------------------------------------
# Le aree controllate
# ---------------------------------------------------------------------------
def _note_di_copertura(area: str, coverage_matrix: list[dict[str, Any]]) -> str:
    """Quali controlli non sono girati su quest'area.

    Un'area a 100 perche' nessuno l'ha guardata non e' un'area a posto. E' la
    distinzione che il punteggio da solo non puo' fare, e tacerla renderebbe il
    documento fuorviante proprio dove promette chiarezza.
    """
    mancati = [
        riga for riga in coverage_matrix
        if area in (riga.get("areas") or []) and riga.get("status") not in ("success", None)
    ]
    if not mancati:
        return ""
    note = [_testo(riga.get("note_it")) for riga in mancati if _testo(riga.get("note_it"))]
    if note:
        testo = "Verifica parziale: " + note[0][0].lower() + note[0][1:]
        return testo if testo.endswith(".") else testo + "."
    return "Verifica parziale: non tutti i controlli previsti su quest'area sono stati eseguiti."


def aree_controllate(categories: list[dict[str, Any]],
                     coverage_matrix: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Le aree del rating con nome corrente e significato del risultato."""
    aree_cfg = _narrativa().get("aree", {})
    righe: list[dict[str, Any]] = []
    for categoria in categories:
        chiave = str(categoria.get("key") or "")
        cfg = aree_cfg.get(chiave, {})
        punteggio = float(categoria.get("score") or 0.0)
        rilievi = int(categoria.get("finding_count") or 0)
        critica = rilievi > 0 and punteggio < SOGLIA_AREA_PULITA
        righe.append({
            "chiave": chiave,
            "nome": _testo(cfg.get("nome")) or str(categoria.get("label_it") or chiave),
            "nome_breve": (_testo(cfg.get("nome_breve")) or _testo(cfg.get("nome"))
                           or str(categoria.get("label_it") or chiave)),
            "punteggio": punteggio,
            "rilievi": rilievi,
            "critica": critica,
            "significato": _testo(cfg.get("esito_negativo") if critica else cfg.get("esito_positivo")),
            "nota_copertura": _note_di_copertura(chiave, coverage_matrix),
            "gravi": int(categoria.get("critical_count") or 0) + int(categoria.get("high_count") or 0),
        })
    return righe


# ---------------------------------------------------------------------------
# Che cosa abbiamo trovato
# ---------------------------------------------------------------------------
def _ordina_piano(remediation_plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        remediation_plan,
        key=lambda voce: (
            _ORDINE_PRIORITA.get(str(voce.get("priority")), 9),
            -_ORDINE_GRAVITA.get(str(voce.get("max_severity")), 0),
        ))


def rilievi_spiegati(remediation_plan: list[dict[str, Any]]) -> dict[str, Any]:
    """I rilievi raggruppati per intervento, ciascuno con un paragone.

    Il raggruppamento e' quello che il piano di rimedio fa gia': cinque
    schede per sei rilievi, non sei schede. Chi legge deve decidere sugli
    interventi, non contare i rilievi.
    """
    interventi_cfg = _narrativa().get("interventi", {})
    schede: list[dict[str, Any]] = []
    informativi: list[str] = []

    for voce in _ordina_piano(remediation_plan):
        cfg = interventi_cfg.get(str(voce.get("catalog_id")), {})
        gravita = str(voce.get("max_severity") or "info")
        titolo = _testo(cfg.get("semplice")) or _testo(voce.get("title_it"))
        if gravita == "info":
            informativi.append(titolo)
            continue
        schede.append({
            "titolo": titolo,
            "gravita": gravita,
            "etichetta_gravita": GRAVITA_IT.get(gravita, gravita),
            "manca": _testo(cfg.get("manca")),
            "paragone": _testo(cfg.get("paragone")),
            "comporta": _testo(cfg.get("comporta")) or _testo(voce.get("risk_mitigated_it")),
            "tempo": _testo(cfg.get("tempo")),
            "rilievi": len(voce.get("finding_codes") or []),
        })

    esposte = schede[:MAX_RILIEVI_ESPOSTI]
    return {
        "schede": esposte,
        "non_esposti": len(schede) - len(esposte),
        "informativi": informativi,
    }


def buona_notizia(remediation_plan: list[dict[str, Any]]) -> str:
    """Se il piano e' fatto solo di configurazioni, va detto.

    E' l'informazione che sposta la decisione: nessun acquisto, nessun fermo
    della produzione. Tacerla fa sembrare piu' grave di quel che e'.
    """
    if not remediation_plan:
        return ""
    if any(str(voce.get("effort")) not in _IMPEGNO_LEGGERO for voce in remediation_plan):
        return ""
    return (
        "Nessuno di questi punti richiede l'acquisto di software, la sostituzione di "
        "sistemi o un fermo dell'attivita'. Sono tutte configurazioni, da pubblicare "
        "sul dominio o da applicare sui sistemi esistenti, alla portata di chi gia' "
        "amministra i sistemi aziendali.")


# ---------------------------------------------------------------------------
# Che cosa puo' succedere davvero
# ---------------------------------------------------------------------------
def area_dominante(remediation_plan: list[dict[str, Any]],
                   categories: list[dict[str, Any]]) -> str:
    """L'area su cui si concentra il rischio.

    Prima il piano di rimedio, che ordina per priorita' reale; se e' vuoto si
    ripiega sull'area con il punteggio piu' basso, perche' una scansione senza
    rilievi ha comunque un'area piu' debole delle altre.
    """
    ordinato = _ordina_piano(remediation_plan)
    if ordinato:
        area = str(ordinato[0].get("area") or "")
        if area:
            return area
    if categories:
        peggiore = min(categories, key=lambda c: float(c.get("score") or 0.0))
        return str(peggiore.get("key") or "")
    return ""


def scenario(area: str) -> dict[str, Any]:
    dati = _narrativa().get("scenari", {}).get(area)
    if not dati:
        return {}
    return {
        "titolo": _testo(dati.get("titolo")),
        "premessa": _testo(dati.get("premessa")),
        "passi": [_testo(passo) for passo in dati.get("passi") or []],
        "variante": _testo(dati.get("variante")),
    }


def domande(area: str) -> dict[str, Any]:
    dati = _narrativa().get("domande", {}).get(area)
    if not dati:
        return {}
    return {
        "a_chi": _testo(dati.get("a_chi")),
        "voci": [{"domanda": _testo(v.get("domanda")), "attesa": _testo(v.get("attesa"))}
                 for v in dati.get("voci") or []],
    }


# ---------------------------------------------------------------------------
# Che cosa fare, in ordine
# ---------------------------------------------------------------------------
def interventi_in_ordine(remediation_plan: list[dict[str, Any]],
                         limite: int = 6) -> list[dict[str, Any]]:
    interventi_cfg = _narrativa().get("interventi", {})
    righe: list[dict[str, Any]] = []
    for voce in _ordina_piano(remediation_plan)[:limite]:
        cfg = interventi_cfg.get(str(voce.get("catalog_id")), {})
        righe.append({
            "titolo": _testo(voce.get("title_it")),
            "in_parole": _testo(cfg.get("semplice")),
            "quando": QUANDO_IT.get(str(voce.get("priority")), "Da pianificare"),
            "tempo": _testo(cfg.get("tempo")),
            "verifica": _testo(voce.get("verification_it")),
        })
    return righe


# ---------------------------------------------------------------------------
# Il risultato in due righe
# ---------------------------------------------------------------------------
def in_pratica(aree: list[dict[str, Any]]) -> str:
    """La frase che un imprenditore ricorda il giorno dopo."""
    critiche = [a for a in aree if a["critica"]]
    if not critiche:
        return ("Dall'esterno non emergono debolezze nelle aree controllate. E' un buon "
                "punto di partenza, non un punto d'arrivo: vale per cio' che si vede da "
                "fuori e alla data della rilevazione.")
    critiche.sort(key=lambda a: a["punteggio"])
    if len(critiche) == 1:
        return (f"Dall'esterno l'azienda non mostra debolezze diffuse, e questa e' una buona "
                f"notizia. Tutti i rilievi si concentrano in una sola area: "
                f"{critiche[0]['nome'].lower()}.")
    nomi = ", ".join(a["nome"].lower() for a in critiche[:2])
    return (f"I rilievi non sono distribuiti a caso: si concentrano su {nomi}. "
            f"E' li' che conviene intervenire per primo, prima di qualsiasi altra cosa.")


def sintesi_del_risultato(overall_score: float, aree: list[dict[str, Any]]) -> str:
    critiche = [a for a in aree if a["critica"]]
    gravi = sum(a["gravi"] for a in aree)
    rilievi = sum(a["rilievi"] for a in aree)
    if not critiche:
        return "Nelle aree controllate non sono emersi rilievi che incidano sul punteggio."
    if len(critiche) == 1:
        area = critiche[0]
        coda = ""
        if gravi:
            coda = f", di cui {gravi} da trattare per " + ("primo" if gravi == 1 else "primi")
        if len(aree) == 1:
            return (f"Nell'unica area controllata, {area['nome'].lower()}, sono emersi "
                    f"{area['rilievi']} rilievi{coda}.")
        return (f"Su {_lettere(len(aree), femminile=True)} aree, i rilievi si concentrano "
                f"in una sola: {area['nome'].lower()} ({area['rilievi']} rilievi{coda}).")
    coda = "."
    if gravi:
        coda = f", di cui {gravi} da trattare per " + ("primo." if gravi == 1 else "primi.")
    return (f"{rilievi} rilievi distribuiti su {_lettere(len(critiche), femminile=True)} aree "
            f"delle {_lettere(len(aree), femminile=True)} controllate{coda}")


# ---------------------------------------------------------------------------
def titolo_aree(quante: int) -> str:
    if quante == 1:
        return "L'unica area controllata"
    return f"Le {_lettere(quante, femminile=True)} aree controllate"


def titolo_domande(quante: int, a_chi: str) -> str:
    if quante == 1:
        return f"La domanda da fare lunedi' mattina {a_chi}".replace("lunedi'", "luned\u00ec")
    return (f"Le {_lettere(quante, femminile=True)} domande da fare "
            f"luned\u00ec mattina {a_chi}")


def blocchi_fissi() -> dict[str, Any]:
    dati = _narrativa()
    return {
        "danno_oltre_il_denaro": [
            {"titolo": _testo(v.get("titolo")), "testo": _testo(v.get("testo"))}
            for v in dati.get("danno_oltre_il_denaro") or []],
        "raccomandazione_finale": {
            "titolo": _testo((dati.get("raccomandazione_finale") or {}).get("titolo")),
            "testo": _testo((dati.get("raccomandazione_finale") or {}).get("testo")),
        },
        "limiti_divulgativi": [_testo(v) for v in dati.get("limiti_divulgativi") or []],
        "avvertenza_punteggio": {
            "titolo": _testo((dati.get("avvertenza_punteggio") or {}).get("titolo")),
            "chiusura": _testo((dati.get("avvertenza_punteggio") or {}).get("chiusura")),
        },
    }


def sintesi_per_la_direzione(*, categories: list[dict[str, Any]],
                             coverage_matrix: list[dict[str, Any]],
                             remediation_plan: list[dict[str, Any]],
                             overall_score: float) -> dict[str, Any]:
    """Tutto cio' che il modello del rapporto per la direzione deve ricevere."""
    aree = aree_controllate(categories, coverage_matrix)
    area = area_dominante(remediation_plan, categories)
    domande_area = domande(area)
    return {
        "aree": aree,
        "titolo_aree": titolo_aree(len(aree)),
        "titolo_domande": titolo_domande(
            len(domande_area.get("voci") or []), domande_area.get("a_chi", "")),
        "in_pratica": in_pratica(aree),
        "sintesi_risultato": sintesi_del_risultato(overall_score, aree),
        "rilievi": rilievi_spiegati(remediation_plan),
        "buona_notizia": buona_notizia(remediation_plan),
        "area_dominante": area,
        "scenario": scenario(area),
        "domande": domande_area,
        "interventi": interventi_in_ordine(remediation_plan),
        **blocchi_fissi(),
    }
