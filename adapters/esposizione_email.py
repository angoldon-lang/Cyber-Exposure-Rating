"""Contratto comune delle evidenze sull'esposizione degli indirizzi e-mail.

Perche' un modulo condiviso
---------------------------
Lo stesso fatto — «questo indirizzo compare in questa violazione» — puo'
arrivare da piu' fonti: XposedOrNot lo riporta direttamente, SpiderFoot lo
riceve dai suoi moduli sulle violazioni. La deduplicazione della pipeline
funziona sull'impronta `asset_key|finding_type|detail|cve_id`: se due fonti
descrivono lo stesso fatto con `finding_type` diversi, l'impronta cambia e la
stessa esposizione viene detratta due volte dal rating.

Qui vive quindi l'unica definizione di quel fatto. Le fonti differiscono per
quanto sanno, non per come lo chiamano: chi conosce anno e categorie di dato
produce un'evidenza piu' grave, chi non li conosce produce la stessa evidenza
con severita' inferiore, e le due convergono sulla stessa impronta.

Cosa non entra mai qui: il valore di una credenziale. Delle violazioni si
conservano nome, anno, dimensione e categorie di dato. La password, in chiaro
o sotto forma di hash, non viene ne' letta ne' registrata.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime

from adapters.base import NormalizedEvidence
from app.core.redaction import mask_email
from app.models.enums import ConfidenceClass, ScoreCategoryKey, Severity

CATEGORIA = ScoreCategoryKey.DARKWEB_BREACH.value

# Una violazione recente pesa piu' di una vecchia: dove la password e' stata
# cambiata nel frattempo l'esposizione e' rientrata, dove non lo e' stata no.
ANNI_RECENTI = 3

# Categorie di dato che rendono l'esposizione sfruttabile, non solo nota.
# Il confronto e' per sottostringa perche' le fonti non usano etichette
# normalizzate: «Passwords», «Hashed Passwords» e «password (hash deboli)»
# descrivono tutte la stessa cosa.
RADICI_CRITICHE = ("password", "passwd", "security question", "domande di sicurezza",
                   "auth token", "authentication token", "session token", "api key",
                   "two factor", "2fa", "mfa", "credit card", "carte di credito",
                   "bank account", "iban", "government issued id", "documento di identita")

# SpiderFoot annota la fonte fra parentesi quadre: «mario@azienda.it [LinkedIn]».
_INDIRIZZO_CON_FONTE = re.compile(r"^\s*(?P<indirizzo>[^\s\[\]]+@[^\s\[\]]+?)\s*(?:\[(?P<fonte>[^\]]+)\])?\s*$")


def categorie_critiche(categorie: set[str]) -> list[str]:
    """Sottoinsieme delle categorie che rendono l'esposizione sfruttabile."""
    return sorted(c for c in categorie if any(r in c.lower() for r in RADICI_CRITICHE))


def separa_indirizzo_e_fonte(valore: str) -> tuple[str, str | None]:
    """Estrae indirizzo e nome della violazione da un evento SpiderFoot."""
    corrispondenza = _INDIRIZZO_CON_FONTE.match(valore)
    if not corrispondenza:
        return valore.strip().lower(), None
    fonte = corrispondenza.group("fonte")
    return corrispondenza.group("indirizzo").strip().lower(), (fonte.strip() if fonte else None)


def severita_violazione(anno: int | None, categorie: set[str]) -> str:
    """Gravita' di una singola violazione per un singolo indirizzo.

    Non e' una scala arbitraria: distingue i tre casi che richiedono azioni
    diverse. Credenziali esposte di recente vanno cambiate subito; credenziali
    vecchie vanno cambiate se mai riusate; la sola presenza dell'indirizzo e'
    materiale per il phishing mirato, non per l'accesso.
    """
    critiche = categorie_critiche(categorie)
    if not critiche:
        return Severity.LOW.value
    if anno is not None and (datetime.now(UTC).year - anno) <= ANNI_RECENTI:
        return Severity.HIGH.value
    return Severity.MEDIUM.value


def evidenza_violazione(*, tool: str, indirizzo: str, violazione: str,
                        anno: int | None = None, categorie: set[str] | None = None,
                        record: int | None = None, fonte_dati: str,
                        confidence: str = ConfidenceClass.CONFIRMED.value) -> NormalizedEvidence:
    """L'indirizzo compare in una specifica violazione di dati.

    Una evidenza per coppia (indirizzo, violazione): e' la granularita' che
    serve all'analista per verificare — quale casella, quale violazione — ed e'
    anche quella su cui due fonti diverse convergono sulla stessa impronta.
    """
    categorie = categorie or set()
    mascherato = mask_email(indirizzo)
    critiche = categorie_critiche(categorie)
    return NormalizedEvidence(
        tool=tool, target=mascherato, asset_key=indirizzo,
        finding_type="email_exposed_in_breach",
        title=f"Indirizzo esposto nella violazione «{violazione}»: {mascherato}",
        description=(
            "L'indirizzo compare fra i dati resi pubblici da questa violazione. "
            "L'esposizione riguarda l'utenza, non necessariamente i sistemi "
            "dell'organizzazione: il rimedio e' il cambio della password su tutti i servizi "
            "dove l'indirizzo e' usato come nome utente e l'attivazione dell'autenticazione a "
            "piu' fattori. Nessuna password e nessun hash sono stati letti o conservati: della "
            "violazione sono registrati soltanto nome, anno e categorie di dato coinvolte."),
        detail=violazione[:200],
        category=CATEGORIA, severity=severita_violazione(anno, categorie),
        confidence_class=confidence, data_source=fonte_dati,
        observed_at=datetime.now(UTC),
        event_date=datetime(anno, 1, 1, tzinfo=UTC) if anno else None,
        attributes={"breach": violazione, "year": anno,
                    "exposed_data_categories": sorted(categorie),
                    "critical_categories": critiche,
                    "records": record})


def evidenza_credenziali_recenti(*, tool: str, indirizzo: str, anno: int,
                                 violazioni: list[str], fonte_dati: str) -> NormalizedEvidence:
    """Credenziali dell'indirizzo esposte di recente: e' l'azione urgente.

    Separata dalle evidenze per violazione perche' la detrazione sul rating
    deve essere una sola per indirizzo, non una per ogni violazione in cui
    quell'indirizzo compare. La emette solo una fonte che conosce l'anno:
    senza data la recenza non e' dimostrabile e non va supposta.
    """
    mascherato = mask_email(indirizzo)
    return NormalizedEvidence(
        tool=tool, target=mascherato, asset_key=indirizzo,
        finding_type="email_credentials_recently_exposed",
        title=f"Credenziali esposte di recente ({anno}): {mascherato}",
        description=(
            "Le credenziali associate a questo indirizzo sono state esposte in una violazione "
            "recente. Se la password non e' stata cambiata dopo quella data, l'utenza e' "
            "utilizzabile da terzi su ogni servizio dove quella password e' stata riusata. "
            "Il rimedio e' immediato: cambio della password e autenticazione a piu' fattori."),
        detail=str(anno), category=CATEGORIA, severity=Severity.HIGH.value,
        confidence_class=ConfidenceClass.CONFIRMED.value, data_source=fonte_dati,
        observed_at=datetime.now(UTC), event_date=datetime(anno, 1, 1, tzinfo=UTC),
        attributes={"most_recent_year": anno, "breaches": sorted(violazioni)})
