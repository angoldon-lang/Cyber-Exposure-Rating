"""Configurazione degli strumenti impostata dall'interfaccia.

Le chiavi delle fonti esterne stavano solo nelle variabili d'ambiente: per
attivare uno strumento bisognava accedere al server, modificare `.env` e
riavviare i contenitori. Chi usa la piattaforma non ha necessariamente
quell'accesso, e la schermata «Strumenti» finiva per descrivere un problema
invece di risolverlo.

Due regole non negoziabili:

  * il valore in chiaro non lascia mai il server. L'API dice se una variabile
    e' impostata, chi l'ha toccata e quando; per rileggere una chiave la si
    sostituisce;
  * si scrivono solo le variabili di questo elenco. Senza, l'endpoint
    diventerebbe una scrittura arbitraria nella configurazione.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.segreti import SegretoNonDisponibile, cifra, decifra
from app.models.configurazione import ToolSetting


@dataclass(frozen=True)
class Variabile:
    nome: str
    strumento: str
    etichetta: str
    segreto: bool
    gratuito: bool
    dove: str | None
    nota: str


VARIABILI: tuple[Variabile, ...] = (
    Variabile(
        nome="SPIDERFOOT_URL", strumento="spiderfoot",
        etichetta="Indirizzo dell'istanza SpiderFoot", segreto=False, gratuito=True,
        dove="https://github.com/smicallef/spiderfoot",
        nota="Istanza raggiungibile dal worker. Si avvia con "
             "`docker run -p 5001:5001 ghcr.io/smicallef/spiderfoot` e si indica "
             "come http://spiderfoot:5001"),
    Variabile(
        nome="ZAP_URL", strumento="zap_baseline",
        etichetta="Indirizzo del demone ZAP", segreto=False, gratuito=True,
        dove="https://www.zaproxy.org/docs/api/",
        nota="Con il compose e' http://zap:8090. Il servizio si avvia con "
             "`docker compose --profile zap up -d`: gira come contenitore a se', "
             "perche' il worker non deve poter avviare altri contenitori."),
    Variabile(
        nome="ZAP_API_KEY", strumento="zap_baseline",
        etichetta="Chiave API del demone ZAP", segreto=True, gratuito=True,
        dove=None,
        nota="La sceglie chi installa, non un fornitore: `openssl rand -hex 24`. "
             "Deve coincidere con quella passata al servizio nel compose."),
    Variabile(
        nome="HIBP_API_KEY", strumento="hibp",
        etichetta="Chiave API Have I Been Pwned", segreto=True, gratuito=False,
        dove="https://haveibeenpwned.com/API/Key",
        nota="Abbonamento a pagamento. Senza, la ricerca per dominio non e' "
             "disponibile: XposedOrNot copre in parte la stessa area, gratis."),
    Variabile(
        nome="CREDENTIAL_EXPOSURE_URL", strumento="credential_exposure",
        etichetta="Indirizzo della fonte di intelligence", segreto=False, gratuito=False,
        dove=None,
        nota="Endpoint del fornitore di intelligence su credenziali esposte."),
    Variabile(
        nome="CREDENTIAL_EXPOSURE_API_KEY", strumento="credential_exposure",
        etichetta="Chiave API della fonte di intelligence", segreto=True, gratuito=False,
        dove=None,
        nota="Le fonti serie in questo ambito sono tutte commerciali. Senza "
             "abbonamento l'area resta scoperta e il rating lo dichiara."),
)

PER_NOME = {v.nome: v for v in VARIABILI}


def _dall_ambiente(variabile: str) -> str | None:
    """Valore che arriva da `.env`.

    I nomi delle variabili sono le stesse chiavi delle impostazioni, in
    maiuscolo: pydantic-settings fa la corrispondenza con l'attributo in
    minuscolo.
    """
    return getattr(settings, variabile.lower(), None) or None


def _dal_database(db: Session) -> dict[str, str]:
    valori: dict[str, str] = {}
    for riga in db.execute(select(ToolSetting)).scalars():
        if riga.variable not in PER_NOME:
            continue
        chiaro = decifra(riga.value_encrypted)
        # `None` significa non piu' decifrabile (JWT_SECRET_KEY cambiata):
        # lo strumento risulta non configurato, che e' la verita'.
        if chiaro:
            valori[riga.variable] = chiaro
    return valori


def valori_effettivi(db: Session | None) -> dict[str, str]:
    """Valori in vigore: il database ha la precedenza sull'ambiente.

    Chi imposta una chiave dall'interfaccia si aspetta che valga. Se
    prevalesse `.env`, la schermata direbbe «impostata» e lo strumento
    userebbe un'altra chiave.
    """
    effettivi = {v.nome: valore for v in VARIABILI
                 if (valore := _dall_ambiente(v.nome))}
    if db is not None:
        effettivi.update(_dal_database(db))
    return effettivi


def origine(db: Session | None) -> dict[str, str]:
    """Da dove arriva ciascun valore: serve a spiegarlo nell'interfaccia."""
    da_db = _dal_database(db) if db is not None else {}
    fonti: dict[str, str] = {}
    for v in VARIABILI:
        if v.nome in da_db:
            fonti[v.nome] = "interfaccia"
        elif _dall_ambiente(v.nome):
            fonti[v.nome] = "ambiente"
    return fonti


def imposta(db: Session, variabile: str, valore: str, *,
            utente_id: uuid.UUID | None) -> None:
    """Salva il valore cifrato. Solleva se la variabile non e' in elenco."""
    if variabile not in PER_NOME:
        raise ValueError(f"variabile non configurabile: {variabile}")
    valore = valore.strip()
    if not valore:
        raise ValueError("il valore non puo' essere vuoto: per togliere una "
                         "configurazione si usa la cancellazione")

    riga = db.execute(
        select(ToolSetting).where(ToolSetting.variable == variabile)).scalar_one_or_none()
    cifrato = cifra(valore)
    if riga is None:
        db.add(ToolSetting(variable=variabile, value_encrypted=cifrato,
                           updated_at=datetime.now(UTC), updated_by_id=utente_id))
    else:
        riga.value_encrypted = cifrato
        riga.updated_at = datetime.now(UTC)
        riga.updated_by_id = utente_id


def rimuovi(db: Session, variabile: str) -> bool:
    riga = db.execute(
        select(ToolSetting).where(ToolSetting.variable == variabile)).scalar_one_or_none()
    if riga is None:
        return False
    db.delete(riga)
    return True


def cifratura_disponibile() -> tuple[bool, str | None]:
    """Se manca il materiale per cifrare va detto prima, non al salvataggio."""
    try:
        cifra("prova")
    except SegretoNonDisponibile as errore:
        return False, str(errore)
    return True, None
