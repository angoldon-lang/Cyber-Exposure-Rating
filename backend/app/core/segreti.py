"""Cifratura dei valori di configurazione conservati nel database.

Le chiavi delle fonti esterne (HIBP, threat intelligence, SpiderFoot) finora
stavano solo nelle variabili d'ambiente. Poterle inserire dall'interfaccia
significa conservarle, e conservarle in chiaro in una tabella sarebbe peggio
del problema che risolve: un dump del database le esporrebbe tutte.

La chiave di cifratura non e' una nuova variabile da impostare. Viene
derivata da `JWT_SECRET_KEY`, che il compose gia' pretende, con una
derivazione dedicata a questo scopo: due usi diversi dello stesso segreto non
condividono la chiave effettiva. Il rovescio della medaglia va detto: se
`JWT_SECRET_KEY` cambia, i valori conservati non sono piu' leggibili e vanno
reinseriti. E' la stessa conseguenza che ha gia' sulle sessioni attive.
"""
from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

# Distingue questa chiave da qualunque altra derivata dallo stesso segreto.
# Il suffisso di versione permette di cambiare derivazione in futuro senza
# confondere i valori cifrati con quella precedente.
_SCOPO = b"defenix-configurazione-strumenti-v1"


class SegretoNonDisponibile(RuntimeError):
    """Manca il materiale per cifrare: meglio rifiutare che scrivere in chiaro."""


def _cifrario() -> Fernet:
    segreto = (settings.jwt_secret_key or "").encode("utf-8")
    if len(segreto) < 16:
        raise SegretoNonDisponibile(
            "JWT_SECRET_KEY assente o troppo corta: senza, i valori di "
            "configurazione non possono essere conservati in modo cifrato.")
    derivata = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=_SCOPO).derive(segreto)
    return Fernet(base64.urlsafe_b64encode(derivata))


def cifra(valore: str) -> bytes:
    return _cifrario().encrypt(valore.encode("utf-8"))


def decifra(dati: bytes) -> str | None:
    """Valore in chiaro, o `None` se non e' piu' decifrabile.

    Succede quando `JWT_SECRET_KEY` e' cambiata. Restituire `None` invece di
    sollevare fa si' che lo strumento risulti non configurato — che e' la
    verita' — mentre un'eccezione fermerebbe l'intera schermata.
    """
    try:
        return _cifrario().decrypt(dati).decode("utf-8")
    except (InvalidToken, SegretoNonDisponibile, ValueError):
        return None
