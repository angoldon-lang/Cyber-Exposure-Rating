"""Correlazione tecnologia -> CVE con regole di attendibilita' rigorose.

Regole (sezione 7.14). Una CVE NON viene associata a un asset se:
  * la tecnologia non e' identificata con sufficiente attendibilita';
  * la versione non e' disponibile;
  * la versione non e' compatibile con la CVE;
  * l'evidenza deriva unicamente da un header generico.

Il risultato di una corrispondenza incerta e' un'evidenza `inferred`
(informativa, detrazione nulla), mai una vulnerabilita' confermata.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.models.enums import ConfidenceClass

# Header che da soli non identificano un prodotto in modo attendibile.
GENERIC_HEADER_SOURCES = {"server", "x-powered-by", "via", "x-generator"}

_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


@dataclass(frozen=True)
class TechnologyObservation:
    name: str
    version: str | None
    source: str                 # es. "httpx-tech-detect", "server-header", "nuclei"
    asset_key: str
    confidence: float = 0.5     # attendibilita' del fingerprint [0,1]


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    confidence_class: str
    reason: str


def parse_version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    match = _VERSION_RE.match(value.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def version_in_range(version: str | None, affected_below: str | None,
                     affected_from: str | None = None) -> bool | None:
    """None = impossibile stabilire (versione o range mancanti)."""
    parsed = parse_version(version)
    if parsed is None:
        return None
    if affected_below:
        upper = parse_version(affected_below)
        if upper is None:
            return None
        if parsed >= upper:
            return False
    if affected_from:
        lower = parse_version(affected_from)
        if lower is None:
            return None
        if parsed < lower:
            return False
    return True


def evaluate_match(observation: TechnologyObservation, vulnerability: dict[str, Any],
                   *, min_fingerprint_confidence: float = 0.7) -> MatchResult:
    """Decide se una CVE puo' essere associata a una tecnologia osservata."""
    product = str(vulnerability.get("product", "")).lower()
    if product and product not in observation.name.lower() and observation.name.lower() not in product:
        return MatchResult(False, ConfidenceClass.INFORMATIONAL.value,
                           "prodotto non corrispondente")

    if observation.source in GENERIC_HEADER_SOURCES:
        return MatchResult(False, ConfidenceClass.INFERRED.value,
                           "evidenza derivante unicamente da un header generico: "
                           "non sufficiente per confermare la vulnerabilita'")

    if observation.confidence < min_fingerprint_confidence:
        return MatchResult(False, ConfidenceClass.INFERRED.value,
                           f"attendibilita' del fingerprint insufficiente "
                           f"({observation.confidence:.2f} < {min_fingerprint_confidence:.2f})")

    if not observation.version:
        return MatchResult(False, ConfidenceClass.INFERRED.value,
                           "versione del prodotto non disponibile: la presenza del prodotto "
                           "non implica la vulnerabilita'")

    verdict = version_in_range(observation.version,
                              vulnerability.get("affected_below"),
                              vulnerability.get("affected_from"))
    if verdict is None:
        return MatchResult(False, ConfidenceClass.INFERRED.value,
                           "range di versioni non determinabile")
    if verdict is False:
        return MatchResult(False, ConfidenceClass.INFORMATIONAL.value,
                           "la versione rilevata non rientra nel range vulnerabile")

    return MatchResult(True, ConfidenceClass.CONFIRMED.value,
                       "prodotto e versione corrispondono al range vulnerabile")
