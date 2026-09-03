"""Verifica della proprieta' di un dominio (sezione 4).

Nessun profilo verificato puo' essere avviato senza una verifica riuscita
e un'autorizzazione attiva. Le verifiche supportate sono quattro:
  * record DNS TXT temporaneo;
  * file di verifica sul sito;
  * e-mail a un indirizzo amministrativo autorizzato;
  * approvazione manuale di un amministratore Defenix.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import generate_verification_token
from app.models.enums import VerificationMethod, VerificationStatus
from app.services.scope_guard import ScopeViolation, normalize_hostname

logger = get_logger(__name__)

TOKEN_VALIDITY_DAYS = 14
VERIFICATION_FILE_PATH = "/.well-known/defenix-verification.txt"
MAX_VERIFICATION_ATTEMPTS = 20

# Indirizzi amministrativi accettati per la verifica via e-mail (RFC 2142 + prassi).
ADMIN_EMAIL_LOCALPARTS: frozenset[str] = frozenset({
    "admin", "administrator", "hostmaster", "postmaster", "webmaster",
    "security", "abuse", "it", "sistemi", "amministrazione",
})


@dataclass
class VerificationChallenge:
    domain: str
    method: str
    token: str
    expires_at: datetime
    instructions_it: str
    record_name: str | None = None
    record_value: str | None = None
    file_url: str | None = None
    file_content: str | None = None


@dataclass
class VerificationOutcome:
    verified: bool
    method: str
    detail_it: str
    checked_at: datetime


def create_challenge(domain: str, method: str) -> VerificationChallenge:
    """Genera la sfida di verifica per il metodo richiesto."""
    host = normalize_hostname(domain)
    token = generate_verification_token()
    expires_at = datetime.now(UTC) + timedelta(days=TOKEN_VALIDITY_DAYS)

    if method == VerificationMethod.DNS_TXT.value:
        return VerificationChallenge(
            domain=host, method=method, token=token, expires_at=expires_at,
            record_name=f"_defenix-verification.{host}", record_value=token,
            instructions_it=(
                f"Pubblicare un record TXT su `_defenix-verification.{host}` "
                f"con valore `{token}`. Il record puo' essere rimosso dopo la verifica. "
                f"La sfida scade il {expires_at.date().isoformat()}."))

    if method == VerificationMethod.HTTP_FILE.value:
        return VerificationChallenge(
            domain=host, method=method, token=token, expires_at=expires_at,
            file_url=f"https://{host}{VERIFICATION_FILE_PATH}", file_content=token,
            instructions_it=(
                f"Pubblicare il file `{VERIFICATION_FILE_PATH}` su https://{host} "
                f"contenente esclusivamente la stringa `{token}`. "
                f"La sfida scade il {expires_at.date().isoformat()}."))

    if method == VerificationMethod.ADMIN_EMAIL.value:
        addresses = ", ".join(f"{local}@{host}" for local in sorted(ADMIN_EMAIL_LOCALPARTS))
        return VerificationChallenge(
            domain=host, method=method, token=token, expires_at=expires_at,
            instructions_it=(
                f"Verra' inviato un codice di verifica a uno degli indirizzi amministrativi "
                f"del dominio ({addresses}). Inserire il codice ricevuto per completare la verifica. "
                f"La sfida scade il {expires_at.date().isoformat()}."))

    if method == VerificationMethod.MANUAL_APPROVAL.value:
        return VerificationChallenge(
            domain=host, method=method, token=token, expires_at=expires_at,
            instructions_it=(
                "Un amministratore della piattaforma deve approvare manualmente la titolarita' "
                "del dominio, allegando il riferimento del documento di autorizzazione. "
                "L'operazione viene registrata nell'audit log con nome dell'approvatore."))

    raise ValueError(f"Metodo di verifica non supportato: {method}")


def verify_dns_txt(domain: str, token: str) -> VerificationOutcome:
    now = datetime.now(UTC)
    if settings.scan_mock_mode:
        return VerificationOutcome(
            False, VerificationMethod.DNS_TXT.value,
            "modalita' mock attiva: la verifica DNS reale non viene eseguita. "
            "Usare l'approvazione manuale nelle installazioni di prova.", now)
    try:
        import dns.resolver

        host = normalize_hostname(domain)
        resolver = dns.resolver.Resolver()
        resolver.timeout, resolver.lifetime = 5.0, 10.0
        answers = resolver.resolve(f"_defenix-verification.{host}", "TXT")
        values = [b"".join(r.strings).decode("utf-8", "replace").strip('"') for r in answers]
    except ScopeViolation as exc:
        return VerificationOutcome(False, VerificationMethod.DNS_TXT.value, exc.reason, now)
    except Exception as exc:  # noqa: BLE001
        return VerificationOutcome(False, VerificationMethod.DNS_TXT.value,
                                   f"record TXT non risolvibile ({type(exc).__name__})", now)
    if token in values:
        return VerificationOutcome(True, VerificationMethod.DNS_TXT.value,
                                   "record TXT presente e corrispondente", now)
    return VerificationOutcome(False, VerificationMethod.DNS_TXT.value,
                               f"record TXT presente ma non corrispondente ({len(values)} valori trovati)",
                               now)


def verify_http_file(domain: str, token: str) -> VerificationOutcome:
    now = datetime.now(UTC)
    if settings.scan_mock_mode:
        return VerificationOutcome(
            False, VerificationMethod.HTTP_FILE.value,
            "modalita' mock attiva: la verifica HTTP reale non viene eseguita.", now)
    try:
        host = normalize_hostname(domain)
        # `follow_redirects=False`: un redirect non deve poter spostare la
        # verifica su un host non controllato dall'organizzazione.
        response = httpx.get(f"https://{host}{VERIFICATION_FILE_PATH}",
                             timeout=10.0, follow_redirects=False)
        response.raise_for_status()
        content = response.text.strip()[:512]
    except ScopeViolation as exc:
        return VerificationOutcome(False, VerificationMethod.HTTP_FILE.value, exc.reason, now)
    except Exception as exc:  # noqa: BLE001
        return VerificationOutcome(False, VerificationMethod.HTTP_FILE.value,
                                   f"file di verifica non raggiungibile ({type(exc).__name__})", now)
    if content == token:
        return VerificationOutcome(True, VerificationMethod.HTTP_FILE.value,
                                   "file di verifica presente e corrispondente", now)
    return VerificationOutcome(False, VerificationMethod.HTTP_FILE.value,
                               "file presente ma contenuto non corrispondente", now)


def verify_admin_email(submitted_token: str, expected_token: str) -> VerificationOutcome:
    now = datetime.now(UTC)
    ok = bool(expected_token) and submitted_token.strip() == expected_token
    return VerificationOutcome(
        ok, VerificationMethod.ADMIN_EMAIL.value,
        "codice corrispondente" if ok else "codice non corrispondente o scaduto", now)


def is_admin_email(address: str, domain: str) -> bool:
    local, _, host = address.lower().partition("@")
    return host == domain.lower() and local in ADMIN_EMAIL_LOCALPARTS


def run_verification(domain: str, method: str, token: str,
                     submitted_token: str | None = None) -> VerificationOutcome:
    if method == VerificationMethod.DNS_TXT.value:
        return verify_dns_txt(domain, token)
    if method == VerificationMethod.HTTP_FILE.value:
        return verify_http_file(domain, token)
    if method == VerificationMethod.ADMIN_EMAIL.value:
        return verify_admin_email(submitted_token or "", token)
    if method == VerificationMethod.MANUAL_APPROVAL.value:
        return VerificationOutcome(
            False, method,
            "l'approvazione manuale richiede l'azione esplicita di un amministratore "
            "tramite l'endpoint dedicato", datetime.now(UTC))
    raise ValueError(f"Metodo di verifica non supportato: {method}")


def is_challenge_expired(expires_at: datetime | None) -> bool:
    if expires_at is None:
        return True
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return datetime.now(UTC) > expires_at


def next_status(outcome: VerificationOutcome, attempts: int) -> str:
    if outcome.verified:
        return VerificationStatus.VERIFIED.value
    if attempts >= MAX_VERIFICATION_ATTEMPTS:
        return VerificationStatus.FAILED.value
    return VerificationStatus.PENDING.value
