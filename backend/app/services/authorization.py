"""Gate di autorizzazione all'avvio di una scansione (sezione 4).

E' l'unico punto che decide se una scansione puo' partire. Ogni rifiuto
produce un motivo leggibile ed e' registrato nell'audit log dal chiamante.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Sequence

from app.models.enums import AuthorizationStatus, ScanProfileType, VerificationStatus


@dataclass
class AuthorizationCheck:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    authorization_id: str | None = None
    expires_at: datetime | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reasons": self.reasons,
            "authorization_id": self.authorization_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass
class DomainView:
    name: str
    verification_status: str


@dataclass
class AuthorizationView:
    authorization_id: str
    status: str
    valid_from: datetime
    expires_at: datetime
    revoked_at: datetime | None
    allowed_profiles: Sequence[str]


@dataclass
class ScopeView:
    entry_type: str
    value: str
    action: str
    is_active: bool = True


def check_scan_authorization(
    *,
    profile: str,
    domains: Sequence[DomainView],
    authorizations: Sequence[AuthorizationView],
    scopes: Sequence[ScopeView],
    profile_definition: dict,
    now: datetime | None = None,
) -> AuthorizationCheck:
    """Verifica tutte le precondizioni per l'avvio di una scansione."""
    now = now or datetime.now(UTC)
    reasons: list[str] = []

    if not domains:
        reasons.append("nessun dominio associato all'azienda")

    # --- Il profilo passivo non richiede verifica ne' autorizzazione ---
    if profile == ScanProfileType.PUBLIC_PASSIVE.value:
        return AuthorizationCheck(allowed=not reasons, reasons=reasons)

    # --- Verifica della proprieta' del dominio ---
    if profile_definition.get("requires_verification", True):
        verified = [d for d in domains if d.verification_status == VerificationStatus.VERIFIED.value]
        if not verified:
            reasons.append(
                "nessun dominio verificato: il profilo richiede la verifica della proprieta' "
                "tramite record DNS TXT, file sul sito, e-mail amministrativa o approvazione manuale")

    # --- Autorizzazione formale attiva e non scaduta ---
    selected: AuthorizationView | None = None
    if profile_definition.get("requires_authorization", True):
        candidates = []
        for authorization in authorizations:
            if authorization.status != AuthorizationStatus.ACTIVE.value:
                continue
            if authorization.revoked_at is not None:
                continue
            valid_from = _aware(authorization.valid_from)
            expires_at = _aware(authorization.expires_at)
            if not (valid_from <= now <= expires_at):
                continue
            if profile not in (authorization.allowed_profiles or []):
                continue
            candidates.append((expires_at, authorization))
        if not candidates:
            reasons.append(
                f"nessuna autorizzazione attiva e non scaduta che includa il profilo «{profile}»")
        else:
            # A parita' di validita' si sceglie quella che scade piu' tardi.
            candidates.sort(key=lambda item: item[0], reverse=True)
            selected = candidates[0][1]

    # --- Whitelist esplicita per il profilo esteso ---
    if profile_definition.get("requires_explicit_scope_whitelist", False):
        includes = [s for s in scopes if s.is_active and s.action == "include"]
        if not includes:
            reasons.append(
                "il profilo esteso richiede una whitelist esplicita di IP, domini o URL "
                "approvati: nessuna voce di perimetro attiva trovata")

    return AuthorizationCheck(
        allowed=not reasons,
        reasons=reasons,
        authorization_id=selected.authorization_id if selected else None,
        expires_at=_aware(selected.expires_at) if selected else None,
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
