"""Classificazione della proprieta' degli asset (sezione 4).

Il perimetro NON si espande automaticamente verso CDN, cloud, hosting
condivisi, fornitori o SaaS: quegli asset sono `third_party` e non
influenzano il rating.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

from app.models.enums import OwnershipStatus
from app.services.scope_guard import CDN_AND_CLOUD_SUFFIXES, SHARED_HOSTING_MARKERS, ScopeGuard


@dataclass(frozen=True)
class OwnershipDecision:
    status: str
    confidence: float
    reason: str
    is_third_party_hosted: bool = False
    is_cdn_fronted: bool = False


@dataclass
class OwnershipContext:
    """Fatti verificati sui quali si basa la classificazione."""

    verified_domains: frozenset[str]        # domini con proprieta' verificata
    declared_domains: frozenset[str]        # domini dichiarati ma non verificati
    authorized_ips: frozenset[str]          # IP con autorizzazione registrata
    authorized_networks: tuple[str, ...]    # CIDR con autorizzazione registrata
    excluded_values: frozenset[str] = frozenset()

    @classmethod
    def build(cls, *, verified_domains: Iterable[str], declared_domains: Iterable[str],
              authorized_ips: Iterable[str], authorized_networks: Iterable[str],
              excluded_values: Iterable[str] = ()) -> "OwnershipContext":
        norm = lambda values: frozenset(str(v).strip().lower().rstrip(".") for v in values if v)  # noqa: E731
        return cls(
            verified_domains=norm(verified_domains),
            declared_domains=norm(declared_domains),
            authorized_ips=norm(authorized_ips),
            authorized_networks=tuple(str(n).strip() for n in authorized_networks if n),
            excluded_values=norm(excluded_values),
        )


def _under_domain(host: str, domains: Iterable[str]) -> str | None:
    for domain in domains:
        if host == domain or host.endswith("." + domain):
            return domain
    return None


def _is_third_party_host(host: str) -> tuple[bool, bool]:
    """(e' di terzi, e' dietro CDN)."""
    cdn = any(host == suffix or host.endswith("." + suffix) for suffix in CDN_AND_CLOUD_SUFFIXES)
    shared = any(host == suffix or host.endswith("." + suffix) for suffix in SHARED_HOSTING_MARKERS)
    return (cdn or shared), cdn


def classify_host(host: str, context: OwnershipContext) -> OwnershipDecision:
    host = host.strip().lower().rstrip(".")
    if host in context.excluded_values:
        return OwnershipDecision(OwnershipStatus.EXCLUDED.value, 1.0,
                                 "asset escluso esplicitamente dal perimetro")

    third_party, cdn = _is_third_party_host(host)
    if third_party:
        return OwnershipDecision(
            OwnershipStatus.THIRD_PARTY.value, 0.9,
            "il nome appartiene a un provider CDN, cloud, hosting condiviso o SaaS: "
            "il perimetro non viene esteso automaticamente",
            is_third_party_hosted=True, is_cdn_fronted=cdn)

    verified_parent = _under_domain(host, context.verified_domains)
    if verified_parent:
        if host == verified_parent:
            return OwnershipDecision(OwnershipStatus.VERIFIED_OWNED.value, 1.0,
                                     f"dominio verificato: {verified_parent}")
        # Un sottodominio di un dominio verificato e' sotto il controllo DNS
        # dell'organizzazione: e' considerato verificato.
        return OwnershipDecision(OwnershipStatus.VERIFIED_OWNED.value, 0.95,
                                 f"sottodominio del dominio verificato {verified_parent}")

    declared_parent = _under_domain(host, context.declared_domains)
    if declared_parent:
        return OwnershipDecision(
            OwnershipStatus.LIKELY_OWNED.value, 0.6,
            f"riconducibile al dominio dichiarato {declared_parent}, la cui proprieta' "
            "non e' stata ancora verificata")

    return OwnershipDecision(OwnershipStatus.UNVERIFIED.value, 0.2,
                             "asset non riconducibile a un dominio dichiarato o verificato")


def classify_ip(address: str, context: OwnershipContext) -> OwnershipDecision:
    address = address.strip()
    if address in context.excluded_values:
        return OwnershipDecision(OwnershipStatus.EXCLUDED.value, 1.0,
                                 "indirizzo escluso esplicitamente dal perimetro")
    if address in context.authorized_ips:
        return OwnershipDecision(OwnershipStatus.VERIFIED_OWNED.value, 1.0,
                                 "indirizzo IP coperto da autorizzazione esplicita")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return OwnershipDecision(OwnershipStatus.UNVERIFIED.value, 0.0, "indirizzo IP non valido")
    for cidr in context.authorized_networks:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return OwnershipDecision(OwnershipStatus.VERIFIED_OWNED.value, 1.0,
                                         f"indirizzo compreso nella rete autorizzata {cidr}")
        except ValueError:
            continue
    # Un IP raggiunto solo per risoluzione DNS non e' di proprieta' dimostrata:
    # potrebbe essere un IP condiviso, una CDN o un hosting di terzi.
    return OwnershipDecision(
        OwnershipStatus.UNVERIFIED.value, 0.25,
        "indirizzo raggiunto per risoluzione DNS ma privo di autorizzazione esplicita: "
        "potrebbe essere condiviso, appartenere a una CDN o a un hosting di terzi")


def classify_asset(asset_key: str, asset_type: str, context: OwnershipContext) -> OwnershipDecision:
    """Punto d'ingresso unico usato dalla pipeline di normalizzazione."""
    if asset_type in {"ip_address", "network_range"}:
        return classify_ip(asset_key.split("/")[0], context)
    if asset_type in {"web_service", "mail_service", "network_service"}:
        # Chiavi composte: `web:host`, `mail:domain`, `service:ip:porta`.
        prefix, _, remainder = asset_key.partition(":")
        if prefix == "service":
            return classify_ip(remainder.split(":")[0], context)
        return classify_host(remainder or asset_key, context)
    if asset_type == "email_address":
        _, _, domain = asset_key.partition("@")
        return classify_host(domain or asset_key, context)
    if asset_type in {"asn", "brand"}:
        return OwnershipDecision(OwnershipStatus.UNVERIFIED.value, 0.3,
                                 "elemento contestuale: non contribuisce direttamente al rating")
    return classify_host(asset_key, context)


def build_scope_guard_from_ownership(context: OwnershipContext, *,
                                     require_explicit_whitelist: bool = False) -> ScopeGuard:
    """Costruisce un ScopeGuard coerente con gli asset di proprieta' accertata."""
    from app.services.scope_guard import ScopeEntry

    entries = [ScopeEntry("wildcard_domain", f"*.{domain}")
               for domain in sorted(context.verified_domains | context.declared_domains)]
    entries += [ScopeEntry("ip_address", ip) for ip in sorted(context.authorized_ips)]
    entries += [ScopeEntry("cidr", cidr) for cidr in context.authorized_networks]
    entries += [ScopeEntry("domain", value, "exclude") for value in sorted(context.excluded_values)]
    return ScopeGuard(entries, require_explicit_whitelist=require_explicit_whitelist)
