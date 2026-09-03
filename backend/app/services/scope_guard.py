"""ScopeGuard: unico punto di autorizzazione dei target di scansione.

Nessun adapter puo' contattare un target che non sia passato da qui.
Protegge da SSRF, scansione di reti private, DNS rebinding, credenziali in URL,
redirect fuori perimetro e path traversal.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Iterable
from urllib.parse import urlparse

import idna

from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import ScopeAction, ScopeEntryType

logger = get_logger(__name__)

# Provider su cui NON si espande automaticamente il perimetro (sezione 4).
CDN_AND_CLOUD_SUFFIXES: tuple[str, ...] = (
    "cloudflare.net", "cloudflarenet.com", "cdn.cloudflare.net", "akamai.net",
    "akamaiedge.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net",
    "fastly.net", "fastlylb.net", "cloudfront.net", "azureedge.net",
    "azurefd.net", "trafficmanager.net", "amazonaws.com", "elb.amazonaws.com",
    "googleusercontent.com", "appspot.com", "cloudapp.azure.com", "herokuapp.com",
    "netlify.app", "vercel.app", "github.io", "githubusercontent.com",
    "wpengine.com", "squarespace.com", "wixsite.com", "shopify.com",
    "sharepoint.com", "outlook.com", "protection.outlook.com", "office365.com",
    "googlemail.com", "google.com", "mimecast.com", "pphosted.com",
    "messagelabs.com", "barracudanetworks.com", "sendgrid.net", "mailgun.org",
)

SHARED_HOSTING_MARKERS: tuple[str, ...] = (
    "aruba.it", "register.it", "ovh.net", "ionos.com", "hostinger.com",
    "siteground.com", "godaddy.com", "bluehost.com",
)

# Reti riservate alla documentazione (RFC 5737 / RFC 3849): non instradabili su
# Internet. Sono ammesse SOLO in mock mode, dove servono ai dati sintetici.
DOCUMENTATION_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# Endpoint di metadati dei cloud provider: bersaglio classico di SSRF.
CLOUD_METADATA_ADDRESSES: frozenset[str] = frozenset({
    "169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200",
})

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$")
_DANGEROUS_CHARS = set(";|&`$><\n\r\t\\\"'()[]{}*?!~ ")


class ScopeViolation(Exception):
    """Sollevata quando un target non e' autorizzato. Non e' recuperabile:
    il target viene scartato e l'evento registrato nell'audit log."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Target fuori perimetro '{target}': {reason}")


@dataclass(frozen=True)
class ScopeEntry:
    entry_type: str
    value: str
    action: str = ScopeAction.INCLUDE.value


@dataclass
class ScopeDecision:
    target: str
    allowed: bool
    reason: str
    normalized: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    matched_entry: str | None = None
    is_cdn_or_cloud: bool = False


def is_documentation_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in DOCUMENTATION_NETWORKS if ip.version == network.version)


def _is_public_ip(address: str, allow_documentation: bool = False) -> bool:
    """Un indirizzo e' contattabile solo se pubblicamente instradabile.

    Gli endpoint di metadati cloud sono sempre negati, anche se una policy
    permissiva abilitasse le reti private.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if str(ip) in CLOUD_METADATA_ADDRESSES:
        return False
    if allow_documentation and is_documentation_ip(address):
        return True
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
        or (ip.version == 6 and (ip.is_site_local or getattr(ip, "ipv4_mapped", None) is not None))
    )


def normalize_hostname(hostname: str) -> str:
    """Normalizza (IDNA/punycode, lowercase) e valida un hostname.

    Rifiuta metacaratteri di shell: nessun input utente puo' contenerli,
    a prescindere dal fatto che gli argomenti siano passati come array.
    """
    candidate = hostname.strip().rstrip(".").lower()
    if not candidate:
        raise ScopeViolation(hostname, "hostname vuoto")
    if len(candidate) > 253:
        raise ScopeViolation(hostname, "hostname troppo lungo")
    if any(char in _DANGEROUS_CHARS for char in candidate):
        raise ScopeViolation(hostname, "hostname contiene caratteri non ammessi")
    if candidate.startswith("-"):
        raise ScopeViolation(hostname, "hostname non puo' iniziare con '-' (rischio option injection)")
    try:
        candidate = idna.encode(candidate, uts46=True).decode("ascii")
    except idna.IDNAError:
        # Etichette gia' ASCII o non convertibili: si valida con la regex.
        pass
    if not _HOSTNAME_RE.match(candidate):
        raise ScopeViolation(hostname, "hostname non conforme")
    return candidate.rstrip(".")


def is_cdn_or_cloud(hostname: str) -> bool:
    host = hostname.lower().rstrip(".")
    return any(host == suffix or host.endswith("." + suffix)
               for suffix in CDN_AND_CLOUD_SUFFIXES + SHARED_HOSTING_MARKERS)


def resolve_hostname(hostname: str) -> list[str]:
    """Risoluzione DNS con gestione degli errori. In mock mode non risolve."""
    if settings.scan_mock_mode:
        return []
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({info[4][0] for info in infos})


class ScopeGuard:
    """Valuta ogni target rispetto al perimetro autorizzato.

    Ordine di valutazione (il primo che risponde vince):
      1. formato del target (anti command-injection / anti path-traversal)
      2. esclusioni esplicite
      3. indirizzi non pubblici (anti-SSRF)
      4. inclusioni esplicite
      5. default deny
    """

    def __init__(self, entries: Iterable[ScopeEntry], *,
                 allow_private: bool | None = None,
                 allow_documentation_ranges: bool | None = None,
                 require_explicit_whitelist: bool = False) -> None:
        entries = list(entries)
        self.includes = [e for e in entries if e.action == ScopeAction.INCLUDE.value]
        self.excludes = [e for e in entries if e.action == ScopeAction.EXCLUDE.value]
        self.allow_private = settings.allow_private_ip_scanning if allow_private is None else allow_private
        # Le reti di documentazione servono ai dati sintetici: mai in produzione reale.
        self.allow_documentation_ranges = (
            settings.scan_mock_mode if allow_documentation_ranges is None else allow_documentation_ranges
        )
        self.require_explicit_whitelist = require_explicit_whitelist
        self.violations: list[ScopeDecision] = []

    def _public(self, address: str) -> bool:
        return _is_public_ip(address, allow_documentation=self.allow_documentation_ranges)

    # -------------------------- matching helpers --------------------------
    @staticmethod
    def _host_matches(host: str, entry: ScopeEntry) -> bool:
        value = entry.value.lower().rstrip(".")
        if entry.entry_type == ScopeEntryType.DOMAIN.value:
            return host == value
        if entry.entry_type == ScopeEntryType.WILDCARD_DOMAIN.value:
            bare = value.removeprefix("*.")
            return host == bare or host.endswith("." + bare)
        if entry.entry_type == ScopeEntryType.EMAIL_DOMAIN.value:
            return host == value
        if entry.entry_type == ScopeEntryType.URL.value:
            parsed = urlparse(value if "://" in value else f"https://{value}")
            return (parsed.hostname or "").lower() == host
        return False

    @staticmethod
    def _ip_matches(address: str, entry: ScopeEntry) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if entry.entry_type == ScopeEntryType.IP_ADDRESS.value:
            try:
                return ip == ipaddress.ip_address(entry.value)
            except ValueError:
                return False
        if entry.entry_type == ScopeEntryType.CIDR.value:
            try:
                return ip in ipaddress.ip_network(entry.value, strict=False)
            except ValueError:
                return False
        return False

    def _matches_any(self, host_or_ip: str, entries: list[ScopeEntry]) -> ScopeEntry | None:
        for entry in entries:
            if self._host_matches(host_or_ip, entry) or self._ip_matches(host_or_ip, entry):
                return entry
            # Esclusioni con pattern glob esplicito (es. "*.staging.example.com")
            if entry.action == ScopeAction.EXCLUDE.value and "*" in entry.value:
                if fnmatch.fnmatch(host_or_ip, entry.value.lower()):
                    return entry
        return None

    # ------------------------------ API -----------------------------------
    def check_hostname(self, hostname: str) -> ScopeDecision:
        try:
            host = normalize_hostname(hostname)
        except ScopeViolation as exc:
            decision = ScopeDecision(hostname, False, exc.reason)
            self.violations.append(decision)
            return decision

        excluded = self._matches_any(host, self.excludes)
        if excluded is not None:
            decision = ScopeDecision(hostname, False, "target escluso esplicitamente dal perimetro",
                                     normalized=host, matched_entry=excluded.value)
            self.violations.append(decision)
            return decision

        included = self._matches_any(host, self.includes)
        if included is None:
            decision = ScopeDecision(hostname, False, "target non presente nel perimetro autorizzato",
                                     normalized=host)
            self.violations.append(decision)
            return decision

        resolved = resolve_hostname(host)
        if resolved and not self.allow_private:
            non_public = [ip for ip in resolved if not self._public(ip)]
            if non_public:
                # Difesa da DNS rebinding: un hostname in perimetro che risolve
                # verso indirizzi interni viene comunque bloccato.
                decision = ScopeDecision(
                    hostname, False,
                    f"l'hostname risolve verso indirizzi non pubblici: {', '.join(non_public[:3])}",
                    normalized=host, resolved_ips=resolved)
                self.violations.append(decision)
                return decision

        return ScopeDecision(hostname, True, "in perimetro", normalized=host,
                             resolved_ips=resolved, matched_entry=included.value,
                             is_cdn_or_cloud=is_cdn_or_cloud(host))

    def check_ip(self, address: str) -> ScopeDecision:
        try:
            ip = ipaddress.ip_address(address.strip())
        except ValueError:
            decision = ScopeDecision(address, False, "indirizzo IP non valido")
            self.violations.append(decision)
            return decision

        if not self.allow_private and not self._public(str(ip)):
            decision = ScopeDecision(address, False,
                                     "indirizzo privato, loopback, link-local o riservato")
            self.violations.append(decision)
            return decision

        excluded = self._matches_any(str(ip), self.excludes)
        if excluded is not None:
            decision = ScopeDecision(address, False, "IP escluso esplicitamente",
                                     normalized=str(ip), matched_entry=excluded.value)
            self.violations.append(decision)
            return decision

        included = self._matches_any(str(ip), self.includes)
        if included is None:
            decision = ScopeDecision(address, False,
                                     "IP non coperto da un'autorizzazione esplicita", normalized=str(ip))
            self.violations.append(decision)
            return decision

        return ScopeDecision(address, True, "in perimetro", normalized=str(ip),
                             resolved_ips=[str(ip)], matched_entry=included.value)

    def check_url(self, url: str) -> ScopeDecision:
        candidate = url.strip()
        if any(char in candidate for char in "\n\r\t"):
            decision = ScopeDecision(url, False, "URL contiene caratteri di controllo")
            self.violations.append(decision)
            return decision
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            decision = ScopeDecision(url, False, f"schema non ammesso: {parsed.scheme or 'assente'}")
            self.violations.append(decision)
            return decision
        if parsed.username or parsed.password or "@" in (parsed.netloc.split("]")[-1]):
            decision = ScopeDecision(url, False, "URL contiene credenziali")
            self.violations.append(decision)
            return decision
        if ".." in parsed.path:
            decision = ScopeDecision(url, False, "URL contiene path traversal")
            self.violations.append(decision)
            return decision
        host = parsed.hostname
        if not host:
            decision = ScopeDecision(url, False, "URL senza host")
            self.violations.append(decision)
            return decision
        try:
            ipaddress.ip_address(host)
        except ValueError:
            decision = self.check_hostname(host)
        else:
            decision = self.check_ip(host)
        if decision.allowed:
            return ScopeDecision(url, True, decision.reason, normalized=candidate,
                                 resolved_ips=decision.resolved_ips,
                                 matched_entry=decision.matched_entry,
                                 is_cdn_or_cloud=decision.is_cdn_or_cloud)
        return ScopeDecision(url, False, decision.reason, normalized=candidate)

    def check_redirect(self, original_url: str, redirect_url: str) -> ScopeDecision:
        """Ogni hop di redirect e' rivalutato: un redirect non estende il perimetro."""
        decision = self.check_url(redirect_url)
        if not decision.allowed:
            logger.warning("redirect_out_of_scope", original=original_url,
                           redirect=redirect_url, reason=decision.reason)
        return decision

    def filter_targets(self, targets: Iterable[str], kind: str = "hostname") -> list[str]:
        checker = {"hostname": self.check_hostname, "ip": self.check_ip, "url": self.check_url}[kind]
        allowed: list[str] = []
        for target in targets:
            decision = checker(target)
            if decision.allowed and decision.normalized:
                allowed.append(decision.normalized)
        if len(allowed) > settings.scan_max_targets:
            logger.warning("target_limit_enforced", requested=len(allowed),
                           limit=settings.scan_max_targets)
            allowed = allowed[: settings.scan_max_targets]
        return allowed

    def violation_report(self) -> list[dict[str, str]]:
        return [
            {"target": v.target, "reason": v.reason, "at": datetime.now(UTC).isoformat()}
            for v in self.violations
        ]


def build_scope_entries(rows: Iterable[object]) -> list[ScopeEntry]:
    """Converte le righe `Scope` del database in voci immutabili."""
    entries: list[ScopeEntry] = []
    for row in rows:
        if not getattr(row, "is_active", True):
            continue
        entries.append(ScopeEntry(
            entry_type=str(getattr(row, "entry_type")),
            value=str(getattr(row, "value")),
            action=str(getattr(row, "action", ScopeAction.INCLUDE.value)),
        ))
    return entries
