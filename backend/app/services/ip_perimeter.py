"""Perimetro degli indirizzi IP pubblici dell'organizzazione.

Il problema
-----------
I domini dichiarati risolvono su indirizzi IP, e quegli indirizzi espongono
servizi. Sapere *quali* servizi e' esattamente cio' che un'analisi di
esposizione esterna deve dire. Ma un indirizzo raggiunto per risoluzione DNS
non e' per ciò stesso un indirizzo che si possa sondare: puo' essere l'edge di
una CDN, condiviso fra migliaia di clienti, e sondarlo significherebbe sondare
un terzo — cosa che i profili di scansione vietano esplicitamente.

Qui vive la distinzione. La classificazione e' deterministica e non fa I/O: i
dati (reverse DNS e rete RDAP) arrivano gia' raccolti, cosi' la regola resta
verificabile senza rete.

La regola
---------
* **CDN o reverse proxy** (Cloudflare, Akamai, Fastly, Imperva...): l'indirizzo
  e' un punto di ingresso condiviso. Non e' dell'organizzazione e non va mai
  sondato, in nessun profilo.
* **Hosting o cloud** (AWS, Azure, OVH, Aruba...): la rete e' del fornitore, ma
  l'istanza che risponde su quell'indirizzo e' del cliente. Sondarla e'
  legittimo se il cliente l'ha autorizzata; la provenienza va comunque
  dichiarata, perche' cambia chi va avvisato prima.
* **Rete non riconducibile a un fornitore noto**: assegnazione diretta o
  hosting dedicato. Sondabile se autorizzata.

In nessun caso la classificazione *concede* l'autorizzazione: quella resta al
ScopeGuard, che ammette solo indirizzi coperti da una voce esplicita di
perimetro. Qui si stabilisce soltanto quali indirizzi ha senso proporre
all'analista come candidati, e quali vanno esclusi a prescindere.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

# Reti condivise: l'indirizzo risponde per molti clienti insieme.
# Sondarle significa sondare l'infrastruttura del fornitore.
FORNITORI_CONDIVISI: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Cloudflare", ("cloudflare",)),
    ("Akamai", ("akamai",)),
    ("Fastly", ("fastly",)),
    ("Imperva / Incapsula", ("imperva", "incapsula")),
    ("Sucuri", ("sucuri",)),
    ("Stackpath", ("stackpath", "highwinds")),
    ("Edgio / Limelight", ("edgio", "limelight")),
    ("Bunny.net", ("bunnycdn", "bunny.net")),
    ("CDN77", ("cdn77",)),
    ("Qrator", ("qrator",)),
    ("Google Cloud CDN", ("googleusercontent",)),
)

# Reti di fornitori dove l'istanza e' comunque dedicata al cliente.
FORNITORI_HOSTING: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Amazon Web Services", ("amazon", "aws", "ec2", "amazonaws")),
    ("Microsoft Azure", ("microsoft", "azure")),
    ("Google Cloud", ("google llc", "google cloud")),
    ("OVHcloud", ("ovh",)),
    ("Hetzner", ("hetzner",)),
    ("Aruba", ("aruba",)),
    ("Register.it", ("register.it", "registerit")),
    ("Seeweb", ("seeweb",)),
    ("Netsons", ("netsons",)),
    ("IONOS", ("ionos", "1&1", "united-internet")),
    ("DigitalOcean", ("digitalocean",)),
    ("Linode", ("linode",)),
    ("Scaleway / Online.net", ("scaleway", "online sas", "online.net")),
    ("Contabo", ("contabo",)),
    ("Vultr", ("vultr", "choopa")),
)


@dataclass(frozen=True)
class ClassificazioneIP:
    """Esito della classificazione di un singolo indirizzo."""

    indirizzo: str
    reverse_dns: str | None = None
    asn: int | None = None
    asn_org: str | None = None
    rete: str | None = None
    fornitore: str | None = None
    tipo_rete: str = "sconosciuta"      # condivisa | hosting | sconosciuta
    domini_origine: tuple[str, ...] = ()
    da_dominio_verificato: bool = False

    @property
    def is_cdn(self) -> bool:
        return self.tipo_rete == "condivisa"

    @property
    def sondabile(self) -> bool:
        """Vero se ha senso proporre l'indirizzo per una scansione attiva.

        Non significa «autorizzato»: significa soltanto che l'indirizzo
        appartiene all'organizzazione e non all'infrastruttura condivisa di un
        terzo. L'autorizzazione resta una decisione dell'analista, registrata
        nel perimetro.
        """
        return not self.is_cdn

    @property
    def motivo(self) -> str:
        if self.is_cdn:
            return (f"punto di ingresso condiviso di {self.fornitore}: risponde per molti "
                    "clienti insieme, sondarlo significherebbe sondare l'infrastruttura "
                    "del fornitore")
        if self.tipo_rete == "hosting":
            return (f"istanza ospitata su rete {self.fornitore}: l'indirizzo serve "
                    "l'organizzazione, la rete e' del fornitore")
        return "rete non riconducibile a un fornitore noto: assegnazione diretta o hosting dedicato"

    def to_dict(self) -> dict:
        return {"address": self.indirizzo, "reverse_dns": self.reverse_dns,
                "asn": self.asn, "asn_org": self.asn_org, "network": self.rete,
                "provider": self.fornitore, "network_type": self.tipo_rete,
                "is_cdn": self.is_cdn, "scannable": self.sondabile,
                "from_domains": list(self.domini_origine),
                "from_verified_domain": self.da_dominio_verificato,
                "reason": self.motivo}


def _riconosci(testo: str) -> tuple[str | None, str]:
    """Fornitore e tipo di rete dedotti da un testo (org RDAP o reverse DNS)."""
    minuscolo = testo.lower()
    for nome, indizi in FORNITORI_CONDIVISI:
        if any(indizio in minuscolo for indizio in indizi):
            return nome, "condivisa"
    for nome, indizi in FORNITORI_HOSTING:
        if any(indizio in minuscolo for indizio in indizi):
            return nome, "hosting"
    return None, "sconosciuta"


def classifica(indirizzo: str, *, reverse_dns: str | None = None,
               asn: int | None = None, asn_org: str | None = None,
               rete: str | None = None, domini_origine: Iterable[str] = (),
               da_dominio_verificato: bool = False) -> ClassificazioneIP:
    """Classifica un indirizzo a partire dai dati gia' raccolti.

    L'organizzazione RDAP e il reverse DNS sono entrambi indizi: il primo dice
    a chi e' assegnata la rete, il secondo come il fornitore nomina la
    macchina. Basta che uno dei due riconosca una rete condivisa perche'
    l'indirizzo sia escluso: davanti a una CDN e' meglio un falso positivo che
    una scansione su infrastruttura di terzi.
    """
    fornitore, tipo = _riconosci(asn_org or "")
    if tipo != "condivisa":
        da_ptr, tipo_ptr = _riconosci(reverse_dns or "")
        if tipo_ptr == "condivisa" or (tipo == "sconosciuta" and tipo_ptr != "sconosciuta"):
            fornitore, tipo = da_ptr, tipo_ptr
    return ClassificazioneIP(
        indirizzo=indirizzo, reverse_dns=reverse_dns, asn=asn, asn_org=asn_org, rete=rete,
        fornitore=fornitore, tipo_rete=tipo,
        domini_origine=tuple(sorted({d.lower() for d in domini_origine})),
        da_dominio_verificato=da_dominio_verificato)


@dataclass
class PerimetroIP:
    """Riepilogo del perimetro IP di una scansione."""

    classificazioni: list[ClassificazioneIP] = field(default_factory=list)
    gia_autorizzati: set[str] = field(default_factory=set)

    @property
    def candidati(self) -> list[ClassificazioneIP]:
        """Indirizzi sondabili ma non ancora coperti da un'autorizzazione."""
        return [c for c in self.classificazioni
                if c.sondabile and c.indirizzo not in self.gia_autorizzati]

    @property
    def esclusi(self) -> list[ClassificazioneIP]:
        return [c for c in self.classificazioni if not c.sondabile]

    def riepilogo(self) -> dict:
        return {"discovered": len(self.classificazioni),
                "authorized": len([c for c in self.classificazioni
                                   if c.indirizzo in self.gia_autorizzati]),
                "candidates": len(self.candidati),
                "third_party": len(self.esclusi)}


def indirizzo_pubblico(valore: str) -> bool:
    """Vero se l'indirizzo e' instradabile su Internet.

    La definizione non e' ridefinita qui: e' quella del ScopeGuard, che e'
    l'unico punto di autorizzazione. Averne due che possono divergere
    significherebbe accettare nel perimetro indirizzi che poi verrebbero
    rifiutati al momento della scansione, senza che nulla lo spieghi. Le reti
    di documentazione sono ammesse solo in mock mode, come li'.
    """
    from app.core.config import settings
    from app.services.scope_guard import _is_public_ip

    return _is_public_ip(valore.strip(),
                         allow_documentation=settings.scan_mock_mode)
