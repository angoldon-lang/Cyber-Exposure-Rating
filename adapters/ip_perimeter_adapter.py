"""Adapter «perimetro IP»: quali indirizzi pubblici espone l'organizzazione.

Prima di questo passaggio la scansione conosceva gli indirizzi solo come
sottoprodotto della risoluzione DNS, senza sapere a chi appartenesse la rete
che li ospita. Il port scanning, di conseguenza, aveva come bersagli soltanto
gli indirizzi digitati a mano nel perimetro — in pratica nessuno.

Qui ogni indirizzo raggiunto dai domini in perimetro viene arricchito con il
reverse DNS e con la rete RDAP, e classificato: infrastruttura condivisa di un
fornitore, istanza ospitata, oppure rete propria. La classificazione non
autorizza nulla: stabilisce quali indirizzi ha senso proporre all'analista e
quali vanno esclusi comunque.

L'adapter e' passivo: reverse DNS e RDAP sono interrogazioni a registri
pubblici, non contatti con i sistemi dell'organizzazione.
"""
from __future__ import annotations

from typing import Any

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset
from adapters.http_sicuro import get_seguendo_redirect
from adapters.synthetic import build_posture
from app.models.enums import AssetType, ScoreCategoryKey
from app.services.ip_perimeter import ClassificazioneIP, classifica, indirizzo_pubblico

RDAP_IP = "https://rdap.org/ip/"


class IPPerimeterAdapter(BaseAdapter):
    key = "ip_perimeter"
    display_name = "Perimetro IP pubblico"
    is_passive = True
    coverage_areas = (ScoreCategoryKey.ATTACK_SURFACE.value,)
    default_timeout = 180

    def check_available(self) -> tuple[bool, str]:
        if not self._candidati():
            return False, "nessun indirizzo IP pubblico raggiunto dai domini in perimetro"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def _candidati(self) -> dict[str, set[str]]:
        """Indirizzo -> domini che lo risolvono.

        Gli indirizzi arrivano dalla fase di discovery (record A/AAAA) e da
        quelli gia' dichiarati nel perimetro. Quelli non instradabili su
        Internet sono scartati subito: non sono esposizione.
        """
        mappa: dict[str, set[str]] = {}
        for indirizzo, domini in (self.context.resolved_ips or {}).items():
            if indirizzo_pubblico(indirizzo):
                mappa.setdefault(indirizzo, set()).update(domini)
        for indirizzo in self.context.ip_addresses:
            if indirizzo_pubblico(indirizzo):
                mappa.setdefault(indirizzo, set())
        return mappa

    def _verificato(self, domini: set[str]) -> bool:
        verificati = {d.lower() for d in self.context.verified_domains}
        return any(d.lower() in verificati or
                   any(d.lower().endswith(f".{v}") for v in verificati) for d in domini)

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        candidati = self._candidati()
        classificazioni: list[ClassificazioneIP] = []
        raw: dict[str, Any] = {}
        errori = 0

        with httpx.Client(timeout=15.0, follow_redirects=False,
                          headers={"Accept": "application/rdap+json"}) as client:
            for indirizzo, domini in sorted(candidati.items()):
                rete = {}
                try:
                    # Come per RDAP sui domini, il bootstrap rimanda al
                    # registro regionale competente: senza seguire il salto
                    # non si ottiene mai la risposta.
                    risposta = get_seguendo_redirect(client, f"{RDAP_IP}{indirizzo}")
                    if risposta.status_code < 400:
                        rete = risposta.json()
                except Exception:  # noqa: BLE001 - la rete resta sconosciuta
                    errori += 1
                raw[indirizzo] = {"rdap": self._sintesi_rdap(rete),
                                  "domains": sorted(domini)}
                classificazioni.append(classifica(
                    indirizzo, reverse_dns=self._reverse_dns(indirizzo),
                    asn=self._asn(rete), asn_org=self._organizzazione(rete),
                    rete=self._cidr(rete), domini_origine=domini,
                    da_dominio_verificato=self._verificato(domini)))

        return AdapterResult(
            tool=self.key,
            status=AdapterStatus.PARTIAL if errori and errori < len(candidati)
            else AdapterStatus.FAILED if errori else AdapterStatus.SUCCESS,
            assets=[self._asset(c) for c in classificazioni],
            target_count=len(candidati), raw_output=self.dump_json(raw),
            error_message=(f"{errori} indirizzi senza risposta RDAP: rete sconosciuta"
                           if errori else None),
            coverage_impact=0.0 if not errori else self.coverage_weight * 0.3,
            config_snapshot={"addresses": len(classificazioni),
                             "third_party": sum(1 for c in classificazioni if not c.sondabile)})

    # ------------------------------------------------------------------
    @staticmethod
    def _reverse_dns(indirizzo: str) -> str | None:
        try:
            import dns.resolver
            import dns.reversename

            nome = dns.reversename.from_address(indirizzo)
            risposta = dns.resolver.resolve(nome, "PTR", lifetime=5.0)
            return str(risposta[0]).rstrip(".").lower()
        except Exception:  # noqa: BLE001 - l'assenza di PTR e' un esito normale
            return None

    @staticmethod
    def _organizzazione(rete: dict) -> str | None:
        """Nome dell'organizzazione a cui la rete e' assegnata.

        RDAP la espone in due punti diversi a seconda del registro: nel campo
        `name` della rete, oppure fra le entita' con ruolo `registrant`.
        """
        nome = rete.get("name")
        if isinstance(nome, str) and nome.strip():
            return nome.strip()
        for entita in rete.get("entities", []) or []:
            if not isinstance(entita, dict):
                continue
            if "registrant" not in (entita.get("roles") or []):
                continue
            for voce in (entita.get("vcardArray") or [None, []])[1]:
                if isinstance(voce, list) and len(voce) >= 4 and voce[0] == "fn":
                    return str(voce[3])
        return None

    @staticmethod
    def _asn(rete: dict) -> int | None:
        for chiave in ("autnums", "arin_originas0_originautnums"):
            valori = rete.get(chiave)
            if isinstance(valori, list) and valori:
                try:
                    return int(valori[0])
                except (TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def _cidr(rete: dict) -> str | None:
        for cidr in rete.get("cidr0_cidrs", []) or []:
            if not isinstance(cidr, dict):
                continue
            prefisso = cidr.get("v4prefix") or cidr.get("v6prefix")
            if prefisso:
                return f"{prefisso}/{cidr.get('length')}"
        inizio, fine = rete.get("startAddress"), rete.get("endAddress")
        return f"{inizio} - {fine}" if inizio and fine else None

    def _sintesi_rdap(self, rete: dict) -> dict[str, Any]:
        """Solo i campi usati: l'RDAP completo contiene contatti personali."""
        return {"name": self._organizzazione(rete), "asn": self._asn(rete),
                "cidr": self._cidr(rete), "handle": rete.get("handle")}

    def _asset(self, classificazione: ClassificazioneIP) -> DiscoveredAsset:
        return DiscoveredAsset(
            asset_key=classificazione.indirizzo, asset_type=AssetType.IP_ADDRESS.value,
            display_name=classificazione.indirizzo, discovered_by=self.key,
            attributes=classificazione.to_dict(),
            relationships=[{"type": "resolves_to", "source": dominio,
                            "target": classificazione.indirizzo}
                           for dominio in classificazione.domini_origine])

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        classificazioni: list[ClassificazioneIP] = []
        for dominio in self.context.domains:
            posture = build_posture(self.context.seed(dominio), dominio,
                                    self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            for indice, indirizzo in enumerate(posture.ip_addresses):
                # Un indirizzo dietro CDN e il resto su hosting: la demo deve
                # mostrare entrambi gli esiti, altrimenti l'esclusione delle
                # reti condivise non si vede mai.
                dietro_cdn = indice == 0
                classificazioni.append(classifica(
                    indirizzo,
                    reverse_dns=f"host-{indice}.{'cloudflare.com' if dietro_cdn else 'aruba.it'}",
                    asn=13335 if dietro_cdn else 31034,
                    asn_org="Cloudflare, Inc." if dietro_cdn else "Aruba S.p.A.",
                    rete=f"{indirizzo}/32", domini_origine={dominio},
                    da_dominio_verificato=dominio in self.context.verified_domains))
        return AdapterResult(
            tool=self.key, status=AdapterStatus.SUCCESS, was_mocked=True,
            assets=[self._asset(c) for c in classificazioni],
            target_count=len(classificazioni), tool_version="perimetro IP (mock)",
            raw_output=self.dump_json([c.to_dict() for c in classificazioni]),
            config_snapshot={"addresses": len(classificazioni),
                             "third_party": sum(1 for c in classificazioni if not c.sondabile)})
