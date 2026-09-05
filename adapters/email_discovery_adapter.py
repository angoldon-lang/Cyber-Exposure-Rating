"""Scoperta degli indirizzi e-mail dell'organizzazione da fonti DNS pubbliche.

Il problema
-----------
La verifica sulle violazioni ha bisogno di indirizzi da cercare. Finora
l'unica fonte erano i moduli di raccolta di SpiderFoot: senza un'istanza
SpiderFoot configurata non c'era alcun indirizzo, XposedOrNot restava saltato
e la sezione dark web era vuota — senza che nulla dicesse che la causa era una
dipendenza mancante, non l'assenza di esposizione.

Il DNS pubblico dell'organizzazione contiene gia' indirizzi reali:

* **DMARC** — i tag `rua` e `ruf` indicano dove spedire i rapporti di
  autenticazione. Quando puntano a una casella del dominio stesso sono
  indirizzi veri dell'organizzazione.
* **SOA** — il campo RNAME e' l'indirizzo del responsabile della zona, scritto
  con un punto al posto della chiocciola.

Sono entrambe interrogazioni al DNS pubblico: nessun contatto con i sistemi
dell'organizzazione, quindi ammesse anche nel profilo passivo.

Cosa resta fuori
----------------
Gli indirizzi su domini diversi da quelli in perimetro non vengono raccolti.
Un `rua` che punta a un servizio di elaborazione DMARC di terzi e' la norma:
e' un indirizzo del fornitore, non del cliente, ed e' un dato personale che
non riguarda il perimetro valutato.
"""
from __future__ import annotations

import re
from typing import Any

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset
from app.core.redaction import mask_email
from app.models.enums import AssetType, ScoreCategoryKey

# `rua=mailto:a@b.it!10m, mailto:c@d.it` — piu' destinazioni, con dimensione
# massima opzionale dopo il punto esclamativo.
_MAILTO = re.compile(r"mailto:\s*([^\s,;!]+@[^\s,;!]+)", re.IGNORECASE)


def indirizzi_da_dmarc(record: str) -> list[str]:
    """Indirizzi indicati dai tag `rua` e `ruf` di un record DMARC."""
    return [m.group(1).strip().lower() for m in _MAILTO.finditer(record or "")]


def indirizzo_da_soa(rname: str) -> str | None:
    """Converte il campo RNAME di un record SOA in un indirizzo e-mail.

    Nel SOA la chiocciola e' scritta come punto: `hostmaster.esempio.it.`
    significa `hostmaster@esempio.it`. Un punto preceduto da barra rovesciata
    fa parte del nome della casella e non va convertito.
    """
    valore = (rname or "").strip().rstrip(".")
    if not valore or "@" in valore:
        return valore.lower() or None
    parti = re.split(r"(?<!\\)\.", valore, maxsplit=1)
    # Il RNAME ha sempre almeno tre etichette («casella.dominio.tld»): con due
    # il valore non e' un indirizzo, e spezzarlo produrrebbe «acme@it».
    if len(parti) != 2 or "." not in parti[1]:
        return None
    return f"{parti[0].replace(chr(92) + '.', '.').lower()}@{parti[1].lower()}"


class EmailDiscoveryAdapter(BaseAdapter):
    key = "email_discovery"
    display_name = "Indirizzi e-mail da DNS"
    is_passive = True
    coverage_areas = (ScoreCategoryKey.DARKWEB_BREACH.value,)
    default_timeout = 60

    def check_available(self) -> tuple[bool, str]:
        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            return False, "dnspython non installato"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def _in_perimetro(self, indirizzo: str) -> bool:
        if "@" not in indirizzo:
            return False
        dominio = indirizzo.rsplit("@", 1)[1]
        domini = {d.lower() for d in self.context.domains}
        return dominio in domini or any(dominio.endswith(f".{d}") for d in domini)

    def execute(self) -> AdapterResult:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        trovati: dict[str, set[str]] = {}
        raw: dict[str, Any] = {}
        domini = self.context.scope_guard.filter_targets(self.context.domains, "hostname")

        for dominio in domini:
            fonti: dict[str, list[str]] = {"dmarc": [], "soa": []}
            try:
                for risposta in resolver.resolve(f"_dmarc.{dominio}", "TXT"):
                    record = "".join(p.decode() if isinstance(p, bytes) else str(p)
                                     for p in getattr(risposta, "strings", []) or [str(risposta)])
                    if record.lower().replace('"', "").startswith("v=dmarc1"):
                        fonti["dmarc"].extend(indirizzi_da_dmarc(record))
            except Exception:  # noqa: BLE001 - l'assenza del record e' un esito normale
                pass
            try:
                for risposta in resolver.resolve(dominio, "SOA"):
                    indirizzo = indirizzo_da_soa(str(getattr(risposta, "rname", "")))
                    if indirizzo:
                        fonti["soa"].append(indirizzo)
            except Exception:  # noqa: BLE001
                pass

            raw[dominio] = {chiave: sorted({mask_email(v) for v in valori})
                            for chiave, valori in fonti.items()}
            for chiave, valori in fonti.items():
                for indirizzo in valori:
                    if self._in_perimetro(indirizzo):
                        trovati.setdefault(indirizzo, set()).add(chiave)

        # Anche gli indirizzi dichiarati nel perimetro diventano asset: senza,
        # comparirebbero nei rilievi delle violazioni ma non nell'inventario.
        for indirizzo in self.context.email_addresses:
            normalizzato = str(indirizzo).strip().lower()
            if self._in_perimetro(normalizzato):
                trovati.setdefault(normalizzato, set()).add("dichiarato")

        assets = [
            DiscoveredAsset(
                asset_key=indirizzo, asset_type=AssetType.EMAIL_ADDRESS.value,
                display_name=mask_email(indirizzo), discovered_by=self.key,
                attributes={"masked": True, "sources": sorted(fonti)})
            for indirizzo, fonti in sorted(trovati.items())
        ]
        return AdapterResult(
            tool=self.key,
            status=AdapterStatus.SUCCESS if domini else AdapterStatus.SKIPPED,
            assets=assets, target_count=len(domini), raw_output=self.dump_json(raw),
            error_message=None if domini else "nessun dominio in perimetro",
            config_snapshot={"addresses": len(assets)})

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        assets = [
            DiscoveredAsset(
                asset_key=f"{locale}@{dominio}", asset_type=AssetType.EMAIL_ADDRESS.value,
                display_name=mask_email(f"{locale}@{dominio}"), discovered_by=self.key,
                attributes={"masked": True, "sources": [fonte]})
            for dominio in self.context.domains
            for locale, fonte in (("dmarc-reports", "dmarc"), ("hostmaster", "soa"))
        ]
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, assets=assets,
                             was_mocked=True, tool_version="scoperta e-mail (mock)",
                             target_count=len(self.context.domains),
                             config_snapshot={"addresses": len(assets)})
