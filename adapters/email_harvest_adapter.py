"""Raccolta degli indirizzi e-mail pubblicati sul sito dell'organizzazione.

Perche' serve
-------------
La verifica sulle violazioni cerca indirizzi. Le fonti DNS ne danno solo di
tecnici — i destinatari dei rapporti DMARC, il responsabile della zona nel
SOA — e quelli in una violazione non compaiono praticamente mai: nessuno li
usa per registrarsi da qualche parte. Il risultato era una verifica che
girava, non trovava nulla, e sembrava dire che l'organizzazione non e'
esposta.

Gli indirizzi che finiscono nelle violazioni sono quelli delle persone:
`nome.cognome@azienda.it`, `commerciale@`, `amministrazione@`. Stanno sulle
pagine pubbliche dell'organizzazione — contatti, chi siamo, privacy — che
chiunque puo' leggere con un browser.

Cosa fa e cosa non fa
---------------------
Legge la pagina iniziale e un numero limitato di pagine collegate dello
stesso sito, scelte fra quelle che tipicamente contengono contatti. Non
esplora il sito in profondita', non segue link esterni, non invia moduli.
E' comunque una richiesta ai sistemi dell'organizzazione, quindi non e'
ammessa nel profilo passivo.

Gli indirizzi su domini diversi da quelli in perimetro non vengono raccolti:
il consulente che cura il sito, il fornitore citato in una pagina, l'autore
di un plugin sono dati personali estranei alla valutazione.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset
from adapters.http_sicuro import get_seguendo_redirect
from app.core.redaction import mask_email
from app.models.enums import AssetType, ScoreCategoryKey

# Un indirizzo e-mail dentro una pagina HTML. Volutamente conservativo: i
# falsi positivi diventano richieste inutili verso la fonte sulle violazioni,
# che ha un limite severo di chiamate.
_INDIRIZZO = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", re.ASCII)

_LINK = re.compile(r"""href\s*=\s*["']([^"'#?]+)""", re.IGNORECASE)

# Pagine dove i contatti stanno quasi sempre. Provate anche se la pagina
# iniziale non le collega: molti siti le raggiungono solo da un menu
# costruito in JavaScript, che qui non viene eseguito.
PERCORSI_TIPICI = ("/contatti", "/contatti/", "/contact", "/contact-us", "/chi-siamo",
                   "/about", "/about-us", "/privacy", "/privacy-policy", "/note-legali",
                   "/team", "/staff", "/azienda")

# Estensioni che non contengono contatti e costano solo tempo.
_NON_PAGINE = (".pdf", ".zip", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
               ".css", ".js", ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".mp3")

# Nomi che somigliano a indirizzi ma non lo sono: risorse con `@2x`, chiavi
# di servizi, esempi nella documentazione dei temi.
_LOCALI_DA_SCARTARE = frozenset({"2x", "3x", "media", "sentry", "example", "email",
                                 "your", "youremail", "nome", "name", "user"})
_DOMINI_DA_SCARTARE = ("example.com", "example.org", "example.net", "domain.com",
                       "email.com", "sentry.io", "wixpress.com")


def indirizzi_in_pagina(html: str) -> set[str]:
    """Indirizzi plausibili contenuti in una pagina, senza duplicati."""
    trovati: set[str] = set()
    for grezzo in _INDIRIZZO.findall(html or ""):
        indirizzo = grezzo.strip(".-_").lower()
        locale, _, dominio = indirizzo.partition("@")
        if not locale or not dominio or locale in _LOCALI_DA_SCARTARE:
            continue
        if dominio.endswith(_NON_PAGINE) or dominio in _DOMINI_DA_SCARTARE:
            continue
        trovati.add(indirizzo)
    return trovati


def collegamenti_interni(html: str, base: str) -> list[str]:
    """Link della stessa origine, senza risorse statiche."""
    origine = urlsplit(base)
    interni: list[str] = []
    for grezzo in _LINK.findall(html or ""):
        if grezzo.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        assoluto = urljoin(base, grezzo)
        parti = urlsplit(assoluto)
        if parti.scheme not in {"http", "https"} or parti.netloc != origine.netloc:
            continue
        if parti.path.lower().endswith(_NON_PAGINE):
            continue
        pulito = f"{parti.scheme}://{parti.netloc}{parti.path}"
        if pulito not in interni:
            interni.append(pulito)
    return interni


class EmailHarvestAdapter(BaseAdapter):
    key = "email_harvest"
    display_name = "Indirizzi e-mail dal sito"
    # Sono richieste ai sistemi dell'organizzazione, non a fonti pubbliche di
    # terzi: fuori dal profilo passivo, come per gli altri controlli web.
    is_passive = False
    coverage_areas = (ScoreCategoryKey.DARKWEB_BREACH.value,)
    default_timeout = 180

    def check_available(self) -> tuple[bool, str]:
        if not self.context.domains:
            return False, "nessun dominio in perimetro"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def _in_perimetro(self, indirizzo: str) -> bool:
        dominio = indirizzo.rsplit("@", 1)[-1]
        domini = {d.lower() for d in self.context.domains}
        return dominio in domini or any(dominio.endswith(f".{d}") for d in domini)

    def _pagine_iniziali(self) -> list[str]:
        pagine: list[str] = []
        for dominio in self.context.scope_guard.filter_targets(
                self.context.domains, "hostname"):
            for host in (dominio, f"www.{dominio}"):
                pagine.append(f"https://{host}/")
        return pagine

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        massimo_pagine = int(self.config.get("max_pages", 24))
        massimo_byte = int(self.config.get("max_page_bytes", 1_000_000))

        da_visitare = self._pagine_iniziali()
        visitate: list[str] = []
        radici_esplorate: set[str] = set()
        indirizzi: dict[str, set[str]] = {}
        raw: dict[str, Any] = {}
        errori = 0

        with httpx.Client(timeout=15.0, follow_redirects=False,
                          headers={"user-agent": "Defenix-Exposure-Rating"}) as client:
            while da_visitare and len(visitate) < massimo_pagine:
                url = da_visitare.pop(0)
                if url in visitate:
                    continue
                visitate.append(url)
                try:
                    risposta = get_seguendo_redirect(client, url)
                except Exception:  # noqa: BLE001 - una pagina irraggiungibile e' normale
                    errori += 1
                    continue
                if risposta.status_code >= 400:
                    continue
                # Dopo i redirect l'indirizzo finale puo' essere gia' stato
                # letto: `/privacy-policy`, `/privacy-policy/` e `/privacy`
                # arrivano tutti sulla stessa pagina, e senza questo controllo
                # la si scarica tre volte.
                finale = str(risposta.url)
                if finale in visitate and finale != url:
                    continue
                visitate.append(finale)
                if "html" not in risposta.headers.get("content-type", "").lower():
                    continue
                pagina = risposta.text[:massimo_byte]

                nuovi = {a for a in indirizzi_in_pagina(pagina) if self._in_perimetro(a)}
                for indirizzo in nuovi:
                    indirizzi.setdefault(indirizzo, set()).add(url)
                raw[url] = {"addresses": sorted(mask_email(a) for a in nuovi)}

                # Dalla pagina iniziale si aggiungono le pagine tipiche dei
                # contatti e i collegamenti interni, in quest'ordine: sono
                # quelle che pagano di piu' entro il numero massimo.
                # I percorsi tipici si provano una volta sola per sito, e
                # solo quelli che la pagina iniziale non collega gia': su un
                # sito che li ha nel menu, riprovarli e' una serie di 404.
                if radici_esplorate.isdisjoint({urlsplit(url).netloc}):
                    origine = urlsplit(url)
                    radici_esplorate.add(origine.netloc)
                    radice = f"{origine.scheme}://{origine.netloc}"
                    interni = collegamenti_interni(pagina, url)
                    gia_collegati = {urlsplit(u).path.rstrip("/") for u in interni}
                    tipici = [f"{radice}{p}" for p in PERCORSI_TIPICI
                              if p.rstrip("/") not in gia_collegati]
                    da_visitare = interni + tipici + da_visitare

        assets = [
            DiscoveredAsset(
                asset_key=indirizzo, asset_type=AssetType.EMAIL_ADDRESS.value,
                display_name=mask_email(indirizzo), discovered_by=self.key,
                attributes={"masked": True, "sources": ["sito web"],
                            "pages": len(pagine)})
            for indirizzo, pagine in sorted(indirizzi.items())
        ]
        return AdapterResult(
            tool=self.key,
            status=AdapterStatus.PARTIAL if errori and not assets else AdapterStatus.SUCCESS,
            assets=assets, target_count=len(visitate), raw_output=self.dump_json(raw),
            error_message=(f"{errori} pagine non raggiungibili" if errori and not assets
                           else None),
            coverage_impact=self.coverage_weight * 0.5 if errori and not assets else 0.0,
            config_snapshot={"pages_visited": len(visitate), "addresses": len(assets)})

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        assets = [
            DiscoveredAsset(
                asset_key=f"{locale}@{dominio}", asset_type=AssetType.EMAIL_ADDRESS.value,
                display_name=mask_email(f"{locale}@{dominio}"), discovered_by=self.key,
                attributes={"masked": True, "sources": ["sito web"], "pages": 1})
            for dominio in self.context.domains
            for locale in ("info", "amministrazione", "mario.rossi")
        ]
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, assets=assets,
                             was_mocked=True, tool_version="raccolta dal sito (mock)",
                             target_count=len(self.context.domains),
                             config_snapshot={"addresses": len(assets)})
