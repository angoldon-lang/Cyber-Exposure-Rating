"""Adapter theHarvester: indirizzi e-mail e sottodomini da fonti pubbliche.

Che cosa fa davvero, e che cosa no
-----------------------------------
theHarvester **non e' uno strumento dark web** e non verifica le violazioni:
e' un enumeratore OSINT. Interroga decine di fonti pubbliche e restituisce
indirizzi e-mail, sottodomini, host, indirizzi IP e ASN legati a un dominio.

Serve qui per la stessa ragione per cui esistono `email_discovery` ed
`email_harvest`: **la verifica sulle violazioni ha bisogno di indirizzi da
cercare.** Le fonti DNS danno solo caselle tecniche, il sito dell'azienda
quelle pubblicate; theHarvester aggiunge quelle che compaiono nei motori di
ricerca e negli archivi. Piu' indirizzi trovati, meno vuota la sezione dark
web — e quella la riempiono XposedOrNot e HIBP, non questo adapter.

Perche' un servizio a se' e non un binario nell'immagine
--------------------------------------------------------
Due vincoli lo impongono, e nessuno dei due e' negoziabile:

* theHarvester 4.11 dichiara `requires-python >= 3.12`, mentre i worker
  girano su 3.11;
* pinna `httpx`, `fastapi`, `playwright`, `censys` e `shodan` a versioni
  esatte. Installarlo nell'ambiente dell'applicazione significherebbe
  rimetterci le mani ogni volta che una delle due parti si aggiorna — ed e'
  la stessa classe di guaio della collisione fra il binario `httpx` di
  ProjectDiscovery e il pacchetto pip omonimo, che e' gia' costata cara.

Gira quindi come contenitore separato che espone la propria API REST, come
SpiderFoot e ZAP, e il worker la interroga. Il worker non deve poter avviare
altri contenitori.

Che cosa non viene mai chiesto al servizio
-------------------------------------------
L'endpoint `/query` accetta anche `dns_brute`, `take_over`, `api_scan`,
`shodan` e `dns_resolve`: sono attivita' **attive** sul bersaglio, fuori da
cio' che un profilo passivo puo' fare e, nel caso del takeover, vicine a un
tentativo di appropriazione. L'adapter costruisce la richiesta da una lista
chiusa di parametri: quelli non elencati non possono essere aggiunti per
errore ne' arrivare dalla configurazione.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset
from adapters.http_sicuro import get_da_servizio_configurato
from adapters.synthetic import build_posture
from app.core.redaction import mask_email
from app.models.enums import AssetType, ScoreCategoryKey

CATEGORY = ScoreCategoryKey.DARKWEB_BREACH.value

# I soli parametri che l'adapter sa costruire. Tutto il resto dell'endpoint
# `/query` — forzatura DNS, verifica dei takeover, scansione delle API,
# interrogazione di Shodan — resta irraggiungibile da qui.
PARAMETRI_AMMESSI = ("source", "domain", "limit")

# Le fonti che theHarvester espone senza chiave. Sono quelle su cui si puo'
# contare in una installazione appena fatta; le altre si attivano dalla
# configurazione degli strumenti, quando il cliente ha l'abbonamento.
FONTI_GRATUITE = ("certspotter", "crtsh", "duckduckgo", "otx", "rapiddns",
                  "subdomaincenter", "urlscan", "yahoo")

# Fonti che richiedono una chiave: elencarle serve a spiegare l'esito quando
# una e' richiesta ma non configurata, invece di lasciare un risultato vuoto.
FONTI_CON_CHIAVE = ("bevigil", "brave", "bufferoverun", "builtwith", "censys",
                    "criminalip", "dehashed", "dnsdumpster", "fofa", "fullhunt",
                    "github-code", "hunter", "hunterhow", "intelx", "leakix",
                    "leaklookup", "netlas", "onyphe", "projectdiscovery",
                    "rocketreach", "securityTrails", "shodan", "tomba",
                    "virustotal", "whoisxml", "zoomeye")

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


class TheHarvesterAdapter(BaseAdapter):
    """Scoperta di indirizzi e sottodomini tramite il servizio theHarvester."""

    key = "theharvester"
    coverage_areas = (CATEGORY, ScoreCategoryKey.ATTACK_SURFACE.value)

    # ------------------------------------------------------------------
    def _base_url(self) -> str | None:
        return self.context.connector_config.get("theharvester", {}).get("base_url")

    def _fonti(self) -> tuple[list[str], list[str]]:
        """Le fonti da interrogare, e quelle scartate perche' senza chiave.

        La configurazione puo' chiedere fonti a pagamento: quelle per cui non
        risulta una chiave vengono tolte e dichiarate, invece di produrre un
        risultato vuoto che sembrerebbe assenza di esposizione.
        """
        richieste = [str(f).strip() for f in (self.config.get("sources") or FONTI_GRATUITE)
                     if str(f).strip()]
        configurate = {str(c).strip() for c in (self.config.get("sources_con_chiave") or ())}
        usabili, scartate = [], []
        for fonte in richieste:
            if fonte in FONTI_CON_CHIAVE and fonte not in configurate:
                scartate.append(fonte)
            else:
                usabili.append(fonte)
        return usabili, scartate

    def check_available(self) -> tuple[bool, str]:
        """Il servizio risponde, e dichiara le fonti che sa interrogare.

        `/sources` e' l'endpoint piu' leggero che theHarvester espone, e dice
        se il servizio e' davvero quello atteso invece che un qualunque
        processo in ascolto su quella porta.
        """
        base = (self._base_url() or "").rstrip("/")
        if not base:
            return False, "servizio theHarvester non configurato (THEHARVESTER_URL)"
        try:
            with httpx.Client(timeout=10.0, follow_redirects=False) as client:
                risposta = get_da_servizio_configurato(client, f"{base}/sources", base=base)
            risposta.raise_for_status()
            fonti = risposta.json().get("sources")
        except Exception as errore:  # noqa: BLE001
            return False, f"servizio theHarvester non raggiungibile: {str(errore)[:160]}"
        if not fonti:
            return False, "il servizio non dichiara alcuna fonte"
        return True, ""

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        base = (self._base_url() or "").rstrip("/")
        if not base:
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED,
                error_message="servizio theHarvester non configurato (THEHARVESTER_URL)")

        domini = self.context.scope_guard.filter_targets(self.context.domains, "hostname")
        if not domini:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun dominio in perimetro")

        fonti, senza_chiave = self._fonti()
        if not fonti:
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED,
                error_message="nessuna fonte utilizzabile: "
                              f"{', '.join(senza_chiave)} richiedono una chiave non configurata")

        massimo = int(self.config.get("max_targets", 5))
        limite = int(self.config.get("limit", 200))
        timeout = int(self.config.get("timeout_seconds", self.default_timeout))

        indirizzi: dict[str, set[str]] = {}
        host: set[str] = set()
        grezzo: dict[str, Any] = {"fonti": fonti, "senza_chiave": senza_chiave, "domini": {}}
        falliti: dict[str, str] = {}
        interrogati = 0

        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            for dominio in domini[:massimo]:
                # Parametri da lista chiusa: niente forzatura DNS, niente
                # verifica dei takeover, niente scansione delle API.
                parametri = {"source": ",".join(fonti), "domain": dominio,
                             "limit": str(limite)}
                assert set(parametri) <= set(PARAMETRI_AMMESSI)
                try:
                    risposta = get_da_servizio_configurato(
                        client, f"{base}/query", base=base, parametri=parametri)
                    risposta.raise_for_status()
                    dati = risposta.json()
                except Exception as errore:  # noqa: BLE001 - l'esito va riportato, non alzato
                    falliti[dominio] = f"{type(errore).__name__}: {str(errore)[:160]}"
                    continue

                interrogati += 1
                trovate = [e for e in (dati.get("emails") or []) if _EMAIL.match(str(e).strip())]
                for indirizzo in trovate:
                    normalizzato = str(indirizzo).strip().lower()
                    if normalizzato.endswith(f"@{dominio}") or f".{dominio}" in normalizzato:
                        indirizzi.setdefault(normalizzato, set()).add(dominio)
                for nome in (dati.get("hosts") or []):
                    # Il formato e' «host:ip» oppure il solo nome.
                    pulito = str(nome).split(":", 1)[0].strip().lower().rstrip(".")
                    if pulito.endswith(f".{dominio}") or pulito == dominio:
                        host.add(pulito)

                grezzo["domini"][dominio] = {
                    # Nel grezzo gli indirizzi restano mascherati: il campo
                    # viene conservato, e un indirizzo in chiaro li' dentro
                    # sarebbe un dato personale senza ragione di esserci.
                    "emails": sorted({mask_email(str(e)) for e in trovate}),
                    "hosts": len(dati.get("hosts") or []),
                    "ips": len(dati.get("ips") or []),
                }

        assets = [
            DiscoveredAsset(
                asset_key=indirizzo, asset_type=AssetType.EMAIL_ADDRESS.value,
                display_name=mask_email(indirizzo), discovered_by=self.key,
                attributes={"masked": True, "sources": ["theharvester"],
                            "domains": sorted(domini_trovati)})
            for indirizzo, domini_trovati in sorted(indirizzi.items())
        ]
        assets += [
            DiscoveredAsset(
                asset_key=nome, asset_type=AssetType.SUBDOMAIN.value,
                display_name=nome, discovered_by=self.key,
                attributes={"sources": ["theharvester"]})
            for nome in sorted(host)
        ]

        # Un guasto su tutti i domini non e' un successo con zero risultati.
        if falliti and not interrogati:
            return AdapterResult(
                tool=self.key, status=AdapterStatus.FAILED, assets=[],
                target_count=len(domini[:massimo]),
                error_message="; ".join(f"{d}: {m}" for d, m in list(falliti.items())[:3]),
                raw_output=self.dump_json(grezzo))

        stato = AdapterStatus.PARTIAL if (falliti or senza_chiave) else AdapterStatus.SUCCESS
        motivi = []
        if falliti:
            motivi.append(f"{len(falliti)} domini non interrogati")
        if senza_chiave:
            motivi.append(f"fonti senza chiave escluse: {', '.join(senza_chiave)}")
        return AdapterResult(
            tool=self.key, status=stato, assets=assets,
            target_count=len(domini[:massimo]),
            error_message="; ".join(motivi) or None,
            raw_output=self.dump_json(grezzo),
            config_snapshot={"sources": fonti, "limit": limite,
                             "addresses": len(indirizzi), "hosts": len(host)})

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        posture = build_posture(self.context)
        assets: list[DiscoveredAsset] = []
        for dominio in self.context.domains:
            for locale in ("amministrazione", "commerciale"):
                indirizzo = f"{locale}@{dominio}"
                assets.append(DiscoveredAsset(
                    asset_key=indirizzo, asset_type=AssetType.EMAIL_ADDRESS.value,
                    display_name=mask_email(indirizzo), discovered_by=self.key,
                    attributes={"masked": True, "sources": ["theharvester"],
                                "domains": [dominio]}))
            if posture.weak:
                assets.append(DiscoveredAsset(
                    asset_key=f"portale.{dominio}", asset_type=AssetType.SUBDOMAIN.value,
                    display_name=f"portale.{dominio}", discovered_by=self.key,
                    attributes={"sources": ["theharvester"]}))
        return AdapterResult(
            tool=self.key, status=AdapterStatus.SUCCESS, assets=assets, was_mocked=True,
            tool_version="theHarvester (mock)", target_count=len(self.context.domains),
            config_snapshot={"sources": list(FONTI_GRATUITE)})

    # ------------------------------------------------------------------
    @staticmethod
    def dump(dati: Any) -> bytes:  # pragma: no cover - comodita' di prova
        return json.dumps(dati, ensure_ascii=False).encode("utf-8")
