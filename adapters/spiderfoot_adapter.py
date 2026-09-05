"""Adapter SpiderFoot: OSINT aziendale via API HTTP dell'istanza SpiderFoot.

I moduli eseguibili sono limitati dall'allowlist per profilo definita in
config/tool_profiles.yaml: nessun modulo attivo nel profilo passivo.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset, NormalizedEvidence
from adapters.esposizione_email import evidenza_violazione, separa_indirizzo_e_fonte
from adapters.http_sicuro import get_seguendo_redirect
from adapters.synthetic import build_posture
from app.core.redaction import mask_email
from app.models.enums import AssetType, ConfidenceClass, ScoreCategoryKey, Severity

POLL_INTERVAL_SECONDS = 10

# Tipi di evento SpiderFoot mappati sugli asset del modello dati.
EVENT_TO_ASSET: dict[str, str] = {
    "INTERNET_NAME": AssetType.SUBDOMAIN.value,
    "DOMAIN_NAME": AssetType.DOMAIN.value,
    "IP_ADDRESS": AssetType.IP_ADDRESS.value,
    "NETBLOCK_OWNER": AssetType.NETWORK_RANGE.value,
    "BGP_AS_OWNER": AssetType.ASN.value,
    "EMAILADDR": AssetType.EMAIL_ADDRESS.value,
    "EMAILADDR_GENERIC": AssetType.EMAIL_ADDRESS.value,
    "EMAILADDR_COMPROMISED": AssetType.EMAIL_ADDRESS.value,
}

# Eventi che segnalano una menzione su fonte non indicizzata.
EVENTI_DARKWEB = frozenset({"DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT"})

# Eventi che segnalano la presenza dell'indirizzo in materiale trafugato.
EVENTI_COMPROMISSIONE = frozenset({"EMAILADDR_COMPROMISED",
                                   "ACCOUNT_EXTERNAL_OWNED_COMPROMISED",
                                   "ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED"})

# Eventi che pubblicano materiale trafugato su siti di leak/paste.
EVENTI_LEAK = frozenset({"LEAKSITE_URL", "LEAKSITE_CONTENT"})

# Eventi il cui contenuto e' una credenziale: si conta l'occorrenza, il valore
# non entra mai ne' nel database ne' nel report. Vale sia per la password in
# chiaro sia per il suo hash: un hash e' una credenziale, non un metadato.
EVENTI_CREDENZIALE = frozenset({"PASSWORD_COMPROMISED", "HASH_COMPROMISED"})


class SpiderFootAdapter(BaseAdapter):
    key = "spiderfoot"
    display_name = "SpiderFoot"
    is_passive = True
    coverage_areas = (ScoreCategoryKey.ATTACK_SURFACE.value, ScoreCategoryKey.DARKWEB_BREACH.value)
    default_timeout = 900

    @property
    def base_url(self) -> str | None:
        return self.context.connector_config.get("spiderfoot", {}).get("base_url")

    def check_available(self) -> tuple[bool, str]:
        if not self.base_url:
            return False, "istanza SpiderFoot non configurata (SPIDERFOOT_URL)"
        try:
            # Come per le altre sonde: i redirect si seguono con validazione.
            with httpx.Client(timeout=10.0, follow_redirects=False) as client:
                response = get_seguendo_redirect(
                    client, f"{self.base_url.rstrip('/')}/ping")
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            return False, f"istanza SpiderFoot non raggiungibile: {type(exc).__name__}"
        return True, "disponibile"

    def allowed_modules(self) -> list[str]:
        modules = (self.config.get("modules") or {}).get(self.context.profile, [])
        forbidden = set(self.config.get("forbidden_modules") or [])
        return [module for module in modules if module not in forbidden]

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        base = (self.base_url or "").rstrip("/")
        modules = self.allowed_modules()
        if not modules:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message=f"nessun modulo ammesso per il profilo {self.context.profile}",
                                 coverage_impact=self.coverage_weight)
        targets = self.context.scope_guard.filter_targets(self.context.domains, "hostname")
        if not targets:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun dominio in perimetro",
                                 coverage_impact=self.coverage_weight)

        events: list[dict[str, Any]] = []
        timeout = int(self.config.get("timeout_seconds", self.default_timeout))
        with httpx.Client(timeout=30.0, follow_redirects=False) as client:
            for target in targets[:5]:
                try:
                    start = client.post(f"{base}/startscan", data={
                        "scanname": f"defenix-{self.context.scan_id[:8]}-{target}",
                        "scantarget": target,
                        "usecase": "all",
                        "modulelist": ",".join(f"module_{m}" for m in modules),
                        "typelist": "",
                    })
                    start.raise_for_status()
                    scan_id = self._extract_scan_id(start)
                    if not scan_id:
                        continue
                    events.extend(self._await_results(client, base, scan_id, timeout))
                except Exception as exc:  # noqa: BLE001
                    return AdapterResult(
                        tool=self.key, status=AdapterStatus.PARTIAL if events else AdapterStatus.FAILED,
                        error_message=f"errore SpiderFoot: {type(exc).__name__}",
                        coverage_impact=self.coverage_weight * 0.5,
                        raw_output=self.dump_json(self._senza_credenziali(events)))

        evidences, assets, credenziali = self._map_events(events)
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             assets=assets, target_count=len(targets),
                             raw_output=self.dump_json(self._senza_credenziali(events)),
                             config_snapshot={"modules": modules,
                                              "credentials_seen_not_stored": credenziali})

    @staticmethod
    def _senza_credenziali(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Rimuove dall'output grezzo gli eventi il cui contenuto e' una credenziale.

        L'output grezzo viene archiviato per la ricostruibilita' della
        scansione: se le password ci finissero dentro, non memorizzarle nel
        modello dati non servirebbe a nulla.
        """
        return [e for e in events
                if str(e.get("type") or "") not in EVENTI_CREDENZIALE]

    @staticmethod
    def _extract_scan_id(response: httpx.Response) -> str | None:
        try:
            payload = response.json()
        except ValueError:
            location = str(response.headers.get("location", ""))
            return location.rsplit("id=", 1)[-1] or None
        if isinstance(payload, list) and len(payload) > 1:
            return str(payload[1])
        return str(payload) if payload else None

    def _await_results(self, client: httpx.Client, base: str, scan_id: str,
                       timeout: int) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = client.get(f"{base}/scanopts", params={"id": scan_id})
            if status.status_code == 200 and "FINISHED" in status.text.upper():
                break
            time.sleep(POLL_INTERVAL_SECONDS)
        data = client.get(f"{base}/scaneventresultexport", params={"id": scan_id, "type": "ALL"})
        try:
            payload = data.json()
        except ValueError:
            return []
        return payload if isinstance(payload, list) else []

    def _map_events(self, events: list[dict[str, Any]]) -> tuple[list[NormalizedEvidence],
                                                                  list[DiscoveredAsset], int]:
        """Traduce gli eventi SpiderFoot in asset ed evidenze.

        La deduplicazione e' per coppia (tipo, valore) e non per solo valore:
        lo stesso indirizzo puo' arrivare come `EMAILADDR` da un modulo di
        raccolta e come `EMAILADDR_COMPROMISED` da un modulo di violazioni, e
        sono due informazioni diverse. Deduplicando sul valore la seconda
        andava persa, che e' esattamente quella che interessa al report.
        """
        assets: list[DiscoveredAsset] = []
        evidences: list[NormalizedEvidence] = []
        visti: set[tuple[str, str]] = set()
        compromessi: dict[str, set[str]] = {}
        leak: list[str] = []
        credenziali = 0

        for event in events:
            event_type = str(event.get("type") or (event[1] if isinstance(event, list) else ""))
            # Il valore non viene abbassato di maiuscole: il nome della
            # violazione fa parte del dato («LinkedIn», non «linkedin») e
            # finisce nel report. La normalizzazione avviene dove serve —
            # sull'indirizzo e sulla chiave dell'asset — mentre il confronto
            # per la deduplicazione resta insensibile alle maiuscole.
            value = str(event.get("data") or "").strip()
            chiave = (event_type, value.lower())
            if not value or chiave in visti:
                continue
            visti.add(chiave)

            if event_type in EVENTI_CREDENZIALE:
                # Il valore e' una credenziale: si conta l'occorrenza e si
                # scarta subito. Non entra in `raw_output`, non entra nel
                # database, non arriva al modello AI.
                credenziali += 1
                continue

            asset_type = EVENT_TO_ASSET.get(event_type)
            if asset_type == AssetType.EMAIL_ADDRESS.value:
                # Gli eventi sugli indirizzi portano la violazione fra
                # parentesi quadre: «mario@azienda.it [LinkedIn]». Indirizzo e
                # violazione vanno separati una volta sola, perche' servono
                # entrambi: il primo come asset, la coppia come evidenza.
                indirizzo, violazione = separa_indirizzo_e_fonte(value)
                if not self._email_in_perimetro(indirizzo):
                    continue
                assets.append(DiscoveredAsset(
                    asset_key=indirizzo, asset_type=asset_type,
                    display_name=mask_email(indirizzo), discovered_by=self.key,
                    attributes={"spiderfoot_event": event_type, "masked": True}))
                if event_type in EVENTI_COMPROMISSIONE:
                    compromessi.setdefault(indirizzo, set()).add(
                        violazione or "violazione non identificata")
                continue
            if asset_type:
                assets.append(DiscoveredAsset(
                    asset_key=value, asset_type=asset_type, display_name=value,
                    discovered_by=self.key, attributes={"spiderfoot_event": event_type}))

            if event_type in EVENTI_DARKWEB:
                evidences.append(self._darkweb_evidence(value))
            elif event_type in EVENTI_COMPROMISSIONE:
                # Compromissioni non legate a un indirizzo (utenze su servizi
                # esterni): il valore e' gia' l'identificativo dell'utenza.
                indirizzo, violazione = separa_indirizzo_e_fonte(value)
                if self._email_in_perimetro(indirizzo):
                    compromessi.setdefault(indirizzo, set()).add(
                        violazione or "violazione non identificata")
            elif event_type in EVENTI_LEAK:
                leak.append(value)

        evidences.extend(
            evidenza_violazione(tool=self.key, indirizzo=indirizzo, violazione=violazione,
                                fonte_dati="SpiderFoot (moduli su violazioni di dati)")
            for indirizzo, violazioni in sorted(compromessi.items())
            for violazione in sorted(violazioni))
        if leak:
            evidences.append(self._evidenza_leak(leak, credenziali))
        return evidences, assets, credenziali

    def _email_in_perimetro(self, indirizzo: str) -> bool:
        """Vero se l'indirizzo appartiene a un dominio dell'organizzazione.

        SpiderFoot raccoglie anche indirizzi di terzi (fornitori, contatti
        citati sul sito). Sono dati personali che non riguardano il perimetro
        valutato e non devono ne' finire nel database ne' comparire nel
        report.
        """
        if "@" not in indirizzo:
            return False
        dominio = indirizzo.rsplit("@", 1)[1]
        domini = {d.lower() for d in self.context.domains}
        return dominio in domini or any(dominio.endswith(f".{d}") for d in domini)

    def _evidenza_leak(self, riferimenti: list[str], credenziali: int) -> NormalizedEvidence:
        dominio = self.context.domains[0] if self.context.domains else "n/d"
        return NormalizedEvidence(
            tool=self.key, target=dominio, asset_key=dominio,
            finding_type="organisation_data_on_leak_site",
            title=f"Materiale riconducibile all'organizzazione su siti di leak ({len(riferimenti)})",
            description=(
                "Contenuti riconducibili all'organizzazione sono stati pubblicati su siti di "
                "leak o di paste. Il contenuto non viene scaricato ne' conservato: sono "
                "registrati soltanto il numero di pubblicazioni e la fonte. Una verifica "
                "manuale da parte di un analista e' necessaria per stabilire la portata."),
            detail=f"{len(riferimenti)} pubblicazioni rilevate",
            category=ScoreCategoryKey.DARKWEB_BREACH.value,
            severity=Severity.HIGH.value if credenziali else Severity.MEDIUM.value,
            confidence_class=ConfidenceClass.PROBABLE.value,
            data_source="SpiderFoot (moduli su siti di leak)", observed_at=datetime.now(UTC),
            attributes={"publications": len(riferimenti),
                        "credentials_seen_not_stored": credenziali})

    def _darkweb_evidence(self, reference: str) -> NormalizedEvidence:
        domain = self.context.domains[0] if self.context.domains else "n/d"
        return NormalizedEvidence(
            tool=self.key, target=domain, asset_key=domain, finding_type="darkweb_mention",
            title="Menzione dell'organizzazione su una fonte non indicizzata",
            description=("E' stata rilevata una menzione riconducibile all'organizzazione su una "
                         "fonte non indicizzata. La menzione non implica di per se' una "
                         "compromissione: richiede verifica da parte di un analista."),
            detail=reference[:200],
            category=ScoreCategoryKey.DARKWEB_BREACH.value,
            severity=Severity.MEDIUM.value, confidence_class=ConfidenceClass.PROBABLE.value,
            data_source="SpiderFoot (moduli Tor/Ahmia)", observed_at=datetime.now(UTC))

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        assets: list[DiscoveredAsset] = []
        evidences: list[NormalizedEvidence] = []
        raw: dict[str, Any] = {}
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            raw[domain] = {"subdomains": len(posture.subdomains),
                           "darkweb_mentions": len(posture.darkweb_mentions)}
            for host in posture.subdomains:
                assets.append(DiscoveredAsset(
                    asset_key=host, asset_type=AssetType.SUBDOMAIN.value, display_name=host,
                    discovered_by=self.key, attributes={"spiderfoot_event": "INTERNET_NAME"}))
            for index in range(3):
                address = f"{['mario.rossi', 'info', 'amministrazione'][index]}@{domain}"
                assets.append(DiscoveredAsset(
                    asset_key=address, asset_type=AssetType.EMAIL_ADDRESS.value,
                    display_name=mask_email(address), discovered_by=self.key,
                    attributes={"spiderfoot_event": "EMAILADDR", "masked": True}))
                # In mock mode le fonti devono raccontare la stessa azienda: la
                # sovrapposizione con XposedOrNot e' cio' che rende verificabile
                # la deduplicazione fra due fonti sullo stesso fatto.
                for violazione in posture.breaches[: max(0, len(posture.breaches) - index)]:
                    evidences.append(evidenza_violazione(
                        tool=self.key, indirizzo=address, violazione=str(violazione["name"]),
                        fonte_dati="SpiderFoot (moduli su violazioni di dati)"))
            for mention in posture.darkweb_mentions:
                evidences.append(self._darkweb_evidence(mention["source"]))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             assets=assets, tool_version="SpiderFoot 4.0 (mock)", was_mocked=True,
                             target_count=len(self.context.domains), raw_output=self.dump_json(raw),
                             config_snapshot={"modules": self.allowed_modules()})
