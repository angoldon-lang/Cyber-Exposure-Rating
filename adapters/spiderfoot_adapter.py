"""Adapter SpiderFoot: OSINT aziendale via API HTTP dell'istanza SpiderFoot.

I moduli eseguibili sono limitati dall'allowlist per profilo definita in
config/tool_profiles.yaml: nessun modulo attivo nel profilo passivo.
"""
from __future__ import annotations

import html
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset, NormalizedEvidence
from adapters.esposizione_email import evidenza_violazione, separa_indirizzo_e_fonte
from adapters.http_sicuro import get_da_servizio_configurato
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
        base = self.base_url.rstrip("/")
        try:
            # SpiderFoot non e' un bersaglio: e' un servizio il cui indirizzo
            # lo scrive un amministratore. Il controllo anti-SSRF sui
            # bersagli lo rifiutava perche' gira su un indirizzo privato,
            # rendendolo inutilizzabile nella distribuzione tipica. Qui vale
            # la regola che serve: i redirect non escono dal servizio.
            with httpx.Client(timeout=10.0, follow_redirects=False) as client:
                response = get_da_servizio_configurato(client, f"{base}/ping", base=base)
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            # Il tipo dell'eccezione da solo non dice cosa fare: senza il
            # messaggio, «non raggiungibile» costringe a indovinare fra
            # indirizzo sbagliato, servizio spento e porta chiusa.
            dettaglio = str(exc).strip() or type(exc).__name__
            return False, f"istanza SpiderFoot non raggiungibile: {dettaglio[:160]}"
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
        problemi: list[str] = []
        timeout = int(self.config.get("timeout_seconds", self.default_timeout))
        # `Accept: application/json` non e' una cortesia: senza questa
        # intestazione `/startscan` risponde con un redirect 303 alla pagina
        # della scansione, e con essa risponde `["SUCCESS", <id>]`. E' la
        # differenza fra un'API e una pagina web.
        with httpx.Client(timeout=30.0, follow_redirects=False,
                          headers={"Accept": "application/json"}) as client:
            for target in targets[:5]:
                try:
                    start = client.post(f"{base}/startscan", data={
                        "scanname": f"defenix-{self.context.scan_id[:8]}-{target}",
                        "scantarget": target,
                        # `usecase` va inviato VUOTO, e serve entrambe le cose.
                        # Inviarlo: e' un parametro obbligatorio della firma
                        # CherryPy di `/startscan`, e senza di esso la
                        # richiesta riceve 404 (misurato).
                        # Vuoto: valeva `all`, e SpiderFoot ricade sul
                        # `usecase` quando `modulelist` e' vuoto -- in quel
                        # caso `all` avvia OGNI modulo, compresi gli attivi
                        # che il profilo passivo vieta. Con la stringa vuota
                        # quella ricaduta non puo' avvenire: SpiderFoot
                        # rifiuta la scansione invece di allargarla.
                        "usecase": "",
                        "modulelist": ",".join(f"module_{m}" for m in modules),
                        "typelist": "",
                    })
                    self._verifica_risposta(start, "avvio della scansione")
                    scan_id = self._extract_scan_id(start)
                    if not scan_id:
                        problemi.append(f"{target}: avvio senza identificativo di scansione")
                        continue
                    trovati, problema = self._await_results(client, base, scan_id, timeout)
                    events.extend(trovati)
                    if problema:
                        problemi.append(f"{target}: {problema}")
                except Exception as exc:  # noqa: BLE001
                    # Il tipo dell'eccezione da solo non dice cosa fare. Era
                    # «errore SpiderFoot: HTTPStatusError», e il codice di
                    # stato -- la sola informazione utile -- restava fuori.
                    problemi.append(f"{target}: {self._descrivi(exc)}")

        evidences, assets, credenziali = self._map_events(events)
        # Un guasto su tutti i bersagli non e' un successo senza risultati: e'
        # la classe di difetto che questo progetto ha gia' pagato due volte.
        if problemi and not events:
            stato = AdapterStatus.FAILED
        elif problemi:
            stato = AdapterStatus.PARTIAL
        else:
            stato = AdapterStatus.SUCCESS
        return AdapterResult(
            tool=self.key, status=stato, evidences=evidences, assets=assets,
            target_count=len(targets),
            error_message="; ".join(problemi[:3]) or None,
            coverage_impact=(self.coverage_weight if stato is AdapterStatus.FAILED
                             else self.coverage_weight * 0.5 if problemi else 0.0),
            raw_output=self.dump_json(self._senza_credenziali(events)),
            config_snapshot={"modules": modules,
                             "credentials_seen_not_stored": credenziali})

    @staticmethod
    def _descrivi(exc: Exception) -> str:
        """Descrizione utilizzabile di un guasto HTTP: stato, indirizzo, corpo."""
        if isinstance(exc, httpx.HTTPStatusError):
            corpo = " ".join(exc.response.text.split())[:120]
            return (f"HTTP {exc.response.status_code} su "
                    f"{exc.request.url.path}: {corpo or 'corpo vuoto'}")
        dettaglio = " ".join(str(exc).split())[:120]
        return f"{type(exc).__name__}: {dettaglio}" if dettaglio else type(exc).__name__

    @staticmethod
    def _verifica_risposta(risposta: httpx.Response, cosa: str) -> None:
        """Solleva se la risposta non e' utilizzabile.

        Non si usa `raise_for_status()`: da httpx 0.24 solleva anche sui 3xx,
        e `/startscan` risponde 303 quando il client non chiede JSON. Era
        esattamente il guasto -- «errore SpiderFoot: HTTPStatusError» -- su una
        scansione che SpiderFoot aveva avviato correttamente ogni volta, e che
        l'adapter buttava via insieme al redirect che ne portava l'id.
        """
        if risposta.is_success or risposta.is_redirect:
            return
        corpo = " ".join(risposta.text.split())[:120]
        raise httpx.HTTPStatusError(
            f"{cosa}: HTTP {risposta.status_code} {corpo}".strip(),
            request=risposta.request, response=risposta)

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
        """Identificativo della scansione avviata.

        SpiderFoot segnala i propri errori con stato 200 e un involucro
        `["ERROR", "<motivo>"]`. Leggendo il secondo elemento senza guardare
        il primo, il motivo dell'errore diventava l'identificativo della
        scansione, e l'adapter si metteva a interrogare uno scan inesistente
        finche' il tempo non finiva.
        """
        try:
            payload = response.json()
        except ValueError:
            # Senza `Accept: application/json` la risposta e' un redirect e
            # l'identificativo sta nell'indirizzo di destinazione.
            location = str(response.headers.get("location", ""))
            return location.rsplit("id=", 1)[-1] or None
        if isinstance(payload, list) and len(payload) > 1:
            if str(payload[0]).upper() == "ERROR":
                raise ValueError(f"SpiderFoot ha rifiutato la scansione: {payload[1]}")
            return str(payload[1])
        return str(payload) if payload else None

    # Stati terminali di SpiderFoot. `CREATED` e `RUNNING` non lo sono: una
    # scansione che resta la' non ha prodotto niente, e dirlo «riuscita con
    # zero risultati» significa concludere che l'organizzazione non e' esposta.
    STATI_RIUSCITI = frozenset({"FINISHED"})
    STATI_FALLITI = frozenset({"ERROR-FAILED", "ABORTED", "ABORT-REQUESTED"})

    def _await_results(self, client: httpx.Client, base: str, scan_id: str,
                       timeout: int) -> tuple[list[dict[str, Any]], str | None]:
        """Attende la fine della scansione e ne raccoglie gli eventi.

        Restituisce anche il motivo quando qualcosa non e' andato: senza, una
        scansione mai partita e una conclusa senza trovare nulla producono lo
        stesso esito, e sono l'opposto l'una dell'altra.
        """
        deadline = time.monotonic() + timeout
        stato = "?"
        while time.monotonic() < deadline:
            risposta = client.get(f"{base}/scanstatus", params={"id": scan_id})
            stato = self._stato_della_scansione(risposta)
            if stato in self.STATI_RIUSCITI or stato in self.STATI_FALLITI:
                break
            time.sleep(POLL_INTERVAL_SECONDS)

        eventi = self._eventi(client, base, scan_id)
        if stato in self.STATI_FALLITI:
            return eventi, f"la scansione SpiderFoot e' terminata in stato {stato}"
        if stato not in self.STATI_RIUSCITI:
            # Caso osservato: senza raggiungere publicsuffix.org, SpiderFoot
            # non riesce a inizializzare e la scansione resta in `CREATED` per
            # sempre, senza errore sull'API.
            return eventi, (f"la scansione SpiderFoot era ancora in stato {stato} "
                            f"dopo {timeout}s: nessun risultato da considerare")
        return eventi, None

    @staticmethod
    def _stato_della_scansione(risposta: httpx.Response) -> str:
        """Lo stato sta in sesta posizione della risposta di `/scanstatus`."""
        if not risposta.is_success:
            return "?"
        try:
            righe = risposta.json()
        except ValueError:
            return "?"
        if isinstance(righe, list) and len(righe) > 5:
            return str(righe[5]).upper()
        return "?"

    def _eventi(self, client: httpx.Client, base: str,
                scan_id: str) -> list[dict[str, Any]]:
        """Eventi della scansione, da `/scaneventresults`.

        NON da `/scaneventresultexport`, che era l'endpoint usato fin qui:
        quello produce CSV (o xlsx) e non ha un formato JSON. La chiamata
        riusciva, `.json()` sollevava, l'eccezione era gia' intercettata, e
        l'adapter concludeva ogni volta con zero eventi e stato «riuscito».
        SpiderFoot non ha mai prodotto un rilievo da quando e' integrato.
        """
        risposta = client.get(f"{base}/scaneventresults",
                              params={"id": scan_id, "eventType": "ALL"})
        if not risposta.is_success:
            return []
        try:
            righe = risposta.json()
        except ValueError:
            return []
        if not isinstance(righe, list):
            return []
        return [tradotto for riga in righe
                if (tradotto := self._riga_in_evento(riga)) is not None]

    # Ordine delle colonne di `/scaneventresults`, ricavato dalla query di
    # `SpiderFootDb.scanResultEvent` e dalla proiezione che l'endpoint ne fa:
    # [0] data/ora, [1] VALORE, [2] origine, [3] modulo, [4] confidenza,
    # [5] visibilita', [6] rischio, [7] impronta, [8] falso positivo,
    # [9] falso positivo del padre, [10] TIPO.
    # Il tipo e' in fondo, non in seconda posizione: leggerlo dall'indice 1
    # avrebbe preso il valore al suo posto.
    _COLONNA_VALORE = 1
    _COLONNA_MODULO = 3
    _COLONNA_FALSO_POSITIVO = 8
    _COLONNA_TIPO = 10

    @classmethod
    def _riga_in_evento(cls, riga: Any) -> dict[str, Any] | None:
        """Porta una riga di SpiderFoot nella forma che `_map_events` legge.

        La conversione sta qui, al confine: `_map_events` continua a ragionare
        su `type` e `data`, e non deve sapere in quale colonna stiano.
        """
        if isinstance(riga, dict):
            return riga
        if not isinstance(riga, (list, tuple)) or len(riga) <= cls._COLONNA_TIPO:
            return None
        # I falsi positivi marcati da un analista di SpiderFoot non vanno
        # ripresentati come rilievi.
        if str(riga[cls._COLONNA_FALSO_POSITIVO]) in {"1", "True", "true"}:
            return None
        # Il valore e il tipo arrivano con le entita' HTML dell'interfaccia.
        return {
            "type": html.unescape(str(riga[cls._COLONNA_TIPO] or "")).strip(),
            "data": html.unescape(str(riga[cls._COLONNA_VALORE] or "")).strip(),
            "module": html.unescape(str(riga[cls._COLONNA_MODULO] or "")).strip(),
        }

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
            # sovrapposizione con XposedOrNot e' cio' che rende verificabile la
            # deduplicazione fra due fonti sullo stesso fatto. Questa fonte non
            # conosce anno ne' categorie: produce la stessa evidenza con la
            # severita' che quei dati mancanti consentono.
            for esposizione in posture.email_exposures:
                evidences.append(evidenza_violazione(
                    tool=self.key, indirizzo=str(esposizione["address"]),
                    violazione=str(esposizione["breach"]),
                    fonte_dati="SpiderFoot (moduli su violazioni di dati)"))
            for mention in posture.darkweb_mentions:
                evidences.append(self._darkweb_evidence(mention["source"]))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             assets=assets, tool_version="SpiderFoot 4.0 (mock)", was_mocked=True,
                             target_count=len(self.context.domains), raw_output=self.dump_json(raw),
                             config_snapshot={"modules": self.allowed_modules()})
