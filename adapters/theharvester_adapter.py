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

* theHarvester dichiara `requires-python >= 3.14`, mentre i worker girano su
  3.11;
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
L'API sa fare anche forzatura DNS, verifica dei takeover e interrogazione di
Shodan: sono attivita' **attive** sul bersaglio, fuori da cio' che un profilo
passivo puo' fare e, nel caso del takeover, vicine a un tentativo di
appropriazione. Il corpo della richiesta che l'adapter costruisce contiene
soltanto bersaglio, fonti e limite, e il modello della richiesta ha
`extra="forbid"`: un campo in piu' non verrebbe ignorato, verrebbe rifiutato.
Quelle azioni restano irraggiungibili da qui perche' non le nominiamo, e la
configurazione non ha modo di farle comparire.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset
from adapters.http_sicuro import get_da_servizio_configurato
from adapters.synthetic import build_posture
from app.core.redaction import mask_email
from app.models.enums import AssetType, ScoreCategoryKey

CATEGORY = ScoreCategoryKey.DARKWEB_BREACH.value

# L'API di theHarvester e' cambiata, e con essa questo adapter.
#
# Il `restfulHarvest` sincrono per cui era scritto non esiste piu': gli entry
# point oggi sono `theHarvester`, `harvestview` e `harvest-report`, e l'API e'
# a lavori asincroni sotto `/api/v1`, con autenticazione obbligatoria.
# Misurato su un'istanza avviata, non dedotto:
#
#   GET  /api/v1/sources        -> {"sources": [{name, ready, capabilities,
#                                                credentials, activity}, ...]}
#   POST /api/v1/runs           -> 201 {"run_id": ..., "status": "queued", ...}
#   GET  /api/v1/runs/{run_id}  -> {"status", "results", "result_count",
#                                   "source_executions", "error", ...}
#
# Ogni risultato e' `{"type": ..., "value": ..., "sources": [...]}`, dove il
# tipo esce da un elenco chiuso: hostname, email, ip, url, asn, breach,
# person. A noi servono i primi due.
PERCORSO_API = "/api/v1"
TIPO_EMAIL = "email"
TIPO_HOSTNAME = "hostname"

# Stati terminali di un lavoro. `queued` e `running` non lo sono.
STATI_CONCLUSI = frozenset({"completed", "failed", "cancelled", "canceled"})
ATTESA_FRA_CONTROLLI = 5.0

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


class TheHarvesterAdapter(BaseAdapter):
    """Scoperta di indirizzi e sottodomini tramite il servizio theHarvester."""

    key = "theharvester"
    display_name = "theHarvester"
    coverage_areas = (CATEGORY, ScoreCategoryKey.ATTACK_SURFACE.value)

    # ------------------------------------------------------------------
    def _base_url(self) -> str | None:
        return self.context.connector_config.get("theharvester", {}).get("base_url")

    def _intestazioni(self) -> dict[str, str]:
        """L'API rifiuta ogni richiesta senza chiave, con 503 se il servizio
        non ne ha una configurata e 401 se la chiave non coincide. Non e'
        opzionale: e' un motore OSINT raggiungibile sulla rete."""
        chiave = self.context.connector_config.get("theharvester", {}).get("api_key")
        return {"X-API-Key": str(chiave)} if chiave else {}

    def _fonti(self, dichiarate: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
        """Le fonti da interrogare, e quelle scartate perche' non pronte.

        Non piu' da un elenco scritto a mano qui: il servizio dichiara per
        ogni fonte un campo `ready`, che e' falso quando le manca una
        credenziale. Mantenere due liste a mano significava che ogni fonte
        aggiunta o diventata a pagamento a monte ci trovava disallineati --
        e una fonte richiesta e non disponibile produceva un risultato vuoto,
        che somiglia all'assenza di esposizione.
        """
        pronte = {str(f.get("name")): bool(f.get("ready")) for f in dichiarate}
        richieste = [str(f).strip() for f in (self.config.get("sources") or ())
                     if str(f).strip()]
        if not richieste:
            # Senza richiesta esplicita si usano tutte quelle pronte: sono
            # gratuite per definizione, e il servizio sa quali sono.
            return sorted(n for n, ok in pronte.items() if ok), []
        usabili = [f for f in richieste if pronte.get(f)]
        scartate = [f for f in richieste if not pronte.get(f)]
        return usabili, scartate

    def check_available(self) -> tuple[bool, str]:
        """Il servizio risponde, e dichiara le fonti che sa interrogare.

        `/api/v1/sources` e' l'endpoint piu' leggero, e dice se dall'altra
        parte c'e' davvero theHarvester invece di un qualunque processo in
        ascolto su quella porta. Serve la chiave: senza, l'API risponde 503
        («non configurata») o 401, e distinguerli aiuta -- il primo e' un
        servizio senza chiave, il secondo una chiave sbagliata.
        """
        base = (self._base_url() or "").rstrip("/")
        if not base:
            return False, "servizio theHarvester non configurato (THEHARVESTER_URL)"
        intestazioni = self._intestazioni()
        if not intestazioni:
            return False, ("chiave API di theHarvester non configurata "
                           "(THEHARVESTER_API_KEY): l'API rifiuta ogni richiesta")
        try:
            with httpx.Client(timeout=10.0, follow_redirects=False) as client:
                risposta = get_da_servizio_configurato(
                    client, f"{base}{PERCORSO_API}/sources", base=base,
                    intestazioni=intestazioni)
            if risposta.status_code == 401:
                return False, ("chiave API rifiutata dal servizio theHarvester: "
                               "THEHARVESTER_API_KEY non coincide con quella del "
                               "contenitore")
            if risposta.status_code == 503:
                return False, ("il servizio theHarvester gira senza chiave "
                               "configurata: va avviato con THEHARVESTER_API_KEY")
            risposta.raise_for_status()
            fonti = risposta.json().get("sources")
        except Exception as errore:  # noqa: BLE001
            return False, f"servizio theHarvester non raggiungibile: {str(errore)[:160]}"
        if not fonti:
            return False, "il servizio non dichiara alcuna fonte"
        pronte = [f for f in fonti if f.get("ready")]
        if not pronte:
            return False, (f"nessuna delle {len(fonti)} fonti e' utilizzabile: "
                           "tutte richiedono una credenziale non configurata")
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

        intestazioni = self._intestazioni()
        try:
            with httpx.Client(timeout=15.0, follow_redirects=False) as client:
                elenco = get_da_servizio_configurato(
                    client, f"{base}{PERCORSO_API}/sources", base=base,
                    intestazioni=intestazioni)
                elenco.raise_for_status()
                dichiarate = elenco.json().get("sources") or []
        except Exception as errore:  # noqa: BLE001
            return AdapterResult(
                tool=self.key, status=AdapterStatus.FAILED,
                error_message=f"elenco delle fonti non ottenuto: {str(errore)[:160]}",
                coverage_impact=self.coverage_weight)

        fonti, senza_chiave = self._fonti(dichiarate)
        if not fonti:
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED,
                error_message="nessuna fonte utilizzabile: "
                              f"{', '.join(senza_chiave)} richiedono una credenziale "
                              "che il servizio non ha",
                coverage_impact=self.coverage_weight)

        massimo = int(self.config.get("max_targets", 5))
        limite = int(self.config.get("limit", 200))
        timeout = int(self.config.get("timeout_seconds", self.default_timeout))

        indirizzi: dict[str, set[str]] = {}
        host: set[str] = set()
        grezzo: dict[str, Any] = {"fonti": fonti, "senza_chiave": senza_chiave,
                                  "domini": {}}
        falliti: dict[str, str] = {}
        interrogati = 0

        with httpx.Client(timeout=min(60.0, float(timeout)), follow_redirects=False,
                          headers=intestazioni) as client:
            for dominio in domini[:massimo]:
                try:
                    lavoro = self._esegui_lavoro(client, base, dominio, fonti,
                                                 limite, timeout)
                except Exception as errore:  # noqa: BLE001 - l'esito va riportato
                    falliti[dominio] = f"{type(errore).__name__}: {str(errore)[:160]}"
                    continue

                interrogati += 1
                risultati = lavoro.get("results") or []
                trovate: set[str] = set()
                for voce in risultati:
                    if not isinstance(voce, dict):
                        continue
                    tipo = str(voce.get("type") or "")
                    valore = str(voce.get("value") or "").strip()
                    if not valore:
                        continue
                    if tipo == TIPO_EMAIL and _EMAIL.match(valore):
                        normalizzato = valore.lower()
                        parte = normalizzato.rsplit("@", 1)[-1].rstrip(".")
                        if parte == dominio or parte.endswith(f".{dominio}"):
                            indirizzi.setdefault(normalizzato, set()).add(dominio)
                            trovate.add(normalizzato)
                    elif tipo == TIPO_HOSTNAME:
                        pulito = valore.split(":", 1)[0].lower().rstrip(".")
                        if pulito.endswith(f".{dominio}") or pulito == dominio:
                            host.add(pulito)

                # Il servizio riporta l'esito di OGNI fonte: una conclusa con
                # tutte le fonti cadute non e' una conclusa senza risultati, e
                # il suo `status` dice «completed» in entrambi i casi.
                esecuzioni = lavoro.get("source_executions") or []
                riuscite = [e for e in esecuzioni if str(e.get("status")) == "completed"]
                if esecuzioni and not riuscite:
                    motivi = sorted({str(e.get("stop_reason") or e.get("status"))
                                     for e in esecuzioni})
                    falliti[dominio] = ("tutte le fonti hanno fallito: "
                                        + ", ".join(motivi[:3]))
                    interrogati -= 1

                grezzo["domini"][dominio] = {
                    # Nel grezzo gli indirizzi restano mascherati: il campo
                    # viene conservato, e un indirizzo in chiaro li' dentro
                    # sarebbe un dato personale senza ragione di esserci.
                    "emails": sorted(mask_email(e) for e in trovate),
                    "risultati": len(risultati),
                    "fonti_riuscite": len(riuscite),
                    "fonti_interrogate": len(esecuzioni),
                    "stato": str(lavoro.get("status") or "?"),
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
        if falliti and interrogati <= 0:
            return AdapterResult(
                tool=self.key, status=AdapterStatus.FAILED, assets=[],
                target_count=len(domini[:massimo]),
                error_message="; ".join(f"{d}: {m}" for d, m in list(falliti.items())[:3]),
                coverage_impact=self.coverage_weight,
                raw_output=self.dump_json(grezzo))

        stato = AdapterStatus.PARTIAL if (falliti or senza_chiave) else AdapterStatus.SUCCESS
        motivi = []
        if falliti:
            motivi.append("; ".join(f"{d}: {m}" for d, m in list(falliti.items())[:2]))
        if senza_chiave:
            motivi.append(f"fonti non disponibili: {', '.join(senza_chiave[:5])}")
        return AdapterResult(
            tool=self.key, status=stato, assets=assets,
            target_count=len(domini[:massimo]),
            error_message="; ".join(motivi) or None,
            coverage_impact=self.coverage_weight * 0.5 if falliti else 0.0,
            raw_output=self.dump_json(grezzo),
            config_snapshot={"sources": fonti, "limit": limite,
                             "addresses": len(indirizzi), "hosts": len(host)})

    def _esegui_lavoro(self, client: httpx.Client, base: str, dominio: str,
                       fonti: list[str], limite: int, timeout: int) -> dict[str, Any]:
        """Avvia un lavoro e ne attende la conclusione.

        L'API non risponde con i risultati: accetta il lavoro (201) e li
        mette a disposizione quando ha finito. Il corpo contiene SOLO i tre
        campi che servono -- bersaglio, fonti, limite -- e il modello della
        richiesta ha `extra='forbid'`, quindi un campo in piu' verrebbe
        rifiutato: le azioni attive dell'API (forzatura DNS, verifica dei
        takeover, Shodan) restano irraggiungibili da qui perche' non le
        nominiamo.
        """
        avvio = client.post(f"{base}{PERCORSO_API}/runs",
                            json={"target": dominio, "sources": fonti,
                                  "limit": limite})
        if avvio.status_code not in (200, 201):
            corpo = " ".join(avvio.text.split())[:120]
            raise RuntimeError(f"avvio rifiutato: HTTP {avvio.status_code} {corpo}")
        identificativo = str((avvio.json() or {}).get("run_id") or "")
        if not identificativo:
            raise RuntimeError("avvio senza identificativo del lavoro")

        scadenza = time.monotonic() + timeout
        lavoro: dict[str, Any] = {}
        while time.monotonic() < scadenza:
            risposta = client.get(f"{base}{PERCORSO_API}/runs/{identificativo}")
            risposta.raise_for_status()
            lavoro = risposta.json() or {}
            if str(lavoro.get("status") or "") in STATI_CONCLUSI:
                break
            time.sleep(ATTESA_FRA_CONTROLLI)
        else:
            raise TimeoutError(
                f"il lavoro {identificativo} non si e' concluso entro {timeout}s "
                f"(stato: {lavoro.get('status') or '?'})")

        if str(lavoro.get("status")) != "completed":
            raise RuntimeError(
                f"lavoro terminato in stato {lavoro.get('status')}: "
                f"{str(lavoro.get('error') or 'nessun dettaglio')[:120]}")
        return lavoro

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
            config_snapshot={"sources": list(self.config.get("sources") or ())})

    # ------------------------------------------------------------------
    @staticmethod
    def dump(dati: Any) -> bytes:  # pragma: no cover - comodita' di prova
        return json.dumps(dati, ensure_ascii=False).encode("utf-8")
