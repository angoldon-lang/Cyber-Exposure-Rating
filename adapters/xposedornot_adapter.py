"""Adapter XposedOrNot: quali indirizzi e-mail dell'organizzazione compaiono
in violazioni di dati pubblicate.

Cosa interessa al report e cosa no
----------------------------------
L'oggetto della verifica e' **l'indirizzo**, non la credenziale. Sapere che
`mario.rossi@azienda.it` compare in tre violazioni dice all'organizzazione che
quell'utenza va forzata al cambio password e messa sotto MFA; conoscere la
password non aggiunge nulla al rimedio e crea un problema di custodia che
nessun report dovrebbe avere. Di ogni violazione si conservano quindi soltanto
nome, anno, dimensione e **categorie** di dato esposto: mai un valore.

La fonte e' gratuita e non richiede API key, ma applica un limite severo per
indirizzo IP (2 al secondo, 25 all'ora, 100 al giorno): il numero di indirizzi
per scansione e' quindi limitato da `max_targets` e le richieste sono
distanziate. Superato il limite l'esito e' PARZIALE, non fallito: i risultati
gia' ottenuti restano validi e la copertura si riduce di conseguenza.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import httpx

from adapters.base import (
    AdapterResult,
    AdapterStatus,
    BaseAdapter,
    DiscoveredAsset,
    NormalizedEvidence,
)
from adapters.esposizione_email import (
    ANNI_RECENTI,
    CATEGORIA,
    evidenza_credenziali_recenti,
    evidenza_violazione,
)
from adapters.http_sicuro import get_seguendo_redirect
from adapters.synthetic import build_posture
from app.core.redaction import mask_email
from app.models.enums import AssetType, ConfidenceClass, Severity

BASE_URL_DEFAULT = "https://api.xposedornot.com/v1"


class XposedOrNotAdapter(BaseAdapter):
    key = "xposedornot"
    display_name = "XposedOrNot"
    is_passive = True
    coverage_areas = (CATEGORIA,)
    default_timeout = 300

    @property
    def base_url(self) -> str:
        configurato = (self.context.connector_config.get("xposedornot", {}).get("base_url")
                       or self.config.get("base_url") or BASE_URL_DEFAULT)
        return str(configurato).rstrip("/")

    def check_available(self) -> tuple[bool, str]:
        if not self._indirizzi():
            return False, ("nessun indirizzo e-mail dell'organizzazione noto: "
                           "servono i moduli di raccolta e-mail di SpiderFoot o "
                           "indirizzi dichiarati nel perimetro")
        return True, "disponibile"

    # ------------------------------------------------------------------
    def _indirizzi(self) -> list[str]:
        """Indirizzi da verificare, deduplicati e limitati al perimetro.

        Si verificano solo gli indirizzi il cui dominio e' in perimetro: la
        fonte espone dati riferibili a persone e non c'e' ragione legittima di
        interrogarla su domini che non appartengono all'organizzazione.
        """
        domini = {d.lower() for d in self.context.domains}
        if self.config.get("only_verified_domains", False):
            domini &= {d.lower() for d in self.context.verified_domains}
        candidati = list(self.context.email_addresses) + list(self.context.discovered_emails)
        visti: list[str] = []
        for indirizzo in candidati:
            normalizzato = str(indirizzo).strip().lower()
            if "@" not in normalizzato or normalizzato in visti:
                continue
            dominio = normalizzato.rsplit("@", 1)[1]
            if dominio in domini or any(dominio.endswith(f".{d}") for d in domini):
                visti.append(normalizzato)
        return visti[: int(self.config.get("max_targets", 20))]

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        indirizzi = self._indirizzi()
        pausa = float(self.config.get("seconds_between_requests", 0.6))
        evidenze: list[NormalizedEvidence] = []
        asset: list[DiscoveredAsset] = []
        raw: dict[str, Any] = {}
        errori = 0
        limite_raggiunto = False

        with httpx.Client(timeout=20.0, follow_redirects=False,
                          headers={"user-agent": "Defenix-Exposure-Rating"}) as client:
            for indice, indirizzo in enumerate(indirizzi):
                if indice:
                    time.sleep(pausa)
                try:
                    risposta = get_seguendo_redirect(
                        client, f"{self.base_url}/breach-analytics?email={indirizzo}")
                except Exception as exc:  # noqa: BLE001
                    errori += 1
                    raw[mask_email(indirizzo)] = {"error": type(exc).__name__}
                    continue
                if risposta.status_code == 429:
                    limite_raggiunto = True
                    break
                if risposta.status_code == 404:
                    # Indirizzo non presente in alcuna violazione indicizzata.
                    raw[mask_email(indirizzo)] = {"breaches": 0}
                    asset.append(self._asset(indirizzo, 0))
                    continue
                if risposta.status_code >= 400:
                    errori += 1
                    raw[mask_email(indirizzo)] = {"error": f"HTTP {risposta.status_code}"}
                    continue
                try:
                    payload = risposta.json()
                except ValueError:
                    errori += 1
                    raw[mask_email(indirizzo)] = {"error": "risposta non JSON"}
                    continue
                violazioni = self._violazioni(payload)
                raw[mask_email(indirizzo)] = {
                    "breaches": len(violazioni),
                    "names": sorted({v["breach"] for v in violazioni}),
                    "pastes": self._numero_paste(payload)}
                asset.append(self._asset(indirizzo, len(violazioni)))
                evidenze.extend(self._evidenze(indirizzo, violazioni))
                paste = self._numero_paste(payload)
                if paste:
                    evidenze.append(self._evidenza_paste(indirizzo, paste))

        return AdapterResult(
            tool=self.key, status=self._stato(indirizzi, errori, limite_raggiunto),
            evidences=evidenze, assets=asset, target_count=len(indirizzi),
            raw_output=self.dump_json(raw),
            error_message=self._motivo(errori, limite_raggiunto),
            coverage_impact=0.0 if not (errori or limite_raggiunto) else self.coverage_weight * 0.5,
            config_snapshot={"addresses_checked": len(indirizzi)})

    def _stato(self, indirizzi: list[str], errori: int, limite: bool) -> AdapterStatus:
        if errori >= len(indirizzi) and indirizzi:
            return AdapterStatus.FAILED
        if errori or limite:
            return AdapterStatus.PARTIAL
        return AdapterStatus.SUCCESS

    @staticmethod
    def _motivo(errori: int, limite: bool) -> str | None:
        if limite:
            return ("limite di richieste della fonte gratuita raggiunto: "
                    "gli indirizzi rimanenti non sono stati verificati")
        if errori:
            return f"{errori} indirizzi non verificati per errore della fonte"
        return None

    # ------------------------------------------------------------------
    @staticmethod
    def _violazioni(payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Estrae i dettagli delle violazioni, scartando tutto il resto.

        Della risposta si legge esclusivamente `ExposedBreaches`: le altre
        sezioni contengono metriche aggregate che non servono al rimedio.
        """
        contenitore = payload.get("ExposedBreaches") or {}
        dettagli = contenitore.get("breaches_details") if isinstance(contenitore, dict) else None
        risultato: list[dict[str, Any]] = []
        for voce in dettagli or []:
            if not isinstance(voce, dict):
                continue
            risultato.append({
                "breach": str(voce.get("breach") or "sconosciuta"),
                "domain": str(voce.get("domain") or ""),
                "year": str(voce.get("xposed_date") or "")[:4],
                "records": int(voce.get("xposed_records") or 0),
                "data": [d.strip().lower() for d in str(voce.get("xposed_data") or "").split(";")
                         if d.strip()],
            })
        return risultato

    @staticmethod
    def _numero_paste(payload: dict[str, Any]) -> int:
        sommario = payload.get("PastesSummary") or {}
        if isinstance(sommario, dict):
            try:
                return int(sommario.get("cnt") or 0)
            except (TypeError, ValueError):
                return 0
        return 0

    def _asset(self, indirizzo: str, violazioni: int) -> DiscoveredAsset:
        return DiscoveredAsset(
            asset_key=indirizzo, asset_type=AssetType.EMAIL_ADDRESS.value,
            display_name=mask_email(indirizzo), discovered_by=self.key,
            attributes={"masked": True, "breach_count": violazioni,
                        "checked_source": "XposedOrNot"})

    # ------------------------------------------------------------------
    def _evidenze(self, indirizzo: str,
                  violazioni: list[dict[str, Any]]) -> list[NormalizedEvidence]:
        """Una evidenza per violazione, piu' una sola per indirizzo se recente.

        La granularita' per violazione e' quella che serve all'analista per
        verificare ed e' quella su cui questa fonte e SpiderFoot convergono
        sulla stessa impronta. La detrazione per credenziali recenti resta
        invece una per indirizzo: moltiplicarla per il numero di violazioni
        punirebbe due volte lo stesso rimedio, che e' un unico cambio password.
        """
        evidenze: list[NormalizedEvidence] = []
        recenti: list[str] = []
        anno_massimo: int | None = None
        anno_corrente = datetime.now(UTC).year

        for violazione in violazioni:
            anno = int(violazione["year"]) if violazione["year"].isdigit() else None
            categorie = set(violazione["data"])
            evidenze.append(evidenza_violazione(
                tool=self.key, indirizzo=indirizzo, violazione=violazione["breach"],
                anno=anno, categorie=categorie, record=violazione["records"] or None,
                fonte_dati="XposedOrNot"))
            if (anno is not None and (anno_corrente - anno) <= ANNI_RECENTI
                    and evidenze[-1].severity == Severity.HIGH.value):
                recenti.append(violazione["breach"])
                anno_massimo = anno if anno_massimo is None else max(anno_massimo, anno)

        if anno_massimo is not None:
            evidenze.append(evidenza_credenziali_recenti(
                tool=self.key, indirizzo=indirizzo, anno=anno_massimo,
                violazioni=recenti, fonte_dati="XposedOrNot"))
        return evidenze

    def _evidenza_paste(self, indirizzo: str, paste: int) -> NormalizedEvidence:
        mascherato = mask_email(indirizzo)
        return NormalizedEvidence(
            tool=self.key, target=mascherato, asset_key=indirizzo,
            finding_type="email_in_public_paste",
            title=f"Indirizzo pubblicato su siti di paste: {mascherato}",
            description=("L'indirizzo compare in contenuti pubblicati su siti di paste, "
                         "tipicamente insieme ad altri dati esfiltrati. Il contenuto non viene "
                         "scaricato ne' conservato: e' registrato soltanto il numero di "
                         "pubblicazioni rilevate."),
            detail=f"{paste} pubblicazioni", category=CATEGORIA,
            severity=Severity.MEDIUM.value, confidence_class=ConfidenceClass.PROBABLE.value,
            data_source="XposedOrNot", observed_at=datetime.now(UTC),
            attributes={"paste_count": paste})

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        evidenze: list[NormalizedEvidence] = []
        asset: list[DiscoveredAsset] = []
        raw: dict[str, Any] = {}
        for dominio in self.context.domains:
            posture = build_posture(self.context.seed(dominio), dominio,
                                    self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            per_indirizzo: dict[str, list[dict[str, Any]]] = {}
            for esposizione in posture.email_exposures:
                per_indirizzo.setdefault(str(esposizione["address"]), []).append({
                    "breach": str(esposizione["breach"]),
                    "domain": "",
                    "year": str(esposizione["year"]),
                    "records": int(esposizione["records"]),
                    "data": [str(c) for c in esposizione["classes"]]})
            for indirizzo, violazioni in sorted(per_indirizzo.items()):
                asset.append(self._asset(indirizzo, len(violazioni)))
                raw[mask_email(indirizzo)] = {"breaches": len(violazioni)}
                evidenze.extend(self._evidenze(indirizzo, violazioni))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidenze,
                             assets=asset, was_mocked=True, tool_version="XposedOrNot v1 (mock)",
                             target_count=len(asset), raw_output=self.dump_json(raw))
