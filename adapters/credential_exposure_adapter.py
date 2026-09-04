"""Credenziali e informazioni aziendali esposte su dark web e canali di leak.

Copre cio' che HIBP da solo non copre: log di infostealer, combolist, paste e
menzioni su forum o canali chiusi. E' scritto per un connettore generico,
perche' le fonti serie in questo ambito sono tutte a pagamento e cambiano nel
tempo: l'indirizzo di base e la chiave si configurano, il resto e' identico.

Vincoli di riservatezza, non negoziabili:

  * **nessuna password viene mai letta, memorizzata o mostrata.** Della
    credenziale si conserva solo l'esistenza, l'identita' mascherata e il
    contesto (servizio interessato, data di osservazione);
  * gli indirizzi e-mail sono sempre mascherati, e visibili in chiaro solo ai
    ruoli autorizzati attraverso lo sblocco esplicito dei dati personali;
  * i dati sono raccolti solo per i domini verificati, perche' riguardano
    persone identificabili;
  * non viene mai scaricato ne' conservato il contenuto integrale di un leak.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, NormalizedEvidence
from adapters.synthetic import build_posture
from app.core.redaction import mask_email
from app.models.enums import ConfidenceClass, ScoreCategoryKey, Severity

CATEGORY = ScoreCategoryKey.DARKWEB_BREACH.value

# Oltre questa soglia una credenziale non e' piu' trattata come "recente": il
# peso nel rating cambia di conseguenza (regole DW-BREACH-RECENT / DW-BREACH-OLD).
GIORNI_RECENTE = 365

# Chiavi che non devono mai entrare nelle evidenze, qualunque cosa restituisca
# la fonte: sono il contenuto della credenziale, non la sua esistenza.
CHIAVI_VIETATE = {"password", "passwd", "pwd", "plaintext", "hash", "ntlm",
                  "cookie", "cookies", "token", "session", "secret", "credential"}


class CredentialExposureAdapter(BaseAdapter):
    """Credenziali aziendali esposte: stealer log, combolist, paste, menzioni."""

    key = "credential_exposure"
    display_name = "Credenziali esposte (dark web)"
    is_passive = True
    optional = True
    coverage_areas = (CATEGORY,)
    default_timeout = 120

    # ------------------------------------------------------------------
    @property
    def connettore(self) -> dict[str, Any]:
        """Configurazione del connettore.

        Nome distinto da `config`, che nella classe base indica la voce di
        `tool_profiles.yaml`: sono due cose diverse.
        """
        return self.context.connector_config.get("credential_exposure", {})

    @property
    def api_key(self) -> str | None:
        return self.connettore.get("api_key")

    def check_available(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, ("connettore delle credenziali esposte non configurato "
                           "(richiede un abbonamento a una fonte di threat intelligence)")
        return True, "disponibile"

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        # Solo domini verificati: si tratta di dati riferibili a persone.
        domini = [d for d in self.context.verified_domains if d in self.context.domains]
        if not domini:
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED,
                error_message="nessun dominio verificato: ricerca non eseguita",
                coverage_impact=self.coverage_weight)

        base = str(self.connettore.get("base_url", "")).rstrip("/")
        if not base:
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED,
                error_message="indirizzo della fonte non configurato",
                coverage_impact=self.coverage_weight)

        evidenze: list[NormalizedEvidence] = []
        grezzo: dict[str, Any] = {}
        with httpx.Client(timeout=self.default_timeout,
                          headers={"Authorization": f"Bearer {self.api_key}",
                                   "User-Agent": "Defenix-Exposure-Rating"}) as client:
            for dominio in domini:
                decisione = self.context.scope_guard.check_hostname(dominio)
                if not decisione.allowed:
                    continue
                risposta = client.get(f"{base}/exposures", params={"domain": dominio})
                risposta.raise_for_status()
                dati = risposta.json()
                grezzo[dominio] = {"voci": len(dati.get("items", []))}
                evidenze.extend(self._da_risposta(dominio, dati.get("items", [])))

        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidenze,
                             tool_version="connettore credenziali esposte",
                             target_count=len(grezzo), raw_output=self.dump_json(grezzo))

    # ------------------------------------------------------------------
    def _da_risposta(self, dominio: str, voci: list[dict[str, Any]]) -> list[NormalizedEvidence]:
        evidenze = []
        for voce in voci:
            tipo = str(voce.get("type", "combolist"))
            osservato = _data(voce.get("observed_at"))
            if tipo == "stealer_log":
                evidenze.append(self._stealer(dominio, voce, osservato))
            elif tipo == "mention":
                evidenze.append(self._menzione(dominio, voce, osservato))
            else:
                evidenze.append(self._credenziali(dominio, voce, osservato))
        return evidenze

    def _attributi(self, voce: dict[str, Any]) -> dict[str, Any]:
        """Attributi ripuliti da tutto cio' che somigli a una credenziale.

        La fonte puo' restituire campi non previsti: la lista di esclusione
        agisce sulle chiavi effettivamente presenti, non su quelle attese.
        """
        puliti = {chiave: valore for chiave, valore in voce.items()
                  if not any(vietata in chiave.lower() for vietata in CHIAVI_VIETATE)}
        campione = voce.get("sample_identities") or []
        if campione:
            puliti["sample_identities"] = [mask_email(str(i)) for i in campione[:5]]
        return puliti

    def _stealer(self, dominio: str, voce: dict, osservato: datetime) -> NormalizedEvidence:
        conteggio = int(voce.get("account_count", 1))
        servizi = ", ".join(str(s) for s in (voce.get("affected_services") or [])[:4])
        return NormalizedEvidence(
            tool=self.key, target=dominio, asset_key=f"mail:{dominio}",
            finding_type="stealer_log_credentials",
            title=f"{dominio}: credenziali presenti in log di infostealer",
            description=(
                f"Sono state osservate {conteggio} identita' del dominio in log prodotti da "
                "malware di tipo infostealer. Questi log contengono in genere credenziali "
                "valide al momento della raccolta e cookie di sessione: vanno considerate "
                "compromesse fino a rotazione."
                + (f" Servizi interessati: {servizi}." if servizi else "")),
            detail=voce.get("source"),
            category=CATEGORY, severity=Severity.CRITICAL.value,
            confidence_class=ConfidenceClass.CONFIRMED.value,
            data_source="Threat intelligence su credenziali esposte",
            observed_at=datetime.now(UTC), event_date=osservato,
            attributes=self._attributi(voce))

    def _credenziali(self, dominio: str, voce: dict, osservato: datetime) -> NormalizedEvidence:
        recente = (datetime.now(UTC) - osservato).days <= GIORNI_RECENTE
        conteggio = int(voce.get("account_count", 1))
        return NormalizedEvidence(
            tool=self.key, target=dominio, asset_key=f"mail:{dominio}",
            finding_type=("breach_credentials_recent" if recente else "breach_credentials_old"),
            title=(f"{dominio}: {conteggio} credenziali esposte in "
                   f"{voce.get('source', 'raccolta di credenziali')}"),
            description=(
                "Indirizzi del dominio compaiono in una raccolta di credenziali diffusa "
                "pubblicamente. Della credenziale viene registrata solo l'esistenza: "
                "nessuna password viene letta o conservata."
                + ("" if recente else " La raccolta non e' recente: il rischio dipende "
                   "dal riutilizzo delle stesse password.")),
            detail=voce.get("source"),
            category=CATEGORY,
            severity=(Severity.HIGH if recente else Severity.MEDIUM).value,
            confidence_class=ConfidenceClass.CONFIRMED.value,
            data_source="Threat intelligence su credenziali esposte",
            observed_at=datetime.now(UTC), event_date=osservato,
            attributes=self._attributi(voce))

    def _menzione(self, dominio: str, voce: dict, osservato: datetime) -> NormalizedEvidence:
        return NormalizedEvidence(
            tool=self.key, target=dominio, asset_key=f"mail:{dominio}",
            finding_type="darkweb_mention",
            title=f"{dominio}: menzione su canali chiusi",
            description=(
                "Il dominio o il nome dell'organizzazione compare su forum, marketplace o "
                "canali chiusi. La menzione non implica di per se' una compromissione: "
                "richiede una verifica di contesto prima di qualunque conclusione."),
            detail=voce.get("source"),
            category=CATEGORY, severity=Severity.MEDIUM.value,
            # Una menzione non e' una compromissione: pesa al 50% nel rating.
            confidence_class=ConfidenceClass.PROBABLE.value,
            data_source="Threat intelligence su credenziali esposte",
            observed_at=datetime.now(UTC), event_date=osservato,
            attributes=self._attributi(voce))

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        """Dati sintetici deterministici, con la stessa forma della fonte reale.

        Un connettore non configurato resta `skipped` anche in modalita'
        simulata, salvo `mock_enabled`: altrimenti la dimostrazione mostrerebbe
        una copertura che l'installazione reale non ha.
        """
        if not self.api_key and not self.connettore.get("mock_enabled"):
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED, was_mocked=True,
                error_message="connettore delle credenziali esposte non configurato",
                coverage_impact=self.coverage_weight)

        evidenze: list[NormalizedEvidence] = []
        grezzo: dict[str, Any] = {}
        adesso = datetime.now(UTC)

        for dominio in (self.context.verified_domains or self.context.domains):
            postura = build_posture(self.context.seed(dominio), dominio,
                                    self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            voci: list[dict[str, Any]] = []
            for log in postura.stealer_logs:
                voci.append({"type": "stealer_log", "source": log["source"],
                             "account_count": log["account_count"],
                             "affected_services": log["affected_services"],
                             "observed_at": log["observed_at"],
                             "sample_identities": [f"utente{i}@{dominio}" for i in range(2)]})
            for breach in postura.breaches:
                voci.append({"type": "combolist", "source": breach.get("name", "raccolta"),
                             "account_count": breach["account_count"],
                             "observed_at": breach["breach_date"],
                             "sample_identities": [f"info@{dominio}"]})
            for menzione in postura.darkweb_mentions:
                voci.append({"type": "mention",
                             "source": menzione.get("source", "forum chiuso"),
                             "observed_at": menzione.get(
                                 "observed_at", (adesso - timedelta(days=40)).isoformat())})

            grezzo[dominio] = {"voci": len(voci)}
            evidenze.extend(self._da_risposta(dominio, voci))

        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidenze,
                             tool_version="connettore credenziali esposte (mock)",
                             was_mocked=True, target_count=len(grezzo),
                             raw_output=self.dump_json(grezzo))


def _data(valore: Any) -> datetime:
    if isinstance(valore, datetime):
        return valore if valore.tzinfo else valore.replace(tzinfo=UTC)
    try:
        analizzata = datetime.fromisoformat(str(valore).replace("Z", "+00:00"))
        return analizzata if analizzata.tzinfo else analizzata.replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return datetime.now(UTC)
