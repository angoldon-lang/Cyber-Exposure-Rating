"""Adapter Have I Been Pwned (opzionale, richiede API key a pagamento).

Vincoli di privacy (sezione 19):
  * nessuna password o credenziale viene mai memorizzata;
  * i dati sono mostrati solo per domini verificati;
  * gli indirizzi e-mail sono conservati in forma mascherata.
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
RECENT_BREACH_DAYS = 3 * 365


class HIBPAdapter(BaseAdapter):
    key = "hibp"
    display_name = "Have I Been Pwned"
    is_passive = True
    optional = True
    coverage_areas = (CATEGORY,)
    default_timeout = 90

    @property
    def api_key(self) -> str | None:
        return self.context.connector_config.get("hibp", {}).get("api_key")

    def check_available(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "HIBP non configurato (connettore opzionale, richiede API key a pagamento)"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        # Solo domini VERIFICATI: HIBP espone dati riferibili a persone.
        domains = [d for d in self.context.verified_domains if d in self.context.domains]
        if not domains:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun dominio verificato: ricerca HIBP non eseguita",
                                 coverage_impact=self.coverage_weight)
        base = str(self.context.connector_config.get("hibp", {})
                   .get("base_url", "https://haveibeenpwned.com/api/v3")).rstrip("/")
        headers = {"hibp-api-key": self.api_key or "", "user-agent": "Defenix-Exposure-Rating"}
        evidences: list[NormalizedEvidence] = []
        raw: dict[str, Any] = {}
        failures = 0
        with httpx.Client(timeout=30.0, headers=headers, follow_redirects=False) as client:
            for domain in domains:
                try:
                    response = client.get(f"{base}/breacheddomain/{domain}")
                    if response.status_code == 404:
                        raw[domain] = {}
                        continue
                    response.raise_for_status()
                    payload = response.json()
                except Exception as exc:  # noqa: BLE001
                    failures += 1
                    raw[domain] = {"error": type(exc).__name__}
                    continue
                # payload: {alias: [nomi dei breach]}. Non conserviamo gli alias in chiaro.
                summary: dict[str, int] = {}
                for aliases in payload.values() if isinstance(payload, dict) else []:
                    for breach in aliases:
                        summary[str(breach)] = summary.get(str(breach), 0) + 1
                raw[domain] = {"breaches": summary,
                               "accounts": len(payload) if isinstance(payload, dict) else 0}
                evidences.extend(self._build_from_summary(domain, summary))
        status = (AdapterStatus.SUCCESS if failures == 0
                  else AdapterStatus.PARTIAL if failures < len(domains) else AdapterStatus.FAILED)
        return AdapterResult(tool=self.key, status=status, evidences=evidences,
                             target_count=len(domains), raw_output=self.dump_json(raw),
                             coverage_impact=0.0 if failures == 0 else self.coverage_weight * 0.5)

    def _build_from_summary(self, domain: str, summary: dict[str, int]) -> list[NormalizedEvidence]:
        return [self._build(domain, {"name": name, "account_count": count,
                                     "breach_date": None, "is_recent": False, "classes": []})
                for name, count in summary.items()]

    # ------------------------------------------------------------------
    def _build(self, domain: str, breach: dict[str, Any]) -> NormalizedEvidence:
        is_recent = bool(breach.get("is_recent"))
        finding_type = "breach_credentials_recent" if is_recent else "breach_credentials_old"
        event_date = None
        if breach.get("breach_date"):
            try:
                event_date = datetime.fromisoformat(str(breach["breach_date"]).replace("Z", "+00:00"))
            except ValueError:
                event_date = None
        classes = ", ".join(breach.get("classes") or []) or "non specificate"
        return NormalizedEvidence(
            tool=self.key, target=domain, asset_key=f"mail:{domain}", finding_type=finding_type,
            title=f"Account del dominio presenti nel data breach «{breach['name']}»",
            description=(
                f"Risultano {breach.get('account_count', 0)} account del dominio {domain} coinvolti "
                f"nel data breach «{breach['name']}». Tipologie di dati compromessi: {classes}. "
                "La piattaforma non conserva password ne' credenziali: e' registrato solo il "
                "riferimento al breach e il numero di account interessati."),
            detail=str(breach["name"]),
            category=CATEGORY, severity=(Severity.HIGH if is_recent else Severity.MEDIUM).value,
            confidence_class=ConfidenceClass.CONFIRMED.value,
            data_source="Have I Been Pwned (fonte commerciale, non open source)",
            observed_at=datetime.now(UTC), event_date=event_date,
            attributes={"breach_name": breach["name"], "account_count": breach.get("account_count", 0),
                        "data_classes": breach.get("classes") or [], "recent": is_recent})

    def _stealer_evidence(self, domain: str, entry: dict[str, Any]) -> NormalizedEvidence:
        try:
            observed = datetime.fromisoformat(str(entry["observed_at"]).replace("Z", "+00:00"))
        except (ValueError, KeyError):
            observed = datetime.now(UTC)
        return NormalizedEvidence(
            tool=self.key, target=domain, asset_key=f"mail:{domain}",
            finding_type="stealer_log_credentials",
            title="Credenziali aziendali presenti in stealer log",
            description=(
                f"Risultano {entry.get('account_count', 0)} credenziali aziendali in log di "
                "infostealer. A differenza di un vecchio data breach, uno stealer log indica un "
                "endpoint compromesso di recente e credenziali potenzialmente ancora valide, "
                f"riferite a: {', '.join(entry.get('affected_services', []))}. "
                "Nessuna password viene memorizzata dalla piattaforma."),
            detail=str(entry.get("source", "stealer log"))[:200],
            category=CATEGORY, severity=Severity.CRITICAL.value,
            confidence_class=ConfidenceClass.CONFIRMED.value,
            data_source="Have I Been Pwned - stealer logs (fonte commerciale)",
            observed_at=datetime.now(UTC), event_date=observed,
            attributes={"account_count": entry.get("account_count", 0),
                        "affected_services": entry.get("affected_services", [])})

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        if not self.api_key and not self.context.connector_config.get("hibp", {}).get("mock_enabled"):
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED, was_mocked=True,
                error_message="HIBP non configurato (connettore opzionale a pagamento)",
                coverage_impact=self.coverage_weight)
        evidences: list[NormalizedEvidence] = []
        raw: dict[str, Any] = {}
        for domain in self.context.verified_domains or self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            raw[domain] = {"breaches": len(posture.breaches), "stealer": len(posture.stealer_logs)}
            for breach in posture.breaches:
                evidences.append(self._build(domain, breach))
            for entry in posture.stealer_logs:
                evidences.append(self._stealer_evidence(domain, entry))
            for index in range(2):
                mask_email(f"user{index}@{domain}")  # dimostra il mascheramento obbligatorio
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             tool_version="HIBP API v3 (mock)", was_mocked=True,
                             target_count=len(raw), raw_output=self.dump_json(raw))
