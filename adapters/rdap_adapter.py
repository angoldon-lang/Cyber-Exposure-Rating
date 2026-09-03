"""Adapter RDAP: informazioni pubbliche di registrazione del dominio."""
from __future__ import annotations

from datetime import UTC, datetime

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, NormalizedEvidence
from adapters.synthetic import build_posture
from app.models.enums import ConfidenceClass, ScoreCategoryKey, Severity

RDAP_BOOTSTRAP = "https://rdap.org/domain/"
EXPIRY_WARNING_DAYS = 60


class RDAPAdapter(BaseAdapter):
    key = "rdap"
    display_name = "RDAP / whois pubblico"
    is_passive = True
    coverage_areas = (ScoreCategoryKey.EMAIL_DNS_SECURITY.value,)
    default_timeout = 45

    def check_available(self) -> tuple[bool, str]:
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        raw: dict[str, object] = {}
        checked = 0
        with httpx.Client(timeout=15.0, follow_redirects=False,
                          headers={"Accept": "application/rdap+json"}) as client:
            for domain in self.context.scope_guard.filter_targets(self.context.domains, "hostname"):
                checked += 1
                try:
                    response = client.get(f"{RDAP_BOOTSTRAP}{domain}")
                    response.raise_for_status()
                    payload = response.json()
                except Exception as exc:  # noqa: BLE001
                    raw[domain] = {"error": str(exc)[:200]}
                    continue
                raw[domain] = payload
                evidences.extend(self._analyse(domain, self._extract_expiry(payload)))
        status = AdapterStatus.SUCCESS if checked else AdapterStatus.SKIPPED
        return AdapterResult(tool=self.key, status=status, evidences=evidences,
                             target_count=checked, raw_output=self.dump_json(raw))

    @staticmethod
    def _extract_expiry(payload: dict) -> datetime | None:
        for event in payload.get("events", []):
            if event.get("eventAction") in {"expiration", "registrar expiration"}:
                try:
                    return datetime.fromisoformat(str(event["eventDate"]).replace("Z", "+00:00"))
                except (ValueError, KeyError):
                    return None
        return None

    def _analyse(self, domain: str, expiry: datetime | None) -> list[NormalizedEvidence]:
        if expiry is None:
            return []
        days = (expiry - datetime.now(UTC)).days
        if days > EXPIRY_WARNING_DAYS:
            return []
        return [NormalizedEvidence(
            tool=self.key, target=domain, asset_key=domain,
            finding_type="domain_expiry_near",
            title=f"Il dominio scade tra {days} giorni",
            description=(f"La registrazione del dominio {domain} scade il {expiry.date().isoformat()}. "
                         "La perdita del dominio comporterebbe l'indisponibilita' di sito e posta "
                         "e il rischio di riassegnazione a terzi."),
            detail=expiry.date().isoformat(),
            category=ScoreCategoryKey.EMAIL_DNS_SECURITY.value,
            severity=Severity.MEDIUM.value, confidence_class=ConfidenceClass.CONFIRMED.value,
            data_source="RDAP", source_url=f"{RDAP_BOOTSTRAP}{domain}",
            attributes={"days_to_expiry": days})]

    def mock(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        raw: dict[str, object] = {}
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            raw[domain] = posture.registrar
            expiry = datetime.fromisoformat(posture.registrar["expires_at"])
            evidences.extend(self._analyse(domain, expiry))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             was_mocked=True, target_count=len(self.context.domains),
                             raw_output=self.dump_json(raw))
