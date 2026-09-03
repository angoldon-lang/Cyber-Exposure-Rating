"""Adapter di vulnerability intelligence.

Arricchisce le tecnologie osservate con CISA KEV, EPSS e CVSS applicando le
regole di attendibilita' di `adapters.vulnintel.matcher`: una CVE diventa
`confirmed` solo con prodotto E versione compatibili e fingerprint affidabile.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, NormalizedEvidence
from adapters.synthetic import build_posture
from adapters.vulnintel.feeds import FeedCache, fetch_epss, fetch_kev
from adapters.vulnintel.matcher import TechnologyObservation, evaluate_match
from app.models.enums import ConfidenceClass, ScoreCategoryKey, Severity

CATEGORY = ScoreCategoryKey.TECHNICAL_VULNERABILITIES.value

# Componenti la cui obsolescenza e' un fatto documentato dal produttore.
END_OF_LIFE_MARKERS: dict[str, str] = {
    "php:7.": "PHP 7.x non riceve piu' aggiornamenti di sicurezza",
    "wordpress:5.": "WordPress 5.x non e' piu' il ramo supportato",
    "microsoft-iis:8": "IIS 8.x segue il ciclo di vita di Windows Server 2012, terminato",
    "openssl:1.0": "OpenSSL 1.0.x e' end-of-life",
    "openssl:1.1": "OpenSSL 1.1.1 e' end-of-life",
    "apache httpd:2.2": "Apache httpd 2.2 e' end-of-life",
    "nginx:1.18": "nginx 1.18 non e' piu' un ramo mantenuto",
}


class VulnerabilityIntelligenceAdapter(BaseAdapter):
    key = "kev"
    display_name = "Vulnerability intelligence (CISA KEV / EPSS / CVSS)"
    is_passive = True
    coverage_areas = (CATEGORY,)
    default_timeout = 120

    def check_available(self) -> tuple[bool, str]:
        return True, "disponibile"

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        cache = FeedCache(Path(self.context.connector_config.get("cache_dir", "/tmp/defenix-feeds")))
        kev_url = self.context.connector_config.get("kev", {}).get("url", "")
        epss_url = self.context.connector_config.get("epss", {}).get("base_url", "")
        try:
            kev = fetch_kev(kev_url, cache) if kev_url else {}
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.key, status=AdapterStatus.FAILED,
                                 error_message=f"feed CISA KEV non disponibile: {type(exc).__name__}",
                                 coverage_impact=self.coverage_weight)

        observations = self._observations_from_context()
        candidates = self.context.tool_config.get("_vulnerability_candidates", [])
        evidences: list[NormalizedEvidence] = []
        cve_ids: list[str] = []

        for observation in observations:
            evidences.extend(self._eol_evidence(observation))
            for candidate in candidates:
                match = evaluate_match(observation, candidate)
                cve_id = str(candidate.get("cve", "")).upper()
                if match.matched and cve_id:
                    cve_ids.append(cve_id)
                evidences.append(self._vulnerability_evidence(
                    observation, candidate, match.confidence_class, match.reason,
                    in_kev=cve_id in kev))

        epss = fetch_epss(sorted(set(cve_ids)), epss_url, cache) if epss_url and cve_ids else {}
        for evidence in evidences:
            if evidence.cve_id and evidence.cve_id in epss:
                evidence.epss_score = epss[evidence.cve_id]

        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             target_count=len(observations),
                             raw_output=self.dump_json({"kev_entries": len(kev),
                                                        "epss_resolved": len(epss)}))

    def _observations_from_context(self) -> list[TechnologyObservation]:
        return [
            TechnologyObservation(
                name=str(entry.get("name", "")),
                version=entry.get("version"),
                source=str(entry.get("source", "unknown")),
                asset_key=str(entry.get("asset_key", "")),
                confidence=float(entry.get("confidence", 0.5)))
            for entry in self.context.tool_config.get("_observed_technologies", [])
        ]

    # ------------------------------------------------------------------
    def _eol_evidence(self, observation: TechnologyObservation) -> list[NormalizedEvidence]:
        if not observation.version:
            return []
        key = f"{observation.name.lower()}:{observation.version}"
        for marker, explanation in END_OF_LIFE_MARKERS.items():
            if key.startswith(marker):
                return [NormalizedEvidence(
                    tool=self.key, target=observation.asset_key, asset_key=observation.asset_key,
                    finding_type="end_of_life_software",
                    title=f"Componente non piu' supportato: {observation.name} {observation.version}",
                    description=(f"{explanation}. Un componente end-of-life non riceve correzioni di "
                                 "sicurezza: le vulnerabilita' future resteranno senza patch."),
                    detail=f"{observation.name} {observation.version}",
                    category=CATEGORY, severity=Severity.HIGH.value,
                    confidence_class=ConfidenceClass.PROBABLE.value,
                    data_source="Ciclo di vita dichiarato dal produttore",
                    observed_at=datetime.now(UTC))]
        return []

    def _vulnerability_evidence(self, observation: TechnologyObservation, candidate: dict[str, Any],
                                confidence_class: str, reason: str, *,
                                in_kev: bool) -> NormalizedEvidence:
        cvss = float(candidate.get("cvss", 0.0))
        severity = (Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH if cvss >= 7.0
                    else Severity.MEDIUM if cvss >= 4.0 else Severity.LOW)
        confirmed = confidence_class == ConfidenceClass.CONFIRMED.value
        prefix = "" if confirmed else "Possibile esposizione (non confermata): "
        default_title = "vulnerabilita' nota"
        return NormalizedEvidence(
            tool=self.key, target=observation.asset_key, asset_key=observation.asset_key,
            finding_type="vulnerability",
            title=f"{prefix}{candidate.get('cve')} - {candidate.get('title', default_title)}",
            description=(
                f"Componente osservato: {observation.name} "
                f"{observation.version or '(versione non determinata)'}. "
                f"Esito della correlazione: {reason}. "
                + ("La vulnerabilita' e' presente nel catalogo CISA Known Exploited Vulnerabilities: "
                   "esistono evidenze pubbliche di sfruttamento reale. " if in_kev else "")
                + ("" if confirmed else
                   "In assenza di una corrispondenza attendibile la voce e' esclusivamente "
                   "informativa e non incide sul rating.")),
            detail=str(candidate.get("cve", "")),
            category=CATEGORY, severity=severity.value, confidence_class=confidence_class,
            data_source="CISA KEV / NVD / EPSS", observed_at=datetime.now(UTC),
            cve_id=str(candidate.get("cve", "")).upper() or None,
            cvss_score=cvss or None,
            epss_score=candidate.get("epss"),
            cisa_kev=in_kev,
            attributes={"product": candidate.get("product"), "match_reason": reason,
                        "fingerprint_source": observation.source,
                        "fingerprint_confidence": observation.confidence})

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        raw: dict[str, Any] = {}
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            raw[domain] = {"vulnerabilities": len(posture.vulnerabilities)}
            for entry in posture.vulnerabilities:
                # Stesse regole del percorso reale: senza versione nota la CVE
                # resta informativa e non genera alcuna detrazione.
                observation = TechnologyObservation(
                    name=entry["product"],
                    version="1.0.0" if entry["version_known"] else None,
                    source="httpx-tech-detect", asset_key=f"web:{entry['host']}", confidence=0.9)
                candidate = {"cve": entry["cve"], "cvss": entry["cvss"], "epss": entry["epss"],
                             "product": entry["product"], "title": entry["title"],
                             "affected_below": "2.0.0"}
                match = evaluate_match(observation, candidate)
                evidences.append(self._vulnerability_evidence(
                    observation, candidate, match.confidence_class, match.reason,
                    in_kev=entry["kev"]))
            for service in posture.web_services:
                for tech in service.get("technologies", []):
                    evidences.extend(self._eol_evidence(TechnologyObservation(
                        name=tech["name"], version=tech.get("version"),
                        source="httpx-tech-detect", asset_key=f"web:{service['host']}",
                        confidence=0.85)))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             tool_version="CISA KEV + EPSS (mock)", was_mocked=True,
                             target_count=len(self.context.domains), raw_output=self.dump_json(raw))
