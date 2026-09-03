"""Certificate Transparency: enumerazione passiva dei sottodomini dai log CT."""
from __future__ import annotations

import httpx

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset, NormalizedEvidence
from adapters.synthetic import build_posture
from app.models.enums import AssetType, ConfidenceClass, ScoreCategoryKey, Severity

CRTSH_URL = "https://crt.sh/"
MAX_RESULTS = 2000


class CertificateTransparencyAdapter(BaseAdapter):
    key = "certificate_transparency"
    display_name = "Certificate Transparency (crt.sh)"
    is_passive = True
    coverage_areas = (ScoreCategoryKey.ATTACK_SURFACE.value,)
    default_timeout = 90

    def check_available(self) -> tuple[bool, str]:
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        assets: list[DiscoveredAsset] = []
        raw: dict[str, object] = {}
        found: set[str] = set()
        checked = 0
        with httpx.Client(timeout=30.0, follow_redirects=False) as client:
            for domain in self.context.scope_guard.filter_targets(self.context.domains, "hostname"):
                checked += 1
                try:
                    response = client.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"})
                    response.raise_for_status()
                    entries = response.json()[:MAX_RESULTS]
                except Exception as exc:  # noqa: BLE001
                    raw[domain] = {"error": str(exc)[:200]}
                    continue
                raw[domain] = {"entries": len(entries)}
                for entry in entries:
                    for name in str(entry.get("name_value", "")).splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(domain) and name not in found:
                            found.add(name)
        for name in sorted(found):
            assets.append(DiscoveredAsset(
                asset_key=name,
                asset_type=AssetType.SUBDOMAIN.value if name not in self.context.domains
                else AssetType.DOMAIN.value,
                display_name=name, discovered_by=self.key,
                attributes={"source": "certificate_transparency"}))
        return AdapterResult(
            tool=self.key,
            status=AdapterStatus.SUCCESS if checked else AdapterStatus.SKIPPED,
            assets=assets, evidences=self._surface_evidence(found), target_count=checked,
            raw_output=self.dump_json(raw))

    def _surface_evidence(self, names: set[str]) -> list[NormalizedEvidence]:
        if len(names) < 50:
            return []
        domain = self.context.domains[0] if self.context.domains else "n/d"
        return [NormalizedEvidence(
            tool=self.key, target=domain, asset_key=domain,
            finding_type="large_exposed_footprint",
            title=f"Superficie esposta ampia: {len(names)} nomi host pubblicati",
            description=("Il numero di nomi host associati al dominio e' elevato. Una superficie "
                         "ampia richiede un inventario aggiornato e un responsabile per ciascun asset."),
            detail=str(len(names)),
            category=ScoreCategoryKey.ATTACK_SURFACE.value,
            severity=Severity.LOW.value, confidence_class=ConfidenceClass.PROBABLE.value,
            data_source="Certificate Transparency")]

    def mock(self) -> AdapterResult:
        assets: list[DiscoveredAsset] = []
        names: set[str] = set()
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            names.update(posture.subdomains)
            names.add(domain)
        for name in sorted(names):
            assets.append(DiscoveredAsset(
                asset_key=name,
                asset_type=AssetType.DOMAIN.value if name in self.context.domains
                else AssetType.SUBDOMAIN.value,
                display_name=name, discovered_by=self.key,
                attributes={"source": "certificate_transparency"}))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, assets=assets,
                             evidences=self._surface_evidence(names), was_mocked=True,
                             target_count=len(self.context.domains),
                             raw_output=self.dump_json({"names": sorted(names)}))
