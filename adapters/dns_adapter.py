"""Adapter DNS: risoluzione dei record pubblici del dominio."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset, NormalizedEvidence
from adapters.synthetic import build_posture
from app.models.enums import AssetType, ConfidenceClass, ScoreCategoryKey, Severity

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")


class DNSAdapter(BaseAdapter):
    key = "dns"
    display_name = "DNS resolver"
    is_passive = True
    coverage_areas = (ScoreCategoryKey.EMAIL_DNS_SECURITY.value, ScoreCategoryKey.ATTACK_SURFACE.value)
    default_timeout = 60

    def check_available(self) -> tuple[bool, str]:
        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            return False, "dnspython non installato"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        evidences: list[NormalizedEvidence] = []
        assets: list[DiscoveredAsset] = []
        raw: dict[str, Any] = {}
        checked = 0

        for domain in self.context.scope_guard.filter_targets(self.context.domains, "hostname"):
            checked += 1
            records: dict[str, list[str]] = {}
            for record_type in RECORD_TYPES:
                try:
                    answers = resolver.resolve(domain, record_type)
                    records[record_type] = sorted(str(rdata) for rdata in answers)
                except Exception:  # noqa: BLE001 - assenza del record e' un esito normale
                    records[record_type] = []
            raw[domain] = records

            assets.append(DiscoveredAsset(
                asset_key=domain, asset_type=AssetType.DOMAIN.value, display_name=domain,
                discovered_by=self.key, attributes={"records": records}))

            for address in records.get("A", []) + records.get("AAAA", []):
                decision = self.context.scope_guard.check_ip(address)
                assets.append(DiscoveredAsset(
                    asset_key=address, asset_type=AssetType.IP_ADDRESS.value, display_name=address,
                    discovered_by=self.key,
                    attributes={"from_domain": domain, "in_authorized_scope": decision.allowed},
                    relationships=[{"type": "resolves_to", "source": domain, "target": address}]))

            if not records.get("CAA"):
                evidences.append(self._evidence(
                    domain, "caa_missing", "Record CAA non presente",
                    "Il dominio non pubblica record CAA: qualsiasi Certification Authority puo' "
                    "emettere certificati per questo dominio.",
                    Severity.LOW, ConfidenceClass.CONFIRMED))

        return AdapterResult(
            tool=self.key, status=AdapterStatus.SUCCESS if checked else AdapterStatus.SKIPPED,
            evidences=evidences, assets=assets, target_count=checked,
            raw_output=self.dump_json(raw),
            error_message=None if checked else "nessun dominio in perimetro")

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        assets: list[DiscoveredAsset] = []
        raw: dict[str, Any] = {}

        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            records = {
                "A": [posture.ip_addresses[0]] if posture.ip_addresses else [],
                "MX": posture.email["mx"],
                "NS": posture.registrar["nameservers"],
                "TXT": [posture.email["spf_record"]] if posture.email.get("spf_record") else [],
                "CAA": ["0 issue \"letsencrypt.org\""] if posture.email["caa"] else [],
            }
            raw[domain] = records
            assets.append(DiscoveredAsset(
                asset_key=domain, asset_type=AssetType.DOMAIN.value, display_name=domain,
                discovered_by=self.key, attributes={"records": records}))
            for address in posture.ip_addresses:
                assets.append(DiscoveredAsset(
                    asset_key=address, asset_type=AssetType.IP_ADDRESS.value, display_name=address,
                    discovered_by=self.key, attributes={"from_domain": domain},
                    relationships=[{"type": "resolves_to", "source": domain, "target": address}]))
            if not posture.email["caa"]:
                evidences.append(self._evidence(
                    domain, "caa_missing", "Record CAA non presente",
                    "Il dominio non pubblica record CAA: qualsiasi Certification Authority puo' "
                    "emettere certificati per questo dominio.",
                    Severity.LOW, ConfidenceClass.CONFIRMED))

        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             assets=assets, was_mocked=True, target_count=len(self.context.domains),
                             raw_output=self.dump_json(raw))

    # ------------------------------------------------------------------
    def _evidence(self, target: str, finding_type: str, title: str, description: str,
                  severity: Severity, confidence: ConfidenceClass) -> NormalizedEvidence:
        return NormalizedEvidence(
            tool=self.key, target=target, asset_key=target, finding_type=finding_type,
            title=title, description=description,
            category=ScoreCategoryKey.EMAIL_DNS_SECURITY.value,
            severity=severity.value, confidence_class=confidence.value,
            data_source="DNS pubblico", observed_at=datetime.now(UTC))
