"""Adapter Subfinder: enumerazione passiva e veloce dei sottodomini."""
from __future__ import annotations

import json

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset
from adapters.runner import UnsafeCommandError, is_available, run_command, tool_version
from adapters.synthetic import build_posture
from app.models.enums import AssetType, ScoreCategoryKey

BINARY = "subfinder"
ALLOWED_FLAGS = ("-silent", "-json", "-all", "-d", "-timeout", "-max-time")


class SubfinderAdapter(BaseAdapter):
    key = "subfinder"
    display_name = "Subfinder"
    is_passive = True
    coverage_areas = (ScoreCategoryKey.ATTACK_SURFACE.value,)
    default_timeout = 180

    def check_available(self) -> tuple[bool, str]:
        if not is_available(BINARY):
            return False, f"binario '{BINARY}' non presente nel worker"
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        version = tool_version(BINARY, "-version")
        assets: list[DiscoveredAsset] = []
        raw_chunks: list[bytes] = []
        seen: set[str] = set()
        failures = 0
        domains = self.context.scope_guard.filter_targets(self.context.domains, "hostname")

        for domain in domains[: int(self.config.get("max_targets", 25))]:
            # Argomenti passati come array: nessuna concatenazione di stringhe.
            args = ["-silent", "-json", "-all", "-d", domain, "-timeout", "10"]
            try:
                result = run_command(BINARY, args, allow_flags=ALLOWED_FLAGS,
                                     timeout=self.config.get("timeout_seconds", self.default_timeout))
            except (FileNotFoundError, UnsafeCommandError) as exc:
                failures += 1
                raw_chunks.append(json.dumps({"domain": domain, "error": str(exc)}).encode())
                continue
            if result.timed_out or result.exit_code != 0:
                failures += 1
            raw_chunks.append(result.stdout)
            for line in result.stdout.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = str(record.get("host", "")).strip().lower()
                if not host or host in seen:
                    continue
                seen.add(host)
                assets.append(DiscoveredAsset(
                    asset_key=host, asset_type=AssetType.SUBDOMAIN.value, display_name=host,
                    discovered_by=self.key,
                    attributes={"source": record.get("source"), "input": domain}))

        if not domains:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun dominio in perimetro",
                                 coverage_impact=self.coverage_weight)
        status = AdapterStatus.SUCCESS if failures == 0 else (
            AdapterStatus.PARTIAL if assets else AdapterStatus.FAILED)
        return AdapterResult(
            tool=self.key, status=status, assets=assets, tool_version=version,
            target_count=len(domains), raw_output=b"\n".join(raw_chunks),
            coverage_impact=0.0 if status is AdapterStatus.SUCCESS else self.coverage_weight * 0.5,
            error_message=None if failures == 0 else f"{failures} dominio/i non completati")

    def mock(self) -> AdapterResult:
        assets: list[DiscoveredAsset] = []
        payload: dict[str, list[str]] = {}
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            payload[domain] = posture.subdomains
            for host in posture.subdomains:
                assets.append(DiscoveredAsset(
                    asset_key=host, asset_type=AssetType.SUBDOMAIN.value, display_name=host,
                    discovered_by=self.key,
                    attributes={"source": "synthetic-passive-source", "input": domain}))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, assets=assets,
                             tool_version="subfinder v2.6.6 (mock)", was_mocked=True,
                             target_count=len(self.context.domains),
                             raw_output=self.dump_json(payload))
