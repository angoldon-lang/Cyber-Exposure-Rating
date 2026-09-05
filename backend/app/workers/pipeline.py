"""Orchestratore della scansione.

Sequenza: preparazione perimetro -> esecuzione adapter -> normalizzazione ->
correlazione -> scoring -> confidence -> persistenza -> diff.

Invariante: il fallimento di un adapter non interrompe mai la scansione.
Riduce la copertura e quindi il confidence score.
"""
from __future__ import annotations

import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Sequence

from adapters.base import AdapterContext, AdapterResult, AdapterStatus
from adapters.registry import build_adapters, build_tool_config, coverage_matrix, profile_definition
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import ScanStatus
from app.services.confidence import ConfidenceEngine, ConfidenceInput, ConfidenceResult, ToolRunSummary
from app.services.normalization import (
    CorrelatedFinding,
    NormalizationOutput,
    NormalizationService,
    collect_technologies,
)
from app.services.ownership import OwnershipContext, build_scope_guard_from_ownership
from app.services.scoring import ScorableFinding, ScoringEngine, ScoringResult

logger = get_logger(__name__)


@dataclass
class ScanRequest:
    """Tutto cio' che serve per eseguire una scansione, gia' autorizzato."""

    scan_id: str
    tenant_id: str
    company_id: str
    company_name: str
    profile: str
    domains: list[str]
    verified_domains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    authorized_ips: list[str] = field(default_factory=list)
    network_ranges: list[str] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    email_header: str | None = None
    dkim_selectors: list[str] = field(default_factory=list)
    excluded_values: list[str] = field(default_factory=list)
    mock_mode: bool = True
    connector_config: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanOutcome:
    scan_id: str
    status: str
    tool_runs: list[dict[str, Any]]
    normalization: NormalizationOutput
    scoring: ScoringResult
    confidence: ConfidenceResult
    raw_outputs: dict[str, bytes] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def is_provisional(self) -> bool:
        return not self.confidence.is_publishable


ProgressCallback = Callable[[str, int], None]


class ScanPipeline:
    def __init__(self, request: ScanRequest, *,
                 progress: ProgressCallback | None = None,
                 scoring_engine: ScoringEngine | None = None,
                 confidence_engine: ConfidenceEngine | None = None) -> None:
        self.request = request
        self.progress = progress or (lambda stage, percent: None)
        self.scoring_engine = scoring_engine or ScoringEngine()
        self.confidence_engine = confidence_engine or ConfidenceEngine()
        self.profile_definition = profile_definition(request.profile)

    # ------------------------------------------------------------------
    def build_context(self, *, known_subdomains: Sequence[str] = (),
                      web_targets: Sequence[str] = (),
                      discovered_emails: Sequence[str] = (),
                      extra_tool_config: dict[str, Any] | None = None) -> AdapterContext:
        ownership = self._ownership_context()
        guard = build_scope_guard_from_ownership(
            ownership,
            require_explicit_whitelist=bool(
                self.profile_definition.get("requires_explicit_scope_whitelist", False)))
        tool_config = build_tool_config(self.request.profile)
        tool_config.update(extra_tool_config or {})
        return AdapterContext(
            scan_id=self.request.scan_id, tenant_id=self.request.tenant_id,
            company_id=self.request.company_id, company_name=self.request.company_name,
            profile=self.request.profile, scope_guard=guard,
            domains=list(self.request.domains),
            verified_domains=list(self.request.verified_domains),
            ip_addresses=list(self.request.ip_addresses),
            network_ranges=list(self.request.network_ranges),
            brands=list(self.request.brands),
            email_addresses=list(self.request.email_addresses),
            email_header=self.request.email_header,
            dkim_selectors=list(self.request.dkim_selectors),
            known_subdomains=list(known_subdomains),
            discovered_emails=list(discovered_emails),
            web_targets=list(web_targets),
            mock_mode=self.request.mock_mode,
            tool_config=tool_config,
            connector_config=self.request.connector_config)

    def _ownership_context(self) -> OwnershipContext:
        return OwnershipContext.build(
            verified_domains=self.request.verified_domains,
            declared_domains=[d for d in self.request.domains
                              if d not in self.request.verified_domains],
            authorized_ips=self.request.authorized_ips,
            authorized_networks=self.request.network_ranges,
            excluded_values=self.request.excluded_values)

    # ------------------------------------------------------------------
    def run(self) -> ScanOutcome:
        started = datetime.now(UTC)
        self.progress(ScanStatus.RUNNING.value, 5)

        # --- Fase 1: discovery (adapter di enumerazione) ---
        discovery_context = self.build_context()
        discovery_adapters = build_adapters(
            discovery_context,
            only=["dns", "rdap", "certificate_transparency", "subfinder", "amass_passive",
                  "spiderfoot"])
        discovery_results = self._execute(discovery_adapters, stage="discovery", base_percent=10)

        subdomains = sorted({asset.asset_key for result in discovery_results
                             for asset in result.assets
                             if asset.asset_type in {"subdomain", "domain"}})
        # Gli indirizzi e-mail emersi in discovery sono l'input delle verifiche
        # sulle violazioni: senza questo passaggio XposedOrNot non ha nulla da
        # cercare e la sezione dark web resta vuota.
        discovered_emails = sorted({asset.asset_key for result in discovery_results
                                    for asset in result.assets
                                    if asset.asset_type == "email_address"})
        self.progress("discovery_completed", 35)

        # --- Fase 2: analisi (posta, web, TLS, dark web) ---
        analysis_context = self.build_context(
            known_subdomains=subdomains,
            discovered_emails=discovered_emails,
            web_targets=[f"https://{host}" for host in subdomains[:200]])
        analysis_adapters = build_adapters(
            analysis_context,
            only=["checkdmarc", "httpx", "testssl", "zap_baseline", "naabu", "nuclei",
                  "ransomware_live", "hibp", "credential_exposure", "xposedornot",
                  "dnstwist", "email_header"])
        analysis_results = self._execute(analysis_adapters, stage="analysis", base_percent=40)
        self.progress("analysis_completed", 70)

        # --- Fase 3: normalizzazione e correlazione ---
        self.progress(ScanStatus.NORMALIZING.value, 75)
        normalization = NormalizationService(self._ownership_context())
        partial = normalization.run(discovery_results + analysis_results)

        # --- Fase 4: vulnerability intelligence sulle tecnologie osservate ---
        observations = collect_technologies(partial.assets)
        intel_context = self.build_context(
            known_subdomains=subdomains,
            extra_tool_config={"_observed_technologies": observations})
        intel_results = self._execute(build_adapters(intel_context, only=["kev"]),
                                      stage="vulnerability_intelligence", base_percent=80)

        all_results = discovery_results + analysis_results + intel_results
        output = normalization.run(all_results)

        # --- Fase 5: scoring deterministico ---
        self.progress(ScanStatus.SCORING.value, 88)
        scoring = self.scoring_engine.score(
            [self._to_scorable(f) for f in output.findings])

        # --- Fase 6: confidence ---
        confidence = self.confidence_engine.compute(
            self._confidence_input(all_results, output))
        self.progress("completed", 100)

        tool_runs = [self._tool_run_record(r) for r in all_results]
        failed = sum(1 for r in all_results if r.status is AdapterStatus.FAILED)
        status = ScanStatus.PARTIAL.value if failed else ScanStatus.COMPLETED.value

        return ScanOutcome(
            scan_id=self.request.scan_id, status=status, tool_runs=tool_runs,
            normalization=output, scoring=scoring, confidence=confidence,
            raw_outputs={r.tool: r.raw_output for r in all_results if r.raw_output},
            stats={**output.stats,
                   "duration_seconds": (datetime.now(UTC) - started).total_seconds(),
                   "tools_total": len(all_results),
                   "tools_failed": failed,
                   "tools_skipped": sum(1 for r in all_results if r.status is AdapterStatus.SKIPPED),
                   "overall_score": scoring.overall_score,
                   "rating_class": scoring.rating_class,
                   "confidence": round(confidence.value, 1),
                   "is_provisional": not confidence.is_publishable})

    # ------------------------------------------------------------------
    def _execute(self, adapters: Sequence[Any], *, stage: str,
                 base_percent: int) -> list[AdapterResult]:
        """Esegue gli adapter in parallelo con concorrenza limitata.

        `BaseAdapter.run()` non solleva mai: ogni esito, anche il fallimento,
        torna come AdapterResult.
        """
        if not adapters:
            return []
        max_workers = max(1, min(settings.scan_max_concurrent_tools, len(adapters)))
        results: list[AdapterResult] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for index, result in enumerate(pool.map(lambda a: a.run(), adapters), start=1):
                results.append(result)
                logger.info("tool_run_finished", stage=stage, **result.summary())
                self.progress(f"{stage}:{result.tool}",
                              base_percent + int(25 * index / len(adapters)))
        return results

    def _to_scorable(self, finding: CorrelatedFinding) -> ScorableFinding:
        return ScorableFinding(
            finding_id=finding.reference_code or finding.fingerprint[:12],
            finding_type=finding.finding_type, category=finding.category,
            severity=finding.severity, confidence_class=finding.confidence_class,
            ownership_status=finding.ownership_status, asset_key=finding.asset_key,
            detail=finding.detail, cve_id=finding.cve_id, cvss_score=finding.cvss_score,
            epss_score=finding.epss_score, cisa_kev=finding.cisa_kev,
            internet_facing=finding.internet_facing, event_date=finding.event_date,
            last_seen_at=finding.last_seen_at)

    def _tool_run_record(self, result: AdapterResult) -> dict[str, Any]:
        return {
            "tool_key": result.tool,
            "tool_version": result.tool_version,
            "status": result.status.value,
            "target_count": result.target_count,
            "evidence_count": len(result.evidences),
            "duration_seconds": result.duration_seconds,
            "exit_code": result.exit_code,
            "error_message": result.error_message,
            "coverage_impact": result.coverage_impact,
            "was_mocked": result.was_mocked,
            "config_snapshot": result.config_snapshot,
            "raw_output_sha256": result.raw_sha256,
            "raw_output_bytes": len(result.raw_output) if result.raw_output else 0,
        }

    def _confidence_input(self, results: Sequence[AdapterResult],
                          output: NormalizationOutput) -> ConfidenceInput:
        matrix = {entry["tool"]: entry for entry in coverage_matrix(self.request.profile)}
        summaries = [
            ToolRunSummary(
                tool_key=result.tool, status=result.status.value,
                coverage_impact=result.coverage_impact,
                coverage_weight=float(matrix.get(result.tool, {}).get("weight", 1.0)),
                areas=tuple(matrix.get(result.tool, {}).get("areas", [])),
                optional=bool(matrix.get(result.tool, {}).get("optional", False)),
                was_mocked=result.was_mocked, error_message=result.error_message)
            for result in results
        ]
        technologies = [t for asset in output.assets for t in asset.technologies]
        now = datetime.now(UTC)
        ages = [max(0.0, (now - e.observed_at).total_seconds() / 86400.0)
                for e in output.evidences]
        darkweb_tools = [s for s in summaries
                         if "darkweb_breach" in s.areas and not s.optional]
        return ConfidenceInput(
            profile=self.request.profile,
            domains_total=len(self.request.domains) or 1,
            domains_verified=len(self.request.verified_domains),
            ips_total=len(self.request.ip_addresses),
            ips_authorized=len(self.request.authorized_ips),
            assets_total=len(output.assets) or 1,
            assets_with_ownership=sum(1 for a in output.assets
                                      if a.ownership.status != "unverified"),
            technologies_total=len(technologies),
            technologies_with_version=sum(1 for t in technologies if t.get("version")),
            critical_high_findings=sum(1 for f in output.findings
                                       if f.severity in {"critical", "high"}),
            critical_high_validated=0,  # aggiornato dopo la revisione dell'analista
            distinct_sources=len({r.tool for r in results if r.status is AdapterStatus.SUCCESS}),
            tool_runs=summaries,
            optional_apis_configured=sum(1 for s in summaries if s.optional),
            optional_apis_available=sum(1 for s in summaries if s.optional and s.succeeded),
            darkweb_sources_available=sum(1 for s in darkweb_tools if s.succeeded),
            darkweb_sources_expected=max(1, len(darkweb_tools)),
            evidence_ages_days=ages,
            scan_partial=any(r.status is AdapterStatus.FAILED for r in results),
            scope_is_empty=not (self.request.domains or self.request.ip_addresses
                                or self.request.network_ranges))


# ---------------------------------------------------------------------------
def store_raw_output(scan_id: str, tool_key: str, payload: bytes,
                     base_path: Path | None = None) -> tuple[str, str]:
    """Salva l'output grezzo in uno storage protetto (accesso ristretto ai
    ruoli con `evidence:raw_read`). Restituisce (riferimento, sha256)."""
    base = base_path or settings.evidence_storage_path
    directory = base / str(scan_id)
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(payload).hexdigest()
    # Nome file derivato: nessun input utente finisce nel percorso.
    safe_tool = "".join(c for c in tool_key if c.isalnum() or c in "-_")[:40]
    path = directory / f"{safe_tool}-{digest[:16]}.raw"
    path.write_bytes(payload)
    path.chmod(0o600)
    return str(path), digest


def new_scan_id() -> str:
    return str(uuid.uuid4())
