"""Contratto comune degli adapter.

Ogni adapter e' indipendente: il suo fallimento riduce la copertura
(e quindi il confidence score) ma non interrompe mai la scansione.
"""
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from app.core.redaction import sanitize_structure, sanitize_text
from app.models.enums import ConfidenceClass, OwnershipStatus, ScoreCategoryKey, Severity, ToolRunStatus
from app.services.scope_guard import ScopeGuard


class AdapterStatus(str, Enum):
    SUCCESS = ToolRunStatus.SUCCESS.value
    PARTIAL = ToolRunStatus.PARTIAL.value
    FAILED = ToolRunStatus.FAILED.value
    SKIPPED = ToolRunStatus.SKIPPED.value


@dataclass
class NormalizedEvidence:
    """Evidenza normalizzata prodotta da un adapter (sezione 11).

    Tutti i campi testuali sono sanitizzati: nessun contenuto raccolto da
    Internet raggiunge il database o il modello AI in forma grezza.
    """

    tool: str
    target: str
    finding_type: str
    title: str
    category: str
    severity: str = Severity.INFO.value
    confidence_class: str = ConfidenceClass.INFERRED.value
    ownership_status: str = OwnershipStatus.UNVERIFIED.value
    description: str | None = None
    detail: str | None = None
    data_source: str = "unknown"
    source_url: str | None = None
    tool_version: str | None = None
    asset_key: str | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_date: datetime | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    cisa_kev: bool = False
    raw_evidence_ref: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.title = sanitize_text(self.title, 512)
        if self.description:
            self.description = sanitize_text(self.description, 4000)
        if self.detail:
            self.detail = sanitize_text(self.detail, 512)
        if self.source_url:
            self.source_url = sanitize_text(self.source_url, 1024)
        self.attributes = sanitize_structure(self.attributes)

    @property
    def fingerprint(self) -> str:
        """Identita' stabile dell'evidenza: base della deduplicazione."""
        parts = [
            (self.asset_key or self.target).lower(),
            self.finding_type,
            (self.detail or "").lower(),
            (self.cve_id or "").upper(),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["observed_at"] = self.observed_at.isoformat()
        data["event_date"] = self.event_date.isoformat() if self.event_date else None
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class DiscoveredAsset:
    """Asset scoperto da un adapter. L'ownership definitiva e' decisa dal
    servizio `ownership`, mai dall'adapter."""

    asset_key: str
    asset_type: str
    display_name: str
    discovered_by: str
    attributes: dict[str, Any] = field(default_factory=dict)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    is_internet_facing: bool = True

    def __post_init__(self) -> None:
        self.asset_key = self.asset_key.strip().lower()
        self.display_name = sanitize_text(self.display_name, 512)
        self.attributes = sanitize_structure(self.attributes)


@dataclass
class AdapterResult:
    tool: str
    status: AdapterStatus
    evidences: list[NormalizedEvidence] = field(default_factory=list)
    assets: list[DiscoveredAsset] = field(default_factory=list)
    tool_version: str | None = None
    error_message: str | None = None
    # Quanto pesa il fallimento sulla copertura (0.0 nessun impatto, 1.0 totale).
    coverage_impact: float = 0.0
    duration_seconds: float | None = None
    exit_code: int | None = None
    was_mocked: bool = False
    raw_output: bytes | None = None
    config_snapshot: dict[str, Any] = field(default_factory=dict)
    target_count: int = 0

    @property
    def raw_sha256(self) -> str | None:
        return hashlib.sha256(self.raw_output).hexdigest() if self.raw_output else None

    def summary(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status.value,
            "evidences": len(self.evidences),
            "assets": len(self.assets),
            "error": self.error_message,
            "coverage_impact": self.coverage_impact,
            "mocked": self.was_mocked,
        }


@dataclass
class AdapterContext:
    """Tutto cio' che un adapter puo' vedere. Non ha accesso al database
    ne' puo' eseguire comandi al di fuori del ToolRunner."""

    scan_id: str
    tenant_id: str
    company_id: str
    company_name: str
    profile: str
    scope_guard: ScopeGuard
    domains: list[str] = field(default_factory=list)
    verified_domains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    network_ranges: list[str] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    email_header: str | None = None
    dkim_selectors: list[str] = field(default_factory=list)
    known_subdomains: list[str] = field(default_factory=list)
    # Indirizzi e-mail emersi dalla fase di discovery (SpiderFoot e simili).
    # Sono separati da `email_addresses`, che contiene quelli dichiarati: la
    # provenienza cambia l'affidabilita' e va conservata.
    discovered_emails: list[str] = field(default_factory=list)
    web_targets: list[str] = field(default_factory=list)
    mock_mode: bool = True
    tool_config: dict[str, Any] = field(default_factory=dict)
    connector_config: dict[str, Any] = field(default_factory=dict)

    def seed(self, extra: str = "") -> int:
        """Seed deterministico per i dati sintetici del mock mode."""
        material = f"{self.company_id}:{self.company_name}:{extra}"
        return int(hashlib.sha256(material.encode()).hexdigest()[:12], 16)

    @property
    def severity_bias(self) -> float:
        """Quanto e' compromessa l'azienda sintetica in mock mode, in [0,1].

        Usato solo dai generatori di dati sintetici: non ha alcun effetto
        sul percorso reale ne' sul motore di scoring.
        """
        raw = self.connector_config.get("synthetic", {}).get("severity_bias", 0.5)
        return max(0.0, min(1.0, float(raw)))


class BaseAdapter(ABC):
    """Classe base di ogni integrazione.

    Contratto:
      * `key`            identificativo usato in tool_profiles.yaml
      * `is_passive`     se puo' girare nel profilo Public Passive
      * `check_available` verifica la disponibilita' del tool
      * `run`            esegue e restituisce un AdapterResult normalizzato
      * `mock`           produce dati sintetici deterministici
    """

    key: str = "base"
    display_name: str = "Base adapter"
    is_passive: bool = True
    coverage_areas: tuple[str, ...] = ()
    default_timeout: int = 300
    optional: bool = False

    def __init__(self, context: AdapterContext) -> None:
        self.context = context
        self.config: dict[str, Any] = context.tool_config.get(self.key, {}) or {}

    # ------------------------------------------------------------------
    @abstractmethod
    def check_available(self) -> tuple[bool, str]:
        """(disponibile, motivo). Un tool non disponibile produce SKIPPED."""

    @abstractmethod
    def execute(self) -> AdapterResult:
        """Esecuzione reale. Non chiamare direttamente: usare `run()`."""

    def mock(self) -> AdapterResult:
        """Dati sintetici deterministici. Nessun contatto di rete."""
        return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                             error_message="mock non implementato per questo adapter",
                             coverage_impact=self.coverage_weight, was_mocked=True)

    # ------------------------------------------------------------------
    @property
    def coverage_weight(self) -> float:
        return float(self.config.get("coverage_weight", 1.0))

    def run(self) -> AdapterResult:
        """Punto d'ingresso unico: cattura ogni eccezione e la converte in
        un risultato FAILED con impatto sulla copertura."""
        started = datetime.now(UTC)
        try:
            if self.context.mock_mode:
                result = self.mock()
            else:
                available, reason = self.check_available()
                if not available:
                    result = AdapterResult(
                        tool=self.key, status=AdapterStatus.SKIPPED,
                        error_message=reason, coverage_impact=self.coverage_weight)
                else:
                    result = self.execute()
        except Exception as exc:  # noqa: BLE001 - nessun adapter puo' bloccare la scansione
            result = AdapterResult(
                tool=self.key, status=AdapterStatus.FAILED,
                error_message=sanitize_text(f"{type(exc).__name__}: {exc}", 1000),
                coverage_impact=self.coverage_weight)
        if result.duration_seconds is None:
            result.duration_seconds = (datetime.now(UTC) - started).total_seconds()
        result.config_snapshot.setdefault("profile", self.context.profile)
        result.config_snapshot.setdefault("mock_mode", self.context.mock_mode)
        return result

    # Utility condivise -------------------------------------------------
    @staticmethod
    def dump_json(payload: Any) -> bytes:
        return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")

    def category(self, key: ScoreCategoryKey | str) -> str:
        return key.value if isinstance(key, ScoreCategoryKey) else key
