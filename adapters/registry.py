"""Registro degli adapter e gate di profilo.

Un adapter e' eseguibile solo se elencato nel profilo richiesto in
`config/tool_profiles.yaml`. Il registro e' l'unico punto in cui gli adapter
vengono istanziati: nessun altro modulo li costruisce direttamente.
"""
from __future__ import annotations

from typing import Iterable

from adapters.base import AdapterContext, BaseAdapter
from adapters.checkdmarc_adapter import CheckDMARCAdapter
from adapters.ct_adapter import CertificateTransparencyAdapter
from adapters.dns_adapter import DNSAdapter
from adapters.hibp_adapter import HIBPAdapter
from adapters.httpx_adapter import HTTPXAdapter
from adapters.phase2 import (
    AILAdapter,
    AmassAdapter,
    DNSTwistAdapter,
    EmailHeaderAdapter,
    NaabuAdapter,
    NucleiAdapter,
    ZAPBaselineAdapter,
)
from adapters.ransomware_live_adapter import RansomwareLiveAdapter
from adapters.rdap_adapter import RDAPAdapter
from adapters.spiderfoot_adapter import SpiderFootAdapter
from adapters.subfinder_adapter import SubfinderAdapter
from adapters.testssl_adapter import TestSSLAdapter
from adapters.vulnintel_adapter import VulnerabilityIntelligenceAdapter
from app.core.config import load_yaml_config
from app.core.logging import get_logger

logger = get_logger(__name__)

ADAPTER_CLASSES: dict[str, type[BaseAdapter]] = {
    # --- Fase 1 (MVP) ---
    DNSAdapter.key: DNSAdapter,
    RDAPAdapter.key: RDAPAdapter,
    CertificateTransparencyAdapter.key: CertificateTransparencyAdapter,
    SubfinderAdapter.key: SubfinderAdapter,
    SpiderFootAdapter.key: SpiderFootAdapter,
    CheckDMARCAdapter.key: CheckDMARCAdapter,
    HTTPXAdapter.key: HTTPXAdapter,
    TestSSLAdapter.key: TestSSLAdapter,
    RansomwareLiveAdapter.key: RansomwareLiveAdapter,
    HIBPAdapter.key: HIBPAdapter,
    VulnerabilityIntelligenceAdapter.key: VulnerabilityIntelligenceAdapter,
    # --- Fase 2 ---
    AmassAdapter.key: AmassAdapter,
    ZAPBaselineAdapter.key: ZAPBaselineAdapter,
    NucleiAdapter.key: NucleiAdapter,
    NaabuAdapter.key: NaabuAdapter,
    DNSTwistAdapter.key: DNSTwistAdapter,
    EmailHeaderAdapter.key: EmailHeaderAdapter,
    # --- Fase 3 ---
    AILAdapter.key: AILAdapter,
}

# `epss` e' servito dallo stesso adapter di `kev`: una sola esecuzione.
TOOL_ALIASES: dict[str, str] = {
    "epss": "kev",                 # stesso adapter di KEV: una sola esecuzione
    "dnstwist_passive": "dnstwist",
    "nmap": "naabu",               # Naabu e' preferito a Nmap per la licenza (NPSL)
    "amass": "amass_passive",      # nel prodotto si usa solo la modalita' passiva
}


class ProfileNotFoundError(ValueError):
    pass


def load_profiles() -> dict:
    return load_yaml_config("tool_profiles")


def profile_definition(profile_key: str) -> dict:
    profiles = load_profiles().get("profiles", {})
    if profile_key not in profiles:
        raise ProfileNotFoundError(f"Profilo di scansione sconosciuto: {profile_key}")
    return profiles[profile_key]


def tools_for_profile(profile_key: str) -> list[str]:
    """Elenco ordinato e deduplicato dei tool ammessi dal profilo."""
    declared = profile_definition(profile_key).get("tools", [])
    resolved: list[str] = []
    for tool in declared:
        canonical = TOOL_ALIASES.get(tool, tool)
        if canonical in ADAPTER_CLASSES and canonical not in resolved:
            resolved.append(canonical)
        elif canonical not in ADAPTER_CLASSES:
            logger.warning("tool_without_adapter", tool=tool, profile=profile_key)
    return resolved


def is_tool_allowed(tool_key: str, profile_key: str) -> bool:
    return TOOL_ALIASES.get(tool_key, tool_key) in tools_for_profile(profile_key)


def build_adapters(context: AdapterContext,
                   only: Iterable[str] | None = None) -> list[BaseAdapter]:
    """Istanzia gli adapter ammessi dal profilo del contesto.

    Il gate di profilo e' applicato QUI e non e' aggirabile da `only`:
    richiedere un tool non ammesso lo esclude silenziosamente e registra
    l'evento.
    """
    allowed = tools_for_profile(context.profile)
    requested = [TOOL_ALIASES.get(t, t) for t in only] if only else allowed
    adapters: list[BaseAdapter] = []
    for tool_key in requested:
        if tool_key not in allowed:
            logger.warning("tool_blocked_by_profile", tool=tool_key, profile=context.profile)
            continue
        adapter_class = ADAPTER_CLASSES[tool_key]
        # Nel profilo passivo nessun adapter attivo puo' essere istanziato,
        # anche se per errore comparisse nella lista del profilo.
        if context.profile == "public_passive" and not adapter_class.is_passive:
            logger.error("active_tool_in_passive_profile", tool=tool_key)
            continue
        adapters.append(adapter_class(context))
    return adapters


def tool_metadata(tool_key: str) -> dict:
    canonical = TOOL_ALIASES.get(tool_key, tool_key)
    return load_profiles().get("tools", {}).get(canonical, {})


def build_tool_config(profile_key: str) -> dict[str, dict]:
    """Configurazione per-tool consegnata all'AdapterContext."""
    tools = load_profiles().get("tools", {})
    config: dict[str, dict] = {}
    for tool_key in tools_for_profile(profile_key):
        config[tool_key] = dict(tools.get(tool_key, {}))
    return config


def coverage_matrix(profile_key: str) -> list[dict]:
    """Matrice di copertura: quali aree copre ogni tool del profilo.

    Alimenta il calcolo della confidence e la sezione «limiti della
    valutazione» del report.
    """
    tools = load_profiles().get("tools", {})
    matrix: list[dict] = []
    for tool_key in tools_for_profile(profile_key):
        definition = tools.get(tool_key, {})
        matrix.append({
            "tool": tool_key,
            "label": definition.get("label", tool_key),
            "areas": definition.get("coverage_areas", []),
            "weight": float(definition.get("coverage_weight", 1.0)),
            "optional": bool(definition.get("optional", False)),
            "commercial": bool(definition.get("commercial", False)),
            "requires_api_key": bool(definition.get("requires_api_key", False)),
            "phase": definition.get("phase", 1),
        })
    return matrix
