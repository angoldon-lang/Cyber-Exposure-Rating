"""Test degli adapter con dati sintetici: nessun contatto con Internet."""
from __future__ import annotations

import pytest

from adapters.base import AdapterStatus, NormalizedEvidence
from adapters.checkdmarc_adapter import CheckDMARCAdapter
from adapters.ct_adapter import CertificateTransparencyAdapter
from adapters.dns_adapter import DNSAdapter
from adapters.hibp_adapter import HIBPAdapter
from adapters.httpx_adapter import HTTPXAdapter
from adapters.phase2 import AILAdapter, DNSTwistAdapter, EmailHeaderAdapter, NaabuAdapter, NucleiAdapter
from adapters.ransomware_live_adapter import RansomwareLiveAdapter, normalize_company_name
from adapters.registry import build_adapters, is_tool_allowed, tools_for_profile
from adapters.subfinder_adapter import SubfinderAdapter
from adapters.synthetic import build_posture
from adapters.testssl_adapter import TestSSLAdapter
from adapters.vulnintel.matcher import TechnologyObservation, evaluate_match, version_in_range
from adapters.vulnintel_adapter import VulnerabilityIntelligenceAdapter

MVP_ADAPTERS = [
    DNSAdapter, CertificateTransparencyAdapter, SubfinderAdapter, CheckDMARCAdapter,
    HTTPXAdapter, TestSSLAdapter, RansomwareLiveAdapter, HIBPAdapter,
    VulnerabilityIntelligenceAdapter, DNSTwistAdapter,
]


# --------------------------------------------------------------------------
# Contratto comune
# --------------------------------------------------------------------------
@pytest.mark.parametrize("adapter_class", MVP_ADAPTERS, ids=lambda c: c.key)
def test_adapter_produce_risultato_valido(adapter_class, adapter_context):
    result = adapter_class(adapter_context).run()
    assert result.tool == adapter_class.key
    assert isinstance(result.status, AdapterStatus)
    assert result.duration_seconds is not None
    for evidence in result.evidences:
        assert isinstance(evidence, NormalizedEvidence)
        assert evidence.fingerprint
        assert evidence.category
        assert evidence.title


@pytest.mark.parametrize("adapter_class", MVP_ADAPTERS, ids=lambda c: c.key)
def test_adapter_non_solleva_mai(adapter_class, adapter_context, monkeypatch):
    """Il fallimento di un adapter non deve fermare la scansione."""
    def esplodi(self):
        raise RuntimeError("guasto simulato del tool")

    monkeypatch.setattr(adapter_class, "mock", esplodi, raising=False)
    result = adapter_class(adapter_context).run()
    assert result.status is AdapterStatus.FAILED
    assert "guasto simulato" in (result.error_message or "")
    assert result.coverage_impact > 0


@pytest.mark.parametrize("adapter_class", MVP_ADAPTERS, ids=lambda c: c.key)
def test_output_deterministico(adapter_class, adapter_context):
    first = adapter_class(adapter_context).run()
    second = adapter_class(adapter_context).run()
    assert {e.fingerprint for e in first.evidences} == {e.fingerprint for e in second.evidences}
    assert {a.asset_key for a in first.assets} == {a.asset_key for a in second.assets}


# --------------------------------------------------------------------------
# Gate di profilo
# --------------------------------------------------------------------------
def test_profilo_passivo_esclude_i_tool_attivi():
    passivi = tools_for_profile("public_passive")
    for attivo in ("httpx", "testssl", "nuclei", "naabu", "zap_baseline"):
        assert attivo not in passivi


def test_nuclei_solo_nel_profilo_esteso():
    assert not is_tool_allowed("nuclei", "public_passive")
    assert not is_tool_allowed("nuclei", "verified_standard")
    assert is_tool_allowed("nuclei", "verified_extended")


def test_port_scanning_solo_nel_profilo_esteso():
    for tool in ("naabu", "nmap"):
        assert not is_tool_allowed(tool, "public_passive")
        assert not is_tool_allowed(tool, "verified_standard")
        assert is_tool_allowed(tool, "verified_extended")


def test_registro_blocca_tool_non_ammessi(adapter_context):
    """Richiedere esplicitamente un tool vietato non lo abilita."""
    adapter_context.profile = "public_passive"
    adapters = build_adapters(adapter_context, only=["nuclei", "naabu", "dns"])
    assert [a.key for a in adapters] == ["dns"]


def test_nuclei_rifiuta_di_partire_fuori_profilo(adapter_context):
    adapter_context.profile = "verified_standard"
    available, reason = NucleiAdapter(adapter_context).check_available()
    assert not available
    assert "Verified Extended" in reason


def test_naabu_rifiuta_di_partire_fuori_profilo(adapter_context):
    adapter_context.profile = "verified_standard"
    available, reason = NaabuAdapter(adapter_context).check_available()
    assert not available
    assert "port scanning" in reason


def test_allowlist_nuclei_esclude_i_template_pericolosi(adapter_context):
    from app.core.config import load_yaml_config

    allowlist = load_yaml_config("nuclei_allowlist")
    vietati = set(allowlist["global_constraints"]["forbidden_request_types"])
    for template in allowlist["templates"]:
        assert template["request_type"] not in vietati
        assert template["approved"] is True


# --------------------------------------------------------------------------
# Comportamenti specifici
# --------------------------------------------------------------------------
def test_checkdmarc_rileva_dmarc_mancante(adapter_context):
    adapter = CheckDMARCAdapter(adapter_context)
    posture = {
        "mx": ["mx.acme-test.example"], "provider": "Provider tradizionale",
        "provider_confidence": "probable", "spf_present": False, "spf_multiple": False,
        "spf_valid": False, "spf_lookups": 0, "dmarc_present": False,
        "dmarc_policy": None, "dmarc_rua": False, "dmarc_syntax_ok": True,
        "dkim_selectors": [], "dnssec": False, "mta_sts": False, "tls_rpt": False,
        "caa": False, "starttls": None,
    }
    tipi = {e.finding_type for e in adapter._analyse("acme-test.example", posture)}
    assert {"spf_missing", "dmarc_missing", "spoofing_possible"} <= tipi


def test_checkdmarc_non_segnala_configurazione_corretta(adapter_context):
    adapter = CheckDMARCAdapter(adapter_context)
    posture = {
        "mx": ["mx.acme-test.example"], "provider": "Microsoft 365",
        "provider_confidence": "detected", "spf_present": True, "spf_multiple": False,
        "spf_valid": True, "spf_lookups": 4, "dmarc_present": True,
        "dmarc_policy": "reject", "dmarc_subdomain_policy": "reject", "dmarc_rua": True,
        "dmarc_syntax_ok": True, "dkim_selectors": ["selector1"], "dnssec": True,
        "mta_sts": True, "tls_rpt": True, "caa": True, "starttls": True,
    }
    assert adapter._analyse("acme-test.example", posture) == []


def test_hibp_saltato_senza_api_key(adapter_context):
    """Connettore opzionale a pagamento: assente => skipped, non failed."""
    adapter_context.connector_config = {}
    result = HIBPAdapter(adapter_context).run()
    assert result.status is AdapterStatus.SKIPPED
    assert "opzionale" in (result.error_message or "")


def test_ail_predisposto_ma_non_attivo(adapter_context):
    result = AILAdapter(adapter_context).run()
    assert result.status is AdapterStatus.SKIPPED
    assert "fase 3" in (result.error_message or "")


def test_email_header_saltato_senza_header(adapter_context):
    result = EmailHeaderAdapter(adapter_context).run()
    assert result.status is AdapterStatus.SKIPPED


def test_email_header_analizzato_e_sanitizzato(adapter_context):
    adapter_context.email_header = (
        "Received: from mail.acme-test.example (203.0.113.10) by "
        "acme.mail.protection.outlook.com with Microsoft SMTP Server "
        "(version=TLS1_2)\r\n"
        "Authentication-Results: spf=fail (sender IP is 198.51.100.7) "
        "smtp.mailfrom=acme-test.example; dkim=fail; dmarc=fail\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; s=selector1; d=acme-test.example;\r\n"
        "From: Mario Rossi <mario@acme-test.example>\r\n"
        "Subject: fattura\r\n\r\nCorpo del messaggio che non deve essere conservato."
    )
    parsed = EmailHeaderAdapter(adapter_context).analyse(adapter_context.email_header)
    assert parsed["spf_result"] == "fail"
    assert parsed["dmarc_result"] == "fail"
    assert parsed["provider"] == "Microsoft 365"
    assert parsed["dkim_selectors"] == ["selector1"]
    # Corpo e oggetto non vengono conservati.
    assert "subject" not in parsed["headers_kept"]
    assert "Corpo del messaggio" not in str(parsed)


def test_dnstwist_non_dichiara_malevolo_un_dominio_simile(adapter_context):
    adapter = DNSTwistAdapter(adapter_context)
    evidence = adapter._build("acme-test.example", {
        "domain": "acme-tests.example", "has_mx": False, "technique": "typosquatting"})
    assert evidence.finding_type == "lookalike_domain_registered"
    assert evidence.confidence_class == "probable"
    assert "non implica intento malevolo" in evidence.description


def test_dnstwist_alza_la_severita_con_mx(adapter_context):
    adapter = DNSTwistAdapter(adapter_context)
    evidence = adapter._build("acme-test.example", {
        "domain": "acme-secure.example", "has_mx": True, "technique": "aggiunta di parola"})
    assert evidence.finding_type == "lookalike_domain_with_mx"
    assert evidence.severity == "high"


def test_ransomware_corrispondenza_debole_resta_probabile(adapter_context):
    adapter = RansomwareLiveAdapter(adapter_context)
    evidence = adapter._build({
        "victim": "ACME Diversa", "group_name": "lockbit3",
        "published": "2026-06-01T00:00:00Z", "match_ratio": 0.82, "domain_hit": False})
    assert evidence.confidence_class == "probable"
    assert "richiede validazione" in evidence.description


def test_normalizzazione_ragione_sociale():
    assert normalize_company_name("ACME Demo S.p.A.") == "acme demo"
    assert normalize_company_name("Brescia Logistica S.r.l.") == "brescia logistica"


# --------------------------------------------------------------------------
# Correlazione CVE
# --------------------------------------------------------------------------
def test_cve_confermata_con_prodotto_e_versione():
    match = evaluate_match(
        TechnologyObservation("WordPress", "5.8.2", "httpx-tech-detect", "web:x", 0.9),
        {"product": "wordpress", "affected_below": "5.9.0"})
    assert match.matched
    assert match.confidence_class == "confirmed"


def test_cve_non_confermata_senza_versione():
    """La sola presenza del prodotto non implica la vulnerabilita'."""
    match = evaluate_match(
        TechnologyObservation("WordPress", None, "httpx-tech-detect", "web:x", 0.9),
        {"product": "wordpress", "affected_below": "5.9.0"})
    assert not match.matched
    assert match.confidence_class == "inferred"


def test_cve_non_confermata_da_header_generico():
    match = evaluate_match(
        TechnologyObservation("WordPress", "5.8.2", "server", "web:x", 0.9),
        {"product": "wordpress", "affected_below": "5.9.0"})
    assert not match.matched
    assert "header generico" in match.reason


def test_cve_non_confermata_con_fingerprint_debole():
    match = evaluate_match(
        TechnologyObservation("WordPress", "5.8.2", "httpx-tech-detect", "web:x", 0.4),
        {"product": "wordpress", "affected_below": "5.9.0"})
    assert not match.matched
    assert "attendibilita'" in match.reason


def test_versione_fuori_range_non_vulnerabile():
    match = evaluate_match(
        TechnologyObservation("WordPress", "6.4.1", "httpx-tech-detect", "web:x", 0.9),
        {"product": "wordpress", "affected_below": "5.9.0"})
    assert not match.matched
    assert match.confidence_class == "informational"


@pytest.mark.parametrize(("version", "below", "expected"), [
    ("1.0.0", "2.0.0", True), ("2.0.0", "2.0.0", False), ("2.0.1", "2.0.0", False),
    ("1.9", "2.0.0", True), (None, "2.0.0", None), ("1.0.0", None, True),
])
def test_confronto_versioni(version, below, expected):
    assert version_in_range(version, below) is expected


# --------------------------------------------------------------------------
# Dati sintetici
# --------------------------------------------------------------------------
def test_posture_sintetica_deterministica():
    a = build_posture(42, "acme-test.example", "ACME", severity_bias=0.5)
    b = build_posture(42, "acme-test.example", "ACME", severity_bias=0.5)
    assert a.subdomains == b.subdomains
    assert a.vulnerabilities == b.vulnerabilities
    assert a.email == b.email


def test_posture_usa_solo_reti_di_documentazione():
    """I dati sintetici non devono mai contenere indirizzi instradabili."""
    import ipaddress

    posture = build_posture(7, "acme-test.example", "ACME", severity_bias=0.9)
    documentazione = [ipaddress.ip_network("203.0.113.0/24"),
                      ipaddress.ip_network("198.51.100.0/24")]
    for address in posture.ip_addresses:
        ip = ipaddress.ip_address(address)
        assert any(ip in net for net in documentazione)


def test_severita_maggiore_produce_piu_problemi():
    pulita = build_posture(11, "acme-test.example", "ACME", severity_bias=0.05)
    compromessa = build_posture(11, "acme-test.example", "ACME", severity_bias=0.95)
    assert len(compromessa.subdomains) >= len(pulita.subdomains)
