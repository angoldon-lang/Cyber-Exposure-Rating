"""Generatore deterministico di dati sintetici per mock mode, demo e test.

Nessun contatto di rete. A parita' di `company_id` la posture generata e'
identica: le scansioni demo sono riproducibili e i test deterministici.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

# Reti riservate alla documentazione (RFC 5737): mai instradabili.
SYNTHETIC_NET_A = "203.0.113."
SYNTHETIC_NET_B = "198.51.100."

SUBDOMAIN_POOL = [
    "www", "mail", "webmail", "vpn", "portal", "intranet", "api", "app",
    "shop", "blog", "dev", "staging", "test", "old", "legacy", "cdn",
    "files", "docs", "support", "crm", "erp", "backup", "git", "jenkins",
    "grafana", "monitor", "remote", "owa", "autodiscover", "sso",
]

TECH_POOL = [
    {"name": "nginx", "version": "1.18.0", "eol": True},
    {"name": "Apache httpd", "version": "2.4.41", "eol": False},
    {"name": "WordPress", "version": "5.8.2", "eol": True},
    {"name": "PHP", "version": "7.4.3", "eol": True},
    {"name": "Microsoft-IIS", "version": "8.5", "eol": True},
    {"name": "OpenSSL", "version": None, "eol": False},
    {"name": "React", "version": None, "eol": False},
    {"name": "Cloudflare", "version": None, "eol": False},
]

RANSOMWARE_GROUPS = ["lockbit3", "blackcat", "cl0p", "play", "akira", "8base"]

SYNTHETIC_CVES = [
    {"cve": "CVE-2023-27350", "cvss": 9.8, "epss": 0.9741, "kev": True,
     "product": "PaperCut NG", "title": "Bypass dell'autenticazione in PaperCut"},
    {"cve": "CVE-2021-44228", "cvss": 10.0, "epss": 0.9756, "kev": True,
     "product": "Apache Log4j", "title": "Esecuzione di codice remoto in Log4j (Log4Shell)"},
    {"cve": "CVE-2022-40684", "cvss": 9.8, "epss": 0.9724, "kev": True,
     "product": "Fortinet FortiOS", "title": "Bypass dell'autenticazione su interfaccia amministrativa"},
    {"cve": "CVE-2023-4966", "cvss": 9.4, "epss": 0.9683, "kev": True,
     "product": "Citrix NetScaler", "title": "Divulgazione di informazioni sensibili (CitrixBleed)"},
    {"cve": "CVE-2022-22965", "cvss": 9.8, "epss": 0.9752, "kev": True,
     "product": "Spring Framework", "title": "Esecuzione di codice remoto (Spring4Shell)"},
    {"cve": "CVE-2021-34473", "cvss": 9.8, "epss": 0.9744, "kev": True,
     "product": "Microsoft Exchange", "title": "Esecuzione di codice remoto (ProxyShell)"},
    {"cve": "CVE-2023-38831", "cvss": 7.8, "epss": 0.9612, "kev": True,
     "product": "RARLAB WinRAR", "title": "Esecuzione di codice tramite archivio manipolato"},
    {"cve": "CVE-2020-1472", "cvss": 10.0, "epss": 0.9748, "kev": True,
     "product": "Microsoft Netlogon", "title": "Elevazione di privilegi (Zerologon)"},
    {"cve": "CVE-2022-1388", "cvss": 9.8, "epss": 0.9739, "kev": True,
     "product": "F5 BIG-IP", "title": "Bypass dell'autenticazione su iControl REST"},
    {"cve": "CVE-2019-11510", "cvss": 10.0, "epss": 0.9750, "kev": True,
     "product": "Pulse Secure VPN", "title": "Lettura arbitraria di file"},
    {"cve": "CVE-2023-35078", "cvss": 10.0, "epss": 0.9718, "kev": True,
     "product": "Ivanti EPMM", "title": "Bypass dell'autenticazione su API remota"},
    {"cve": "CVE-2024-21762", "cvss": 9.8, "epss": 0.9407, "kev": True,
     "product": "Fortinet FortiOS SSL VPN", "title": "Scrittura fuori dai limiti in SSL VPN"},
    {"cve": "CVE-2023-46747", "cvss": 9.8, "epss": 0.9673, "kev": True,
     "product": "F5 BIG-IP", "title": "Bypass dell'autenticazione nella UI di gestione"},
    {"cve": "CVE-2022-26134", "cvss": 9.8, "epss": 0.9745, "kev": True,
     "product": "Atlassian Confluence", "title": "Injection OGNL con esecuzione di codice"},
    {"cve": "CVE-2021-26855", "cvss": 9.8, "epss": 0.9754, "kev": True,
     "product": "Microsoft Exchange", "title": "Server-side request forgery (ProxyLogon)"},
    {"cve": "CVE-2018-13379", "cvss": 9.8, "epss": 0.9741, "kev": True,
     "product": "Fortinet FortiOS", "title": "Path traversal nel portale SSL VPN"},
    {"cve": "CVE-2023-3519", "cvss": 9.8, "epss": 0.9691, "kev": True,
     "product": "Citrix ADC", "title": "Esecuzione di codice remoto non autenticata"},
    {"cve": "CVE-2024-3400", "cvss": 10.0, "epss": 0.9432, "kev": True,
     "product": "Palo Alto PAN-OS", "title": "Command injection in GlobalProtect"},
    {"cve": "CVE-2022-30190", "cvss": 7.8, "epss": 0.9587, "kev": True,
     "product": "Microsoft Windows MSDT", "title": "Esecuzione di codice remoto (Follina)"},
    {"cve": "CVE-2017-0144", "cvss": 8.1, "epss": 0.9744, "kev": True,
     "product": "Microsoft SMBv1", "title": "Esecuzione di codice remoto (EternalBlue)"},
    {"cve": "CVE-2020-0796", "cvss": 10.0, "epss": 0.9723, "kev": True,
     "product": "Microsoft SMBv3", "title": "Esecuzione di codice remoto (SMBGhost)"},
    {"cve": "CVE-2023-20198", "cvss": 10.0, "epss": 0.9438, "kev": True,
     "product": "Cisco IOS XE", "title": "Creazione di account privilegiati via web UI"},
    {"cve": "CVE-2021-40539", "cvss": 9.8, "epss": 0.9704, "kev": True,
     "product": "Zoho ManageEngine ADSelfService", "title": "Bypass dell'autenticazione REST API"},
    {"cve": "CVE-2019-19781", "cvss": 9.8, "epss": 0.9752, "kev": True,
     "product": "Citrix ADC", "title": "Directory traversal con esecuzione di codice"},
    {"cve": "CVE-2022-41040", "cvss": 8.8, "epss": 0.9691, "kev": True,
     "product": "Microsoft Exchange", "title": "Server-side request forgery (ProxyNotShell)"},
]

BREACH_POOL = [
    {"name": "LinkedIn", "year": 2021, "classes": ["indirizzi e-mail", "nomi", "profili professionali"]},
    {"name": "Adobe", "year": 2013, "classes": ["indirizzi e-mail", "password (hash deboli)"]},
    {"name": "Dropbox", "year": 2012, "classes": ["indirizzi e-mail", "password (hash)"]},
    {"name": "Collection #1", "year": 2019, "classes": ["indirizzi e-mail", "password"]},
    {"name": "MyFitnessPal", "year": 2018, "classes": ["indirizzi e-mail", "username"]},
    {"name": "Zynga", "year": 2019, "classes": ["indirizzi e-mail", "username"]},
]


@dataclass
class SyntheticPosture:
    """Postura sintetica completa di un'azienda demo."""

    domain: str
    company_name: str
    subdomains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    web_services: list[dict[str, Any]] = field(default_factory=list)
    email: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    breaches: list[dict[str, Any]] = field(default_factory=list)
    # Indirizzi dell'azienda sintetica e violazioni in cui compaiono. E' un
    # dato a se' e non un derivato di `breaches`: le fonti che lo leggono
    # devono vedere sempre la stessa esposizione, altrimenti in demo la
    # sezione resta vuota a seconda del seed e la funzione sembra rotta.
    email_exposures: list[dict[str, Any]] = field(default_factory=list)
    stealer_logs: list[dict[str, Any]] = field(default_factory=list)
    ransomware: list[dict[str, Any]] = field(default_factory=list)
    lookalikes: list[dict[str, Any]] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    darkweb_mentions: list[dict[str, Any]] = field(default_factory=list)
    certificate: dict[str, Any] = field(default_factory=dict)
    registrar: dict[str, Any] = field(default_factory=dict)


def _rng(seed: int, salt: str = "") -> random.Random:
    return random.Random(f"{seed}:{salt}")


def build_posture(seed: int, domain: str, company_name: str, *, severity_bias: float = 0.5) -> SyntheticPosture:
    """Costruisce una postura sintetica riproducibile.

    `severity_bias` in [0,1] regola quanto e' compromessa l'azienda demo:
    0 = quasi pulita, 1 = fortemente esposta.
    """
    rng = _rng(seed, "posture")
    now = datetime.now(UTC)
    posture = SyntheticPosture(domain=domain, company_name=company_name)

    # --- sottodomini -------------------------------------------------
    count = 6 + int(rng.random() * 14 * (0.5 + severity_bias))
    chosen = rng.sample(SUBDOMAIN_POOL, min(count, len(SUBDOMAIN_POOL)))
    posture.subdomains = sorted(f"{label}.{domain}" for label in chosen)

    # --- indirizzi IP ------------------------------------------------
    ip_count = max(2, min(8, len(posture.subdomains) // 3))
    posture.ip_addresses = [f"{SYNTHETIC_NET_A}{10 + i}" for i in range(ip_count)]

    # --- servizi web -------------------------------------------------
    for index, host in enumerate(posture.subdomains[:12]):
        r = _rng(seed, f"web:{host}")
        tech = r.sample(TECH_POOL, r.randint(1, 3))
        posture.web_services.append({
            "host": host,
            "url": f"https://{host}",
            "status_code": r.choice([200, 200, 200, 301, 302, 403, 404]),
            "title": f"{company_name} - {host.split('.')[0]}",
            "ip": posture.ip_addresses[index % len(posture.ip_addresses)],
            "server": tech[0]["name"],
            "technologies": tech,
            "https": r.random() > 0.15 * (1 + severity_bias),
            "hsts": r.random() > 0.45 + 0.2 * severity_bias,
            "csp": r.random() > 0.60 + 0.2 * severity_bias,
            "x_frame_options": r.random() > 0.40 + 0.2 * severity_bias,
            "x_content_type_options": r.random() > 0.35 + 0.2 * severity_bias,
            "referrer_policy": r.random() > 0.55,
            "permissions_policy": r.random() > 0.75,
            "cookie_secure": r.random() > 0.35 + 0.2 * severity_bias,
            "cookie_httponly": r.random() > 0.30,
            "cookie_samesite": r.random() > 0.50,
            "directory_listing": r.random() < 0.08 * (1 + severity_bias),
            "version_disclosure": r.random() < 0.35 * (1 + severity_bias),
            "mixed_content": r.random() < 0.12 * (1 + severity_bias),
            "cors_wildcard": r.random() < 0.10 * (1 + severity_bias),
            "security_txt": r.random() > 0.85,
            "is_admin_panel": host.split(".")[0] in {"portal", "intranet", "crm", "erp", "jenkins", "grafana", "owa"},
            "is_non_production": host.split(".")[0] in {"dev", "staging", "test", "old", "legacy"},
            "cdn": r.choice([None, None, None, "cloudflare", "akamai"]),
            "waf": r.choice([None, None, "cloudflare", "aws-waf"]),
        })

    # --- certificato TLS ---------------------------------------------
    cert_rng = _rng(seed, "cert")
    days = cert_rng.choice([-12, 5, 21, 45, 120, 240, 320])
    posture.certificate = {
        "subject": f"CN={domain}",
        "issuer": cert_rng.choice(["Let's Encrypt R3", "DigiCert TLS RSA SHA256 2020 CA1", "Sectigo RSA DV"]),
        "not_after": (now + timedelta(days=days)).isoformat(),
        "days_to_expiry": days,
        "sans": [domain, f"www.{domain}"],
        "hostname_match": cert_rng.random() > 0.1,
        "protocols": {
            "TLSv1.3": True,
            "TLSv1.2": True,
            "TLSv1.1": cert_rng.random() < 0.25 * (1 + severity_bias),
            "TLSv1.0": cert_rng.random() < 0.20 * (1 + severity_bias),
            "SSLv3": cert_rng.random() < 0.05 * (1 + severity_bias),
        },
        "weak_ciphers": ([{"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "reason": "3DES"}]
                         if cert_rng.random() < 0.3 * (1 + severity_bias) else []),
    }

    # --- posta elettronica -------------------------------------------
    mail_rng = _rng(seed, "mail")
    provider = mail_rng.choice(["Microsoft 365", "Google Workspace", "Provider tradizionale", "Secure Email Gateway"])
    has_spf = mail_rng.random() > 0.10 * (1 + severity_bias)
    has_dmarc = mail_rng.random() > 0.30 * (1 + severity_bias)
    posture.email = {
        "provider": provider,
        "provider_confidence": "detected" if provider in {"Microsoft 365", "Google Workspace"} else "probable",
        "mx": [f"mx1.{domain}", f"mx2.{domain}"] if provider == "Provider tradizionale"
              else [f"{domain.replace('.', '-')}.mail.protection.outlook.com"],
        "spf_present": has_spf,
        "spf_record": f"v=spf1 include:_spf.{domain} ~all" if has_spf else None,
        "spf_multiple": has_spf and mail_rng.random() < 0.08,
        "spf_lookups": mail_rng.randint(4, 14),
        "spf_valid": has_spf and mail_rng.random() > 0.15,
        "dmarc_present": has_dmarc,
        "dmarc_policy": mail_rng.choice(["none", "none", "quarantine", "reject"]) if has_dmarc else None,
        "dmarc_subdomain_policy": mail_rng.choice([None, "none", "reject"]) if has_dmarc else None,
        "dmarc_rua": mail_rng.random() > 0.45 if has_dmarc else False,
        "dmarc_syntax_ok": mail_rng.random() > 0.10 if has_dmarc else True,
        "dkim_selectors": ["selector1", "selector2"] if provider == "Microsoft 365"
                          else (["google"] if provider == "Google Workspace" else []),
        "dnssec": mail_rng.random() > 0.70,
        "mta_sts": mail_rng.random() > 0.80,
        "tls_rpt": mail_rng.random() > 0.85,
        "bimi": mail_rng.random() > 0.95,
        "dane": mail_rng.random() > 0.92,
        "caa": mail_rng.random() > 0.65,
        "starttls": mail_rng.random() > 0.12 * (1 + severity_bias),
    }

    # --- vulnerabilita' ----------------------------------------------
    vuln_rng = _rng(seed, "vuln")
    vuln_count = int(vuln_rng.random() * 4 * severity_bias)
    for entry in vuln_rng.sample(SYNTHETIC_CVES, min(vuln_count, len(SYNTHETIC_CVES))):
        host = vuln_rng.choice(posture.subdomains) if posture.subdomains else domain
        posture.vulnerabilities.append({**entry, "host": host, "version_known": vuln_rng.random() > 0.35})

    # --- breach / stealer / ransomware --------------------------------
    dw_rng = _rng(seed, "darkweb")
    for entry in dw_rng.sample(BREACH_POOL, min(int(dw_rng.random() * 4 * (0.5 + severity_bias)), len(BREACH_POOL))):
        posture.breaches.append({
            **entry,
            "account_count": dw_rng.randint(1, 60),
            "breach_date": datetime(entry["year"], dw_rng.randint(1, 12), dw_rng.randint(1, 28), tzinfo=UTC).isoformat(),
            "is_recent": (now.year - entry["year"]) <= 3,
        })
    # --- esposizione degli indirizzi e-mail ---------------------------
    email_rng = _rng(seed, "email_exposure")
    for indice, locale in enumerate(("mario.rossi", "info", "amministrazione")):
        # Il primo indirizzo e' sempre esposto: senza almeno un caso la demo
        # non mostrerebbe mai la verifica sulle violazioni.
        quante = max(1 - indice, 0) + int(email_rng.random() * 3 * (0.5 + severity_bias))
        if not quante:
            continue
        for violazione in email_rng.sample(BREACH_POOL, min(quante, len(BREACH_POOL))):
            posture.email_exposures.append({
                "address": f"{locale}@{domain}",
                "breach": violazione["name"],
                "year": violazione["year"],
                "classes": list(violazione["classes"]),
                "records": email_rng.randint(10_000, 5_000_000),
            })

    if dw_rng.random() < 0.35 * (1 + severity_bias):
        posture.stealer_logs.append({
            "account_count": dw_rng.randint(1, 12),
            "observed_at": (now - timedelta(days=dw_rng.randint(5, 220))).isoformat(),
            "source": "commodity infostealer log (fonte aggregata)",
            "affected_services": dw_rng.sample(["VPN", "webmail", "CRM", "portale clienti"], 2),
        })
    if dw_rng.random() < 0.12 * (1 + severity_bias):
        posture.ransomware.append({
            "group": dw_rng.choice(RANSOMWARE_GROUPS),
            "published_at": (now - timedelta(days=dw_rng.randint(10, 500))).isoformat(),
            "post_title": f"{company_name} - dati pubblicati",
            "source_reference": "ransomware.live",
            "has_screenshot": True,
        })
    if dw_rng.random() < 0.30:
        posture.darkweb_mentions.append({
            "context": "menzione del dominio aziendale in un forum non indicizzato",
            "observed_at": (now - timedelta(days=dw_rng.randint(1, 300))).isoformat(),
            "source": "ahmia (indice Tor pubblico)",
        })

    # --- domini simili -------------------------------------------------
    look_rng = _rng(seed, "lookalike")
    base, _, tld = domain.partition(".")
    variants = [f"{base}-secure.{tld}", f"{base}s.{tld}", f"{base.replace('o', '0')}.{tld}",
                f"{base}.co", f"{base}-support.{tld}"]
    for variant in variants:
        if look_rng.random() < 0.35 * (1 + severity_bias):
            posture.lookalikes.append({
                "domain": variant,
                "registered": True,
                "has_mx": look_rng.random() < 0.4,
                "a_record": f"{SYNTHETIC_NET_B}{look_rng.randint(2, 250)}",
                "technique": look_rng.choice(["typosquatting", "omografo", "TLD alternativo", "aggiunta di parola"]),
                "created_at": (now - timedelta(days=look_rng.randint(10, 900))).isoformat(),
            })

    # --- porte esposte (solo profilo extended) --------------------------
    port_rng = _rng(seed, "ports")
    catalogue = [
        (22, "ssh", "OpenSSH", False), (3389, "ms-wbt-server", "Microsoft Terminal Services", True),
        (445, "microsoft-ds", "SMB", True), (3306, "mysql", "MySQL", True),
        (5432, "postgresql", "PostgreSQL", True), (6379, "redis", "Redis", True),
        (9200, "elasticsearch", "Elasticsearch", True), (23, "telnet", "Telnet", True),
        (21, "ftp", "FTP", True), (5900, "vnc", "VNC", True),
        (80, "http", "HTTP", False), (443, "https", "HTTPS", False),
        (25, "smtp", "SMTP", False),
    ]
    for ip in posture.ip_addresses[:4]:
        for port, service, product, sensitive in catalogue:
            probability = 0.9 if port in (80, 443) else (0.25 * (1 + severity_bias) if sensitive else 0.4)
            if port_rng.random() < probability:
                posture.open_ports.append({
                    "ip": ip, "port": port, "service": service,
                    "product": product, "sensitive": sensitive,
                })

    posture.registrar = {
        "registrar": _rng(seed, "rdap").choice(["Aruba S.p.A.", "Register.it", "OVH SAS", "GoDaddy LLC"]),
        "created_at": (now - timedelta(days=_rng(seed, "rdap2").randint(400, 7000))).isoformat(),
        "expires_at": (now + timedelta(days=_rng(seed, "rdap3").choice([18, 45, 120, 400, 700]))).isoformat(),
        "dnssec": posture.email["dnssec"],
        "nameservers": [f"ns1.{domain}", f"ns2.{domain}"],
    }
    return posture
