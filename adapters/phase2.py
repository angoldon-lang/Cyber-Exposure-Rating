"""Adapter di fase 2 e 3.

Ognuno espone l'interfaccia completa e un mock funzionante: l'applicazione
gira e produce risultati anche prima che il tool reale sia installato.
Cosi' l'assenza di un tool riduce la copertura (e la confidence), senza
bloccare ne' la scansione ne' lo sviluppo delle funzionalita' a valle.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from email import message_from_string
from email.policy import default as email_default
from typing import Any

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset, NormalizedEvidence
from adapters.runner import UnsafeCommandError, is_available, run_command, tool_version
from adapters.synthetic import build_posture
from app.core.redaction import sanitize_text
from app.models.enums import AssetType, ConfidenceClass, ScoreCategoryKey, Severity

WEB = ScoreCategoryKey.WEB_SECURITY.value
SURFACE = ScoreCategoryKey.ATTACK_SURFACE.value
DARKWEB = ScoreCategoryKey.DARKWEB_BREACH.value
EMAIL = ScoreCategoryKey.EMAIL_DNS_SECURITY.value
VULN = ScoreCategoryKey.TECHNICAL_VULNERABILITIES.value


# ---------------------------------------------------------------------------
# OWASP Amass
# ---------------------------------------------------------------------------
class AmassAdapter(BaseAdapter):
    """Attack surface discovery e correlazione domini/IP/ASN.

    Nel profilo Public Passive si usa esclusivamente `enum -passive`.
    """

    key = "amass_passive"
    display_name = "OWASP Amass (passive)"
    is_passive = True
    coverage_areas = (SURFACE,)
    default_timeout = 900
    BINARY = "amass"
    ALLOWED_FLAGS = ("enum", "-passive", "-nocolor", "-json", "-d", "-timeout", "-silent")

    def check_available(self) -> tuple[bool, str]:
        if not is_available(self.BINARY):
            return False, f"binario '{self.BINARY}' non presente nel worker"
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        from adapters.runner import TemporaryWorkspace, read_output_file

        domains = self.context.scope_guard.filter_targets(self.context.domains, "hostname")
        if not domains:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun dominio in perimetro",
                                 coverage_impact=self.coverage_weight)
        assets: list[DiscoveredAsset] = []
        raw_chunks: list[bytes] = []
        version = tool_version(self.BINARY, "-version")
        for domain in domains[:10]:
            with TemporaryWorkspace("defenix-amass-") as workspace:
                outfile = workspace / "amass.json"
                args = ["enum", "-passive", "-nocolor", "-json", str(outfile), "-d", domain]
                try:
                    run_command(self.BINARY, args, allow_flags=self.ALLOWED_FLAGS,
                                timeout=self.config.get("timeout_seconds", self.default_timeout),
                                cwd=workspace)
                except (FileNotFoundError, UnsafeCommandError) as exc:
                    return AdapterResult(tool=self.key, status=AdapterStatus.FAILED,
                                         error_message=str(exc), coverage_impact=self.coverage_weight)
                payload = read_output_file(outfile)
            raw_chunks.append(payload)
            for line in payload.decode("utf-8", errors="replace").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                name = str(record.get("name", "")).strip().lower()
                if name:
                    assets.append(DiscoveredAsset(
                        asset_key=name, asset_type=AssetType.SUBDOMAIN.value, display_name=name,
                        discovered_by=self.key,
                        attributes={"sources": record.get("sources"), "input": domain}))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, assets=assets,
                             tool_version=version, target_count=len(domains),
                             raw_output=b"\n".join(raw_chunks))

    def mock(self) -> AdapterResult:
        assets: list[DiscoveredAsset] = []
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            for host in posture.subdomains:
                assets.append(DiscoveredAsset(
                    asset_key=host, asset_type=AssetType.SUBDOMAIN.value, display_name=host,
                    discovered_by=self.key, attributes={"sources": ["crt.sh", "dns"], "input": domain}))
            for address in posture.ip_addresses:
                assets.append(DiscoveredAsset(
                    asset_key=address, asset_type=AssetType.IP_ADDRESS.value, display_name=address,
                    discovered_by=self.key, attributes={"input": domain},
                    relationships=[{"type": "resolves_to", "source": domain, "target": address}]))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, assets=assets,
                             tool_version="amass v4.2 (mock)", was_mocked=True,
                             target_count=len(self.context.domains))


# ---------------------------------------------------------------------------
# OWASP ZAP Baseline
# ---------------------------------------------------------------------------
class ZAPBaselineAdapter(BaseAdapter):
    """Solo ZAP Baseline: Full Scan e Active Scan non sono mai attivabili."""

    key = "zap_baseline"
    display_name = "OWASP ZAP Baseline"
    is_passive = False
    coverage_areas = (WEB,)
    default_timeout = 900

    # Mappa gli alert ZAP sui finding_type del motore di scoring.
    ALERT_MAP: dict[str, tuple[str, str]] = {
        "10035": ("hsts_missing", Severity.MEDIUM.value),
        "10038": ("csp_missing", Severity.MEDIUM.value),
        "10020": ("clickjacking_protection_missing", Severity.LOW.value),
        "10021": ("x_content_type_options_missing", Severity.LOW.value),
        "10063": ("permissions_policy_missing", Severity.INFO.value),
        "10054": ("cookie_insecure", Severity.MEDIUM.value),
        "10010": ("cookie_insecure", Severity.MEDIUM.value),
        "10011": ("cookie_insecure", Severity.MEDIUM.value),
        "10036": ("version_disclosure", Severity.LOW.value),
        "10037": ("version_disclosure", Severity.LOW.value),
        "10015": ("version_disclosure", Severity.LOW.value),
        "10098": ("cors_permissive", Severity.MEDIUM.value),
        "10040": ("mixed_content", Severity.LOW.value),
        "10096": ("version_disclosure", Severity.INFO.value),
    }

    def check_available(self) -> tuple[bool, str]:
        if not is_available("docker"):
            return False, "runtime Docker non disponibile nel worker per l'immagine ZAP"
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        # L'esecuzione reale avviene tramite l'immagine ufficiale ZAP orchestrata
        # dal worker (non dal container API), con rete e volumi dedicati.
        urls = self.context.scope_guard.filter_targets(self.context.web_targets, "url")
        if not urls:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun URL autorizzato per ZAP Baseline",
                                 coverage_impact=self.coverage_weight)
        return AdapterResult(
            tool=self.key, status=AdapterStatus.SKIPPED,
            error_message=("esecuzione ZAP Baseline delegata al worker containerizzato: "
                           "abilitare il servizio `zap` nel compose per attivarla"),
            coverage_impact=self.coverage_weight, target_count=len(urls))

    def _from_alerts(self, url: str, alerts: list[dict[str, Any]]) -> list[NormalizedEvidence]:
        out: list[NormalizedEvidence] = []
        host = url.split("://", 1)[-1].split("/")[0]
        for alert in alerts:
            mapped = self.ALERT_MAP.get(str(alert.get("pluginid")))
            if not mapped:
                continue
            finding_type, severity = mapped
            out.append(NormalizedEvidence(
                tool=self.key, target=url, asset_key=f"web:{host}", finding_type=finding_type,
                title=f"{host}: {sanitize_text(str(alert.get('name', finding_type)), 200)}",
                description=sanitize_text(str(alert.get("desc", "")), 2000),
                # Il plugin id resta un attributo di tracciabilita': non entra
                # nell'identita' del finding, altrimenti lo stesso problema
                # rilevato anche da un altro tool verrebbe penalizzato due volte.
                detail=None,
                category=WEB, severity=severity,
                confidence_class=ConfidenceClass.CONFIRMED.value,
                data_source="OWASP ZAP Baseline (passivo)", source_url=url,
                attributes={"zap_plugin_id": str(alert.get("pluginid"))},
                observed_at=datetime.now(UTC)))
        return out

    def mock(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            for service in posture.web_services[:4]:
                alerts: list[dict[str, Any]] = []
                if not service["hsts"]:
                    alerts.append({"pluginid": "10035", "name": "Strict-Transport-Security non impostato",
                                   "desc": "Il sito non dichiara HSTS."})
                if not service["csp"]:
                    alerts.append({"pluginid": "10038", "name": "Content Security Policy assente",
                                   "desc": "Nessuna CSP dichiarata nelle risposte."})
                if not service["x_content_type_options"]:
                    alerts.append({"pluginid": "10021", "name": "X-Content-Type-Options assente",
                                   "desc": "Il MIME sniffing non e' disabilitato."})
                evidences.extend(self._from_alerts(service["url"], alerts))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             tool_version="ZAP 2.15 baseline (mock)", was_mocked=True,
                             target_count=len(self.context.domains))


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------
class NucleiAdapter(BaseAdapter):
    """Nuclei con allowlist di template approvati (solo Verified Extended)."""

    key = "nuclei"
    display_name = "Nuclei"
    is_passive = False
    coverage_areas = (VULN, WEB)
    default_timeout = 1200
    BINARY = "nuclei"
    ALLOWED_FLAGS = ("-jsonl", "-silent", "-no-color", "-t", "-id", "-l", "-rate-limit",
                     "-timeout", "-retries", "-severity", "-etags", "-disable-update-check")

    def check_available(self) -> tuple[bool, str]:
        if self.context.profile != "verified_extended":
            return False, "Nuclei e' ammesso solo nel profilo Verified Extended Check"
        if not is_available(self.BINARY):
            return False, f"binario '{self.BINARY}' non presente nel worker"
        return True, "disponibile"

    def approved_template_ids(self) -> list[str]:
        from app.core.config import load_yaml_config

        allowlist = load_yaml_config("nuclei_allowlist")
        constraints = allowlist.get("global_constraints", {})
        allowed_types = set(constraints.get("allowed_request_types", []))
        return [
            str(template["id"])
            for template in allowlist.get("templates", [])
            if template.get("approved") and str(template.get("request_type")) in allowed_types
        ]

    def execute(self) -> AdapterResult:
        from adapters.runner import TemporaryWorkspace

        template_ids = self.approved_template_ids()
        urls = self.context.scope_guard.filter_targets(self.context.web_targets, "url")
        if not template_ids or not urls:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun template approvato o nessun URL in whitelist",
                                 coverage_impact=self.coverage_weight)
        urls = urls[: int(self.config.get("max_targets", 100))]
        excluded = ",".join(self.config.get("excluded_tags", []))
        with TemporaryWorkspace("defenix-nuclei-") as workspace:
            list_file = workspace / "targets.txt"
            list_file.write_text("\n".join(urls), encoding="utf-8")
            args = ["-jsonl", "-silent", "-no-color", "-disable-update-check",
                    "-l", str(list_file), "-id", ",".join(template_ids),
                    "-rate-limit", str(int(self.config.get("rate_limit_per_second", 20))),
                    "-timeout", "20", "-retries", "1"]
            if excluded:
                args += ["-etags", excluded]
            try:
                result = run_command(self.BINARY, args, allow_flags=self.ALLOWED_FLAGS,
                                     timeout=self.config.get("timeout_seconds", self.default_timeout),
                                     cwd=workspace)
            except (FileNotFoundError, UnsafeCommandError) as exc:
                return AdapterResult(tool=self.key, status=AdapterStatus.FAILED,
                                     error_message=str(exc), coverage_impact=self.coverage_weight)
        evidences = self._parse(result.stdout)
        stato, motivo, impatto = self.esito_del_comando(result, prodotto=len(evidences))
        return AdapterResult(tool=self.key, status=stato, evidences=evidences,
                             tool_version=tool_version(self.BINARY, "-version"),
                             target_count=len(urls), raw_output=result.stdout,
                             error_message=motivo, coverage_impact=impatto,
                             exit_code=result.exit_code,
                             config_snapshot={"templates": template_ids})

    def _parse(self, payload: bytes) -> list[NormalizedEvidence]:
        mapping = {
            "expired-ssl": ("tls_certificate_expired", Severity.CRITICAL.value),
            "mismatched-ssl-certificate": ("tls_certificate_hostname_mismatch", Severity.HIGH.value),
            "directory-listing": ("directory_listing", Severity.MEDIUM.value),
            "git-config": ("sensitive_file_exposed", Severity.HIGH.value),
            "env-file-exposure": ("sensitive_file_exposed", Severity.CRITICAL.value),
            "phpinfo-files": ("version_disclosure", Severity.MEDIUM.value),
            "apache-server-status": ("version_disclosure", Severity.MEDIUM.value),
            "http-missing-security-headers": ("csp_missing", Severity.INFO.value),
        }
        out: list[NormalizedEvidence] = []
        for line in payload.decode("utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            template_id = str(record.get("template-id", ""))
            finding_type, severity = mapping.get(template_id, ("web_misconfiguration", Severity.LOW.value))
            host = str(record.get("host", ""))
            out.append(NormalizedEvidence(
                tool=self.key, target=host, asset_key=f"web:{host.split('://')[-1].split('/')[0]}",
                finding_type=finding_type,
                title=sanitize_text(str(record.get("info", {}).get("name", template_id)), 300),
                description=sanitize_text(str(record.get("info", {}).get("description", "")), 2000),
                detail=template_id, category=WEB, severity=severity,
                confidence_class=ConfidenceClass.CONFIRMED.value,
                data_source=f"Nuclei (template approvato {template_id})",
                observed_at=datetime.now(UTC)))
        return out

    def mock(self) -> AdapterResult:
        if self.context.profile != "verified_extended":
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED, was_mocked=True,
                                 error_message="Nuclei non ammesso in questo profilo",
                                 coverage_impact=0.0)
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=[],
                             tool_version="nuclei v3.3 (mock)", was_mocked=True,
                             config_snapshot={"templates": self.approved_template_ids()})


# ---------------------------------------------------------------------------
# Naabu / Nmap
# ---------------------------------------------------------------------------
class NaabuAdapter(BaseAdapter):
    """Port scanning controllato, solo Verified Extended e solo su IP autorizzati."""

    key = "naabu"
    display_name = "Naabu"
    is_passive = False
    coverage_areas = (SURFACE,)
    default_timeout = 900
    BINARY = "naabu"
    ALLOWED_FLAGS = ("-json", "-silent", "-no-color", "-host", "-p", "-rate", "-retries",
                     "-timeout", "-list", "-l", "-disable-update-check")

    SENSITIVE_PORTS: dict[int, str] = {
        21: "FTP", 23: "Telnet", 445: "SMB", 1433: "Microsoft SQL Server",
        3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        9200: "Elasticsearch", 27017: "MongoDB", 10000: "Webmin",
    }
    REMOTE_ADMIN_PORTS: dict[int, str] = {22: "SSH", 3389: "RDP", 5985: "WinRM"}

    def check_available(self) -> tuple[bool, str]:
        if self.context.profile != "verified_extended":
            return False, "il port scanning e' ammesso solo nel profilo Verified Extended Check"
        if not is_available(self.BINARY):
            # Su linux/arm64 Naabu non esiste, e la rilevazione dei servizi la
            # fa `port_scan`. Dire solo «binario non presente» farebbe pensare
            # a una lacuna che invece e' coperta.
            return False, (f"binario '{self.BINARY}' non presente per questa architettura: "
                           "la rilevazione dei servizi e' svolta da port_scan")
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        ips = self.context.scope_guard.filter_targets(self.context.ip_addresses, "ip")
        if not ips:
            # Distinguere i due casi cambia l'azione dell'operatore: se nessun
            # indirizzo e' stato trovato il perimetro e' incompleto, se ne sono
            # stati trovati ma nessuno e' autorizzato manca solo un consenso.
            scoperti = len([a for a in self.context.ip_addresses if a])
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED,
                error_message=(
                    f"{scoperti} indirizzi IP pubblici individuati, nessuno coperto da "
                    "un'autorizzazione esplicita: autorizzarli in Gestione azienda "
                    "prima di eseguire il port scanning"
                    if scoperti else
                    "nessun indirizzo IP pubblico individuato per i domini in perimetro"),
                coverage_impact=self.coverage_weight)
        ports = ",".join(str(p) for p in self.config.get("default_ports", [80, 443]))
        from adapters.runner import TemporaryWorkspace

        with TemporaryWorkspace("defenix-naabu-") as workspace:
            list_file = workspace / "hosts.txt"
            list_file.write_text("\n".join(ips), encoding="utf-8")
            args = ["-json", "-silent", "-no-color", "-disable-update-check", "-l", str(list_file),
                    "-p", ports, "-rate", str(int(self.config.get("rate_limit_per_second", 100))),
                    "-retries", "1", "-timeout", "5000"]
            try:
                result = run_command(self.BINARY, args, allow_flags=self.ALLOWED_FLAGS,
                                     timeout=self.config.get("timeout_seconds", self.default_timeout),
                                     cwd=workspace)
            except (FileNotFoundError, UnsafeCommandError) as exc:
                return AdapterResult(tool=self.key, status=AdapterStatus.FAILED,
                                     error_message=str(exc), coverage_impact=self.coverage_weight)
        records = []
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append({"ip": record.get("ip") or record.get("host"),
                            "port": int(record.get("port", 0)), "service": None, "product": None})
        evidences, assets = self._build(records)
        stato, motivo, impatto = self.esito_del_comando(result, prodotto=len(records))
        return AdapterResult(tool=self.key, status=stato, evidences=evidences,
                             assets=assets, tool_version=tool_version(self.BINARY, "-version"),
                             target_count=len(ips), raw_output=result.stdout,
                             error_message=motivo, coverage_impact=impatto,
                             exit_code=result.exit_code)

    def _build(self, records: list[dict[str, Any]]) -> tuple[list[NormalizedEvidence],
                                                              list[DiscoveredAsset]]:
        evidences: list[NormalizedEvidence] = []
        assets: list[DiscoveredAsset] = []
        for record in records:
            ip, port = str(record["ip"]), int(record["port"])
            asset_key = f"service:{ip}:{port}"
            assets.append(DiscoveredAsset(
                asset_key=asset_key, asset_type=AssetType.NETWORK_SERVICE.value,
                display_name=f"{ip}:{port}", discovered_by=self.key,
                attributes={"ip": ip, "port": port, "service": record.get("service")},
                relationships=[{"type": "service_on", "source": asset_key, "target": ip}]))
            if port in self.REMOTE_ADMIN_PORTS:
                evidences.append(NormalizedEvidence(
                    tool=self.key, target=f"{ip}:{port}", asset_key=asset_key,
                    finding_type="remote_admin_service_exposed",
                    title=f"Servizio di amministrazione remota esposto: {self.REMOTE_ADMIN_PORTS[port]} su {ip}:{port}",
                    description=("Un servizio di accesso amministrativo remoto risponde direttamente da "
                                 "Internet. L'esposizione va limitata a sorgenti autorizzate tramite "
                                 "VPN o accesso privilegiato, con autenticazione a piu' fattori."),
                    detail=f"{port}/{self.REMOTE_ADMIN_PORTS[port]}", category=SURFACE,
                    severity=Severity.CRITICAL.value,
                    confidence_class=ConfidenceClass.CONFIRMED.value,
                    data_source="Port scanning autorizzato", observed_at=datetime.now(UTC)))
            elif port in self.SENSITIVE_PORTS:
                evidences.append(NormalizedEvidence(
                    tool=self.key, target=f"{ip}:{port}", asset_key=asset_key,
                    finding_type="sensitive_service_exposed",
                    title=f"Servizio sensibile esposto: {self.SENSITIVE_PORTS[port]} su {ip}:{port}",
                    description=("Un servizio non destinato alla pubblicazione su Internet risulta "
                                 "raggiungibile. Va rimosso dal perimetro pubblico o limitato "
                                 "a sorgenti autorizzate."),
                    detail=f"{port}/{self.SENSITIVE_PORTS[port]}", category=SURFACE,
                    severity=Severity.HIGH.value,
                    confidence_class=ConfidenceClass.CONFIRMED.value,
                    data_source="Port scanning autorizzato", observed_at=datetime.now(UTC)))
        return evidences, assets

    def mock(self) -> AdapterResult:
        if self.context.profile != "verified_extended":
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED, was_mocked=True,
                                 error_message="port scanning non ammesso in questo profilo",
                                 coverage_impact=0.0)
        records: list[dict[str, Any]] = []
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            records.extend(posture.open_ports)
        evidences, assets = self._build(records)
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             assets=assets, tool_version="naabu v2.3 (mock)", was_mocked=True,
                             target_count=len(records))


# ---------------------------------------------------------------------------
# DNSTwist
# ---------------------------------------------------------------------------
class DNSTwistAdapter(BaseAdapter):
    """Domini simili e potenziale impersonificazione.

    Un dominio simile NON e' dichiarato malevolo per il solo fatto di essere
    simile: la severita' aumenta solo in presenza di record MX (capacita' di
    ricevere e inviare posta) e la validazione resta all'analista.
    """

    key = "dnstwist"
    display_name = "DNSTwist"
    is_passive = True
    coverage_areas = (DARKWEB,)
    default_timeout = 900

    def check_available(self) -> tuple[bool, str]:
        try:
            import dnstwist  # noqa: F401
        except ImportError:
            return False, "libreria dnstwist non installata nel worker"
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        import dnstwist

        evidences: list[NormalizedEvidence] = []
        raw: dict[str, Any] = {}
        domains = self.context.scope_guard.filter_targets(self.context.domains, "hostname")
        for domain in domains[:5]:
            try:
                results = dnstwist.run(domain=domain, registered=True, format="null",
                                       threads=8, nameservers=None)
            except Exception as exc:  # noqa: BLE001
                raw[domain] = {"error": type(exc).__name__}
                continue
            raw[domain] = {"variants": len(results)}
            for entry in results:
                if str(entry.get("domain", "")).lower() == domain:
                    continue
                evidences.append(self._build(domain, {
                    "domain": entry.get("domain"),
                    "has_mx": bool(entry.get("dns_mx")),
                    "a_record": (entry.get("dns_a") or [None])[0],
                    "technique": entry.get("fuzzer", "variazione"),
                }))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             target_count=len(domains), raw_output=self.dump_json(raw))

    def _build(self, base_domain: str, variant: dict[str, Any]) -> NormalizedEvidence:
        has_mx = bool(variant.get("has_mx"))
        return NormalizedEvidence(
            tool=self.key, target=base_domain, asset_key=base_domain,
            finding_type="lookalike_domain_with_mx" if has_mx else "lookalike_domain_registered",
            title=f"Dominio simile registrato: {variant['domain']}",
            description=(
                f"Il dominio «{variant['domain']}» e' una variante di «{base_domain}» "
                f"(tecnica: {variant.get('technique', 'n/d')}) e risulta registrato. "
                + ("Dispone di record MX: puo' quindi ricevere e inviare posta, il che ne "
                   "aumenta l'idoneita' a campagne di phishing mirate."
                   if has_mx else
                   "La sola somiglianza non implica intento malevolo: e' necessaria una verifica "
                   "del contenuto e della titolarita' prima di qualsiasi azione.")),
            detail=str(variant["domain"]),
            category=DARKWEB,
            severity=(Severity.HIGH if has_mx else Severity.MEDIUM).value,
            confidence_class=(ConfidenceClass.CONFIRMED if has_mx else ConfidenceClass.PROBABLE).value,
            data_source="DNSTwist + risoluzione DNS pubblica", observed_at=datetime.now(UTC),
            attributes={"variant_domain": variant["domain"], "has_mx": has_mx,
                        "technique": variant.get("technique"), "a_record": variant.get("a_record")})

    def mock(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            for variant in posture.lookalikes:
                evidences.append(self._build(domain, variant))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             tool_version="dnstwist 20240521 (mock)", was_mocked=True,
                             target_count=len(self.context.domains))


# ---------------------------------------------------------------------------
# Analisi header e-mail
# ---------------------------------------------------------------------------
class EmailHeaderAdapter(BaseAdapter):
    """Analizza un header e-mail fornito dal cliente.

    Vengono conservati solo i campi necessari: corpo, allegati e dati personali
    non indispensabili non entrano mai nel sistema.
    """

    key = "email_header"
    display_name = "Email header analyzer"
    is_passive = True
    coverage_areas = (EMAIL,)
    default_timeout = 30

    KEEP_HEADERS = ("received", "received-spf", "authentication-results", "dkim-signature",
                    "arc-authentication-results", "return-path", "from", "date",
                    "x-forefront-antispam-report", "x-ms-exchange-organization-authas")

    def check_available(self) -> tuple[bool, str]:
        if not self.context.email_header:
            return False, "nessun header e-mail fornito"
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        parsed = self.analyse(self.context.email_header or "")
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS,
                             evidences=self._build(parsed), target_count=1,
                             raw_output=self.dump_json(parsed))

    def analyse(self, header_text: str) -> dict[str, Any]:
        """Estrae esclusivamente i campi di autenticazione, sanitizzati."""
        message = message_from_string(header_text[:200_000], policy=email_default)
        kept: dict[str, list[str]] = {}
        for name in self.KEEP_HEADERS:
            values = message.get_all(name) or []
            if values:
                kept[name] = [sanitize_text(str(value), 1000) for value in values[:20]]

        auth = " ".join(kept.get("authentication-results", [])).lower()
        received_spf = " ".join(kept.get("received-spf", [])).lower()
        provider = None
        for needle, name in (("outlook.com", "Microsoft 365"), ("google.com", "Google Workspace"),
                             ("mimecast", "Mimecast"), ("pphosted", "Proofpoint"),
                             ("libraesva", "Libraesva"), ("barracuda", "Barracuda")):
            if needle in " ".join(sum(kept.values(), [])).lower():
                provider = name
                break

        return {
            "spf_result": self._verdict(auth, received_spf, "spf"),
            "dkim_result": self._verdict(auth, "", "dkim"),
            "dmarc_result": self._verdict(auth, "", "dmarc"),
            "alignment_ok": "dmarc=pass" in auth,
            "provider": provider,
            "secure_email_gateway": provider if provider in {"Mimecast", "Proofpoint",
                                                             "Libraesva", "Barracuda"} else None,
            "hop_count": len(kept.get("received", [])),
            "tls_declared": "version=tls" in header_text.lower(),
            "dkim_selectors": self._selectors(kept.get("dkim-signature", [])),
            "headers_kept": sorted(kept),
        }

    @staticmethod
    def _verdict(auth: str, fallback: str, mechanism: str) -> str:
        for outcome in ("pass", "fail", "softfail", "neutral", "permerror", "temperror", "none"):
            if f"{mechanism}={outcome}" in auth or (fallback and fallback.startswith(outcome)):
                return outcome
        return "unknown"

    @staticmethod
    def _selectors(signatures: list[str]) -> list[str]:
        selectors: list[str] = []
        for signature in signatures:
            for part in signature.split(";"):
                key, _, value = part.strip().partition("=")
                if key.strip().lower() == "s" and value.strip():
                    selectors.append(value.strip()[:64])
        return sorted(set(selectors))

    def _build(self, parsed: dict[str, Any]) -> list[NormalizedEvidence]:
        domain = self.context.domains[0] if self.context.domains else "n/d"
        out: list[NormalizedEvidence] = []
        anomalies = [
            ("spf_result", "spf_invalid", "SPF non superato nell'header analizzato", Severity.MEDIUM),
            ("dkim_result", "dkim_no_selector_found", "DKIM non superato nell'header analizzato", Severity.MEDIUM),
        ]
        for field, finding_type, title, severity in anomalies:
            if parsed.get(field) in {"fail", "softfail", "permerror", "none"}:
                out.append(NormalizedEvidence(
                    tool=self.key, target=domain, asset_key=f"mail:{domain}",
                    finding_type=finding_type, title=title,
                    description=(f"L'analisi dell'header e-mail fornito riporta "
                                 f"{field.replace('_result', '').upper()}={parsed[field]}. "
                                 "Il risultato si riferisce al singolo messaggio esaminato e va "
                                 "confrontato con la configurazione DNS del dominio."),
                    detail=str(parsed.get(field)), category=EMAIL, severity=severity.value,
                    confidence_class=ConfidenceClass.PROBABLE.value,
                    data_source="Header e-mail fornito dal cliente (sanitizzato)",
                    observed_at=datetime.now(UTC),
                    attributes={"provider": parsed.get("provider"),
                                "hop_count": parsed.get("hop_count")}))
        return out

    def mock(self) -> AdapterResult:
        if not self.context.email_header:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED, was_mocked=True,
                                 error_message="nessun header e-mail fornito", coverage_impact=0.0)
        parsed = self.analyse(self.context.email_header)
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=self._build(parsed),
                             was_mocked=True, target_count=1, raw_output=self.dump_json(parsed))


# ---------------------------------------------------------------------------
# AIL Framework (fase 3)
# ---------------------------------------------------------------------------
class AILAdapter(BaseAdapter):
    """Predisposizione all'integrazione con AIL Framework (fase 3).

    AIL e' AGPL-3.0: viene usato come servizio esterno separato, interrogato
    via API di rete. Nessun codice AIL e' incorporato nel prodotto Defenix.
    """

    key = "ail"
    display_name = "AIL Framework"
    is_passive = True
    optional = True
    coverage_areas = (DARKWEB,)
    default_timeout = 600

    def check_available(self) -> tuple[bool, str]:
        base_url = self.context.connector_config.get("ail", {}).get("base_url")
        if not base_url:
            return False, "AIL Framework non configurato (integrazione prevista in fase 3)"
        return True, "disponibile"

    def execute(self) -> AdapterResult:
        return AdapterResult(
            tool=self.key, status=AdapterStatus.SKIPPED,
            error_message="integrazione AIL prevista in fase 3: interfaccia predisposta",
            coverage_impact=0.0)

    def mock(self) -> AdapterResult:
        return AdapterResult(
            tool=self.key, status=AdapterStatus.SKIPPED, was_mocked=True,
            error_message="integrazione AIL prevista in fase 3: interfaccia predisposta",
            coverage_impact=0.0)
