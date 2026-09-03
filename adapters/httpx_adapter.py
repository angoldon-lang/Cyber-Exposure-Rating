"""Adapter HTTPX: validazione dei servizi web e analisi degli header.

Attivo solo nei profili verificati (richiede richieste HTTP dirette al target).
"""
from __future__ import annotations

import json
from typing import Any

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset, NormalizedEvidence
from adapters.runner import UnsafeCommandError, is_available, run_command, tool_version
from adapters.synthetic import build_posture
from app.models.enums import AssetType, ConfidenceClass, ScoreCategoryKey, Severity

BINARY = "httpx"
CATEGORY = ScoreCategoryKey.WEB_SECURITY.value
ALLOWED_FLAGS = (
    "-json", "-silent", "-no-color", "-status-code", "-title", "-tech-detect",
    "-web-server", "-cdn", "-tls-grab", "-follow-redirects", "-max-redirects",
    "-timeout", "-rate-limit", "-list", "-include-response-header", "-l",
)

ADMIN_PANEL_MARKERS = ("portal", "intranet", "admin", "crm", "erp", "jenkins",
                       "grafana", "owa", "manage", "console")
NON_PRODUCTION_MARKERS = ("dev", "staging", "stage", "test", "uat", "preprod",
                          "old", "legacy", "demo")


class HTTPXAdapter(BaseAdapter):
    key = "httpx"
    display_name = "HTTPX"
    is_passive = False
    coverage_areas = (CATEGORY, ScoreCategoryKey.ATTACK_SURFACE.value)
    default_timeout = 300

    def check_available(self) -> tuple[bool, str]:
        if not is_available(BINARY):
            return False, f"binario '{BINARY}' non presente nel worker"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        targets = self.context.scope_guard.filter_targets(
            self.context.known_subdomains or self.context.domains, "hostname")
        if not targets:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun host in perimetro",
                                 coverage_impact=self.coverage_weight)
        targets = targets[: int(self.config.get("max_targets", 500))]

        from adapters.runner import TemporaryWorkspace

        version = tool_version(BINARY, "-version")
        with TemporaryWorkspace("defenix-httpx-") as workspace:
            list_file = workspace / "targets.txt"
            list_file.write_text("\n".join(targets), encoding="utf-8")
            args = ["-json", "-silent", "-no-color", "-status-code", "-title", "-tech-detect",
                    "-web-server", "-cdn", "-tls-grab", "-follow-redirects",
                    "-max-redirects", "3", "-timeout", "10", "-rate-limit",
                    str(int(self.config.get("rate_limit_per_second", 20))),
                    "-l", str(list_file)]
            try:
                result = run_command(BINARY, args, allow_flags=ALLOWED_FLAGS,
                                     timeout=self.config.get("timeout_seconds", self.default_timeout),
                                     cwd=workspace)
            except (FileNotFoundError, UnsafeCommandError) as exc:
                return AdapterResult(tool=self.key, status=AdapterStatus.FAILED,
                                     error_message=str(exc), coverage_impact=self.coverage_weight)
            raw = result.stdout

        records: list[dict[str, Any]] = []
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        evidences, assets = self._analyse_records(records)
        status = AdapterStatus.SUCCESS if not result.timed_out else AdapterStatus.PARTIAL
        return AdapterResult(tool=self.key, status=status, evidences=evidences, assets=assets,
                             tool_version=version, target_count=len(targets), raw_output=raw,
                             exit_code=result.exit_code,
                             coverage_impact=0.0 if status is AdapterStatus.SUCCESS
                             else self.coverage_weight * 0.4)

    def _analyse_records(self, records: list[dict[str, Any]]) -> tuple[list[NormalizedEvidence],
                                                                       list[DiscoveredAsset]]:
        services: list[dict[str, Any]] = []
        for record in records:
            headers = {k.lower(): v for k, v in (record.get("header") or {}).items()}
            url = str(record.get("url", ""))
            host = str(record.get("input") or record.get("host") or "")
            csp = headers.get("content-security-policy", "")
            services.append({
                "host": host,
                "url": url,
                "status_code": record.get("status_code"),
                "title": record.get("title"),
                "ip": record.get("host"),
                "server": headers.get("server") or record.get("webserver"),
                "technologies": [{"name": t, "version": None} for t in (record.get("tech") or [])],
                "https": url.startswith("https://"),
                "hsts": "strict-transport-security" in headers,
                "csp": bool(csp),
                "x_frame_options": ("x-frame-options" in headers) or ("frame-ancestors" in csp),
                "x_content_type_options": "nosniff" in headers.get("x-content-type-options", "").lower(),
                "referrer_policy": "referrer-policy" in headers,
                "permissions_policy": "permissions-policy" in headers,
                "cookie_secure": "secure" in headers.get("set-cookie", "").lower(),
                "cookie_httponly": "httponly" in headers.get("set-cookie", "").lower(),
                "cookie_samesite": "samesite" in headers.get("set-cookie", "").lower(),
                "has_cookies": "set-cookie" in headers,
                "cors_wildcard": headers.get("access-control-allow-origin") == "*",
                "version_disclosure": self._has_version(headers.get("server", "")),
                "directory_listing": "index of /" in str(record.get("title", "")).lower(),
                "mixed_content": False,
                "security_txt": False,
                "cdn": record.get("cdn_name"),
                "waf": None,
                "is_admin_panel": any(m in host.split(".")[0] for m in ADMIN_PANEL_MARKERS),
                "is_non_production": any(m in host.split(".")[0] for m in NON_PRODUCTION_MARKERS),
            })
        return self._build(services)

    @staticmethod
    def _has_version(server_header: str) -> bool:
        return any(char.isdigit() for char in server_header) and "/" in server_header

    # ------------------------------------------------------------------
    def _build(self, services: list[dict[str, Any]]) -> tuple[list[NormalizedEvidence],
                                                               list[DiscoveredAsset]]:
        evidences: list[NormalizedEvidence] = []
        assets: list[DiscoveredAsset] = []

        for service in services:
            host = service["host"]
            asset_key = f"web:{host}"
            assets.append(DiscoveredAsset(
                asset_key=asset_key, asset_type=AssetType.WEB_SERVICE.value,
                display_name=service.get("url") or host, discovered_by=self.key,
                attributes={k: v for k, v in service.items() if k != "technologies"},
                technologies=service.get("technologies", []),
                relationships=[{"type": "service_on", "source": asset_key, "target": host}]))

            status_code = service.get("status_code")
            if status_code in (404, 410, None):
                continue

            def add(finding_type: str, title: str, description: str, severity: Severity,
                    confidence: ConfidenceClass = ConfidenceClass.CONFIRMED,
                    detail: str | None = None) -> None:
                evidences.append(NormalizedEvidence(
                    tool=self.key, target=service.get("url") or host, asset_key=asset_key,
                    finding_type=finding_type, title=title, description=description, detail=detail,
                    category=CATEGORY, severity=severity.value, confidence_class=confidence.value,
                    data_source="Richiesta HTTP autorizzata",
                    source_url=service.get("url"),
                    attributes={"status_code": status_code, "server": service.get("server")}))

            if not service.get("https"):
                add("https_not_available", f"{host}: servizio raggiungibile solo in HTTP",
                    "Il servizio non espone HTTPS o non reindirizza il traffico in chiaro: "
                    "credenziali e dati di sessione transitano senza cifratura.", Severity.HIGH)
            if not service.get("hsts"):
                add("hsts_missing", f"{host}: HSTS non attivo",
                    "L'header Strict-Transport-Security non e' presente: il browser puo' essere "
                    "indotto a usare HTTP in chiaro alla prima connessione.", Severity.MEDIUM)
            if not service.get("csp"):
                add("csp_missing", f"{host}: Content Security Policy assente",
                    "Nessuna Content Security Policy dichiarata: viene a mancare una difesa "
                    "trasversale contro cross-site scripting e injection di risorse esterne.",
                    Severity.MEDIUM)
            if not service.get("x_frame_options"):
                add("clickjacking_protection_missing", f"{host}: nessuna protezione dal clickjacking",
                    "Non sono presenti ne' `X-Frame-Options` ne' la direttiva CSP `frame-ancestors`: "
                    "la pagina puo' essere incorniciata da un sito di terzi.", Severity.LOW)
            if not service.get("x_content_type_options"):
                add("x_content_type_options_missing", f"{host}: `X-Content-Type-Options` assente",
                    "Senza `nosniff` il browser puo' interpretare le risorse in modo diverso dal "
                    "content-type dichiarato.", Severity.LOW)
            if not service.get("referrer_policy"):
                add("referrer_policy_missing", f"{host}: `Referrer-Policy` assente",
                    "Gli URL interni possono essere trasmessi a siti di terzi tramite il referrer.",
                    Severity.INFO)
            if not service.get("permissions_policy"):
                add("permissions_policy_missing", f"{host}: `Permissions-Policy` assente",
                    "Non sono limitate le API del browser utilizzabili dalla pagina e dai suoi iframe.",
                    Severity.INFO)
            if service.get("has_cookies", True) and not (
                    service.get("cookie_secure") and service.get("cookie_httponly")
                    and service.get("cookie_samesite")):
                missing = [name for name, present in (
                    ("Secure", service.get("cookie_secure")),
                    ("HttpOnly", service.get("cookie_httponly")),
                    ("SameSite", service.get("cookie_samesite"))) if not present]
                if missing:
                    add("cookie_insecure", f"{host}: cookie senza attributi di protezione",
                        f"Ai cookie mancano gli attributi {', '.join(missing)}: la sessione e' piu' "
                        "esposta a furto e a richieste cross-site.", Severity.MEDIUM,
                        detail=",".join(missing))
            if service.get("version_disclosure"):
                add("version_disclosure", f"{host}: versione del software esposta negli header",
                    "L'header `Server` rivela prodotto e versione, agevolando la ricerca di "
                    "vulnerabilita' note.", Severity.LOW, detail=str(service.get("server")))
            if service.get("directory_listing"):
                add("directory_listing", f"{host}: directory listing abilitato",
                    "Il server elenca il contenuto delle directory: possibile esposizione di file "
                    "non destinati alla pubblicazione.", Severity.MEDIUM)
            if service.get("cors_wildcard"):
                add("cors_permissive", f"{host}: CORS permissivo",
                    "L'header `Access-Control-Allow-Origin: *` consente a qualunque origine di "
                    "leggere le risposte dell'applicazione.", Severity.MEDIUM)
            if service.get("mixed_content"):
                add("mixed_content", f"{host}: contenuto misto",
                    "La pagina HTTPS carica risorse in HTTP: la protezione del canale e' compromessa.",
                    Severity.LOW)
            if not service.get("security_txt"):
                add("security_txt_missing", f"{host}: `security.txt` non pubblicato",
                    "Non e' pubblicato un contatto per le segnalazioni di sicurezza.", Severity.INFO)
            if service.get("is_admin_panel") and status_code in (200, 401, 403):
                add("admin_panel_exposed", f"{host}: interfaccia di gestione raggiungibile da Internet",
                    "Un'interfaccia amministrativa risponde su Internet. Anche se protetta da "
                    "autenticazione, l'esposizione diretta va limitata a sorgenti autorizzate.",
                    Severity.HIGH, detail=host.split(".")[0])
            if service.get("is_non_production") and status_code == 200:
                add("non_production_environment_exposed",
                    f"{host}: ambiente non produttivo esposto",
                    "Un ambiente di sviluppo, test o dismesso e' raggiungibile pubblicamente: "
                    "spesso ha configurazioni meno rigorose e dati reali.",
                    Severity.MEDIUM, ConfidenceClass.PROBABLE)
        return evidences, assets

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        services: list[dict[str, Any]] = []
        for domain in self.context.domains:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            for service in posture.web_services:
                services.append({**service, "has_cookies": True})
        evidences, assets = self._build(services)
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             assets=assets, tool_version="httpx v1.6.9 (mock)", was_mocked=True,
                             target_count=len(services), raw_output=self.dump_json(services))
