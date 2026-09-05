"""Adapter testssl.sh: protocolli, cipher, certificati e vulnerabilita' TLS."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, NormalizedEvidence
from adapters.runner import TemporaryWorkspace, UnsafeCommandError, is_available, read_output_file, run_command
from adapters.synthetic import build_posture
from app.models.enums import ConfidenceClass, ScoreCategoryKey, Severity

BINARY = "testssl.sh"
CATEGORY = ScoreCategoryKey.WEB_SECURITY.value
ALLOWED_FLAGS = ("--jsonfile-pretty", "--quiet", "--color", "--severity", "--sneaky",
                 "--warnings", "--openssl-timeout", "--connect-timeout")

LEGACY_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
CERT_EXPIRY_WARNING_DAYS = 30


class TestSSLAdapter(BaseAdapter):
    key = "testssl"
    display_name = "testssl.sh"
    is_passive = False
    coverage_areas = (CATEGORY,)
    default_timeout = 600

    def check_available(self) -> tuple[bool, str]:
        if not is_available(BINARY):
            return False, f"binario '{BINARY}' non presente nel worker"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        # I bersagli sono nomi host, non URL: `web_targets` contiene
        # «https://host» e filtrarlo come hostname lo scartava sempre, cosi'
        # testssl dichiarava «nessun host in perimetro» a ogni scansione anche
        # con il perimetro corretto. I sottodomini scoperti stanno in
        # `known_subdomains`, che e' gia' una lista di nomi.
        targets = self.context.scope_guard.filter_targets(
            self.context.known_subdomains or self.context.domains, "hostname")
        if not targets:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun host in perimetro",
                                 coverage_impact=self.coverage_weight)
        targets = targets[: int(self.config.get("max_targets", 25))]

        evidences: list[NormalizedEvidence] = []
        raw: dict[str, Any] = {}
        failures = 0
        for host in targets:
            with TemporaryWorkspace("defenix-testssl-") as workspace:
                outfile = workspace / "result.json"
                args = ["--jsonfile-pretty", str(outfile), "--quiet", "--color", "0",
                        "--severity", "LOW", "--sneaky", host]
                try:
                    result = run_command(BINARY, args, allow_flags=ALLOWED_FLAGS,
                                         timeout=self.config.get("timeout_seconds", self.default_timeout),
                                         cwd=workspace)
                except (FileNotFoundError, UnsafeCommandError) as exc:
                    failures += 1
                    raw[host] = {"error": str(exc)[:200]}
                    continue
                if result.timed_out:
                    failures += 1
                payload_bytes = read_output_file(outfile)
            try:
                findings = json.loads(payload_bytes or b"[]")
            except json.JSONDecodeError:
                failures += 1
                continue
            raw[host] = findings
            evidences.extend(self._analyse_testssl(host, findings))

        status = (AdapterStatus.SUCCESS if failures == 0
                  else AdapterStatus.PARTIAL if failures < len(targets) else AdapterStatus.FAILED)
        return AdapterResult(tool=self.key, status=status, evidences=evidences,
                             target_count=len(targets), raw_output=self.dump_json(raw),
                             coverage_impact=0.0 if failures == 0
                             else self.coverage_weight * (failures / len(targets)))

    def _analyse_testssl(self, host: str, findings: list[dict[str, Any]] | dict) -> list[NormalizedEvidence]:
        """Traduce l'output nativo di testssl.sh in evidenze normalizzate."""
        items = findings.get("scanResult", findings) if isinstance(findings, dict) else findings
        if not isinstance(items, list):
            return []
        posture: dict[str, Any] = {"protocols": {}, "weak_ciphers": [], "days_to_expiry": None,
                                   "hostname_match": True}
        for item in items:
            if not isinstance(item, dict):
                continue
            identifier = str(item.get("id", ""))
            finding = str(item.get("finding", ""))
            severity = str(item.get("severity", "")).upper()
            if identifier in {"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}:
                label = {"TLS1": "TLSv1.0", "TLS1_1": "TLSv1.1", "TLS1_2": "TLSv1.2",
                         "TLS1_3": "TLSv1.3"}.get(identifier, identifier)
                posture["protocols"][label] = "offered" in finding and "not" not in finding
            if severity in {"HIGH", "CRITICAL", "MEDIUM"} and "cipher" in identifier.lower():
                posture["weak_ciphers"].append({"name": identifier, "reason": finding[:120]})
            if identifier == "cert_expirationStatus":
                digits = [int(tok) for tok in finding.replace(">", " ").split() if tok.isdigit()]
                posture["days_to_expiry"] = -1 if "expired" in finding.lower() else (
                    digits[0] if digits else None)
            if identifier == "cert_hostnameMismatch":
                posture["hostname_match"] = "no" in finding.lower() or "matches" in finding.lower()
        return self._build(host, posture)

    # ------------------------------------------------------------------
    def _build(self, host: str, posture: dict[str, Any]) -> list[NormalizedEvidence]:
        asset_key = f"web:{host}"
        out: list[NormalizedEvidence] = []

        def add(finding_type: str, title: str, description: str, severity: Severity,
                detail: str | None = None) -> None:
            out.append(NormalizedEvidence(
                tool=self.key, target=host, asset_key=asset_key, finding_type=finding_type,
                title=title, description=description, detail=detail, category=CATEGORY,
                severity=severity.value, confidence_class=ConfidenceClass.CONFIRMED.value,
                data_source="Analisi TLS autorizzata", observed_at=datetime.now(UTC)))

        for protocol in LEGACY_PROTOCOLS:
            if posture.get("protocols", {}).get(protocol):
                add("tls_legacy_protocol", f"{host}: protocollo obsoleto {protocol} abilitato",
                    f"Il servizio negozia ancora {protocol}, protocollo deprecato e vulnerabile a "
                    "downgrade e attacchi noti. Va disabilitato lasciando solo TLS 1.2 e 1.3.",
                    Severity.HIGH, detail=protocol)

        for cipher in posture.get("weak_ciphers", []):
            add("tls_weak_cipher", f"{host}: cipher suite debole ({cipher['reason']})",
                f"E' accettata la cipher suite {cipher['name']}, considerata debole. "
                "Va rimossa dalla configurazione TLS.",
                Severity.MEDIUM, detail=str(cipher["name"]))

        days = posture.get("days_to_expiry")
        if days is not None:
            if days < 0:
                add("tls_certificate_expired", f"{host}: certificato TLS scaduto",
                    "Il certificato del servizio e' scaduto: i browser mostrano un errore di "
                    "sicurezza e la connessione non e' piu' considerata attendibile.",
                    Severity.CRITICAL, detail=str(days))
            elif days <= CERT_EXPIRY_WARNING_DAYS:
                add("tls_certificate_expiring", f"{host}: certificato TLS in scadenza tra {days} giorni",
                    "Il certificato scade a breve. Un mancato rinnovo comporta l'interruzione del "
                    "servizio HTTPS.", Severity.MEDIUM, detail=str(days))

        if posture.get("hostname_match") is False:
            add("tls_certificate_hostname_mismatch", f"{host}: hostname non corrispondente al certificato",
                "Il nome host richiesto non compare fra Common Name e SAN del certificato: "
                "il browser segnala la connessione come non attendibile.", Severity.HIGH)
        return out

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        raw: dict[str, Any] = {}
        for domain in self.context.domains:
            posture_model = build_posture(self.context.seed(domain), domain,
                                          self.context.company_name, severity_bias=self.context.severity_bias)
            hosts = [service["host"] for service in posture_model.web_services
                     if service.get("https")][:8] or [domain]
            for host in hosts:
                certificate = dict(posture_model.certificate)
                raw[host] = certificate
                evidences.extend(self._build(host, certificate))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             tool_version="testssl.sh 3.2 (mock)", was_mocked=True,
                             target_count=len(raw), raw_output=self.dump_json(raw))
