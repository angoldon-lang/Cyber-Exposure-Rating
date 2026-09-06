"""Adapter testssl.sh: protocolli, cipher, certificati e vulnerabilita' TLS."""
from __future__ import annotations

import json
import re
import socket
import time
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

# Quando l'host presenta piu' di un certificato (tipico con RSA ed ECDSA
# insieme) testssl aggiunge « <hostCert#2>» all'identificatore del rilievo.
# Senza toglierlo, il confronto per uguaglianza fallisce proprio sugli host
# meglio configurati.
_POSTFIX_CERTIFICATO = re.compile(r"\s*<hostCert#\d+>\s*$")
_GIORNI_FRA_PARENTESI = re.compile(r"\((-?\d+)\)")
_PRIMO_INTERO = re.compile(r"-?\d+")


def rilievi_testssl(payload: Any) -> list[dict[str, Any]]:
    """Appiattisce l'output di testssl in una lista di rilievi.

    Con `--jsonfile-pretty` testssl non scrive una lista piatta: mette ogni
    host sotto `scanResult` e, dentro l'host, distribuisce i rilievi in una
    lista per sezione (`protocols`, `ciphers`, `serverDefaults`,
    `vulnerabilities`, `headerResponse`, ...).

    Il codice precedente iterava direttamente `scanResult`, il cui unico
    elemento e' l'host e non ha alcun campo `id`: nessun rilievo veniva
    riconosciuto e testssl restituiva zero evidenze a ogni scansione, pur
    consumando la maggior parte del tempo dell'analisi.

    Si accetta anche la forma piatta prodotta da `--jsonfile`, cosi' il
    parser non dipende dall'opzione scelta.
    """
    if isinstance(payload, list):
        voci: list[Any] = payload
    elif isinstance(payload, dict):
        voci = payload.get("scanResult") or []
    else:
        return []

    rilievi: list[dict[str, Any]] = []
    for voce in voci:
        if not isinstance(voce, dict):
            continue
        if "id" in voce:                      # forma piatta
            rilievi.append(voce)
            continue
        for sezione in voce.values():         # sezioni dell'host
            if isinstance(sezione, list):
                rilievi.extend(r for r in sezione if isinstance(r, dict) and "id" in r)
    return rilievi


def giorni_alla_scadenza(finding: str) -> int | None:
    """Giorni residui letti da `cert_expirationStatus`.

    testssl usa tre forme, e la seconda e la terza si somigliano abbastanza
    da confondersi:

        «expired»                 -> certificato gia' scaduto
        «89 >= 60 days»           -> il residuo e' il primo numero
        «expires < 30 days (25)»  -> il residuo e' quello fra parentesi;
                                     il 30 e' la soglia di allarme, e
                                     leggerlo al suo posto fa credere che il
                                     certificato duri piu' di quanto duri
    """
    if "expired" in finding.lower():
        return -1
    fra_parentesi = _GIORNI_FRA_PARENTESI.search(finding)
    if fra_parentesi:
        return int(fra_parentesi.group(1))
    primo = _PRIMO_INTERO.search(finding)
    return int(primo.group()) if primo else None


def _risolve(host: str) -> bool:
    """Vero se il nome ha almeno un indirizzo IP.

    Serve solo a non sprecare il budget su nomi che non esistono piu': la
    decisione su cosa sia in perimetro resta dello ScopeGuard, che ha gia'
    filtrato l'elenco.
    """
    try:
        socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    return True


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

        # I nomi arrivano anche dai log di Certificate Transparency, dove
        # restano quelli di certificati emessi per host poi dismessi. Su
        # quelli testssl esce con codice 247 («No IPv4/IPv6 address(es)
        # available») dopo aver comunque atteso il DNS: nell'ultima scansione
        # erano la maggior parte dei fallimenti. Un nome che non risolve non
        # e' un TLS non verificato: non e' un host.
        risolti = [h for h in targets if _risolve(h)]
        non_risolti = len(targets) - len(risolti)
        targets = risolti
        if not targets:
            return AdapterResult(tool=self.key, status=AdapterStatus.SKIPPED,
                                 error_message="nessun host del perimetro risolve in un indirizzo",
                                 coverage_impact=self.coverage_weight)

        # testssl.sh e' lento per costruzione: prova centinaia di combinazioni
        # di cifrari e protocolli, un host alla volta. Con il solo timeout per
        # host, venticinque host da dieci minuti fanno oltre quattro ore, e la
        # scansione resta in corso senza che nulla sia andato storto. Il tetto
        # complessivo interrompe l'analisi e dichiara quanti host sono rimasti
        # fuori: una copertura parziale e dichiarata vale piu' di una completa
        # che non arriva mai.
        budget = float(self.config.get("total_budget_seconds", 900))
        scadenza = time.monotonic() + budget
        per_host = int(self.config.get("timeout_seconds", self.default_timeout))

        evidences: list[NormalizedEvidence] = []
        raw: dict[str, Any] = {}
        failures = 0
        analizzati = 0
        for host in targets:
            residuo = scadenza - time.monotonic()
            if residuo <= 0:
                break
            analizzati += 1
            with TemporaryWorkspace("defenix-testssl-") as workspace:
                outfile = workspace / "result.json"
                args = ["--jsonfile-pretty", str(outfile), "--quiet", "--color", "0",
                        "--severity", "LOW", "--sneaky", host]
                try:
                    result = run_command(BINARY, args, allow_flags=ALLOWED_FLAGS,
                                         timeout=max(30, int(min(per_host, residuo))),
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

        non_analizzati = len(targets) - analizzati
        status = (AdapterStatus.SUCCESS if failures == 0 and not non_analizzati
                  else AdapterStatus.PARTIAL if failures < analizzati or non_analizzati
                  else AdapterStatus.FAILED)
        motivo = None
        if non_analizzati:
            motivo = (f"tempo massimo dello strumento ({int(budget)} s) esaurito: "
                      f"{non_analizzati} host su {len(targets)} non sono stati verificati")
        if non_risolti:
            nota = (f"{non_risolti} nomi del perimetro non risolvono in un indirizzo "
                    "e non sono stati provati")
            motivo = f"{motivo}; {nota}" if motivo else nota
        return AdapterResult(tool=self.key, status=status, evidences=evidences,
                             target_count=analizzati, error_message=motivo,
                             raw_output=self.dump_json(raw),
                             # Gli host non analizzati pesano sulla copertura
                             # quanto quelli falliti: in entrambi i casi il
                             # TLS di quell'host non e' stato verificato.
                             coverage_impact=self.coverage_weight
                             * ((failures + non_analizzati) / len(targets)))

    def _analyse_testssl(self, host: str, findings: list[dict[str, Any]] | dict) -> list[NormalizedEvidence]:
        """Traduce l'output nativo di testssl.sh in evidenze normalizzate."""
        posture: dict[str, Any] = {"protocols": {}, "weak_ciphers": [], "days_to_expiry": None,
                                   "hostname_match": True}
        for item in rilievi_testssl(findings):
            identifier = _POSTFIX_CERTIFICATO.sub("", str(item.get("id", "")))
            finding = str(item.get("finding", ""))
            severity = str(item.get("severity", "")).upper()
            if identifier in {"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}:
                label = {"TLS1": "TLSv1.0", "TLS1_1": "TLSv1.1", "TLS1_2": "TLSv1.2",
                         "TLS1_3": "TLSv1.3"}.get(identifier, identifier)
                posture["protocols"][label] = "offered" in finding and "not" not in finding
            if severity in {"HIGH", "CRITICAL", "MEDIUM"} and "cipher" in identifier.lower():
                posture["weak_ciphers"].append({"name": identifier, "reason": finding[:120]})
            if identifier == "cert_expirationStatus":
                posture["days_to_expiry"] = giorni_alla_scadenza(finding)
            # testssl non emette alcun `cert_hostnameMismatch`: il nome che
            # non corrisponde e' un esito della catena di fiducia.
            if identifier == "cert_chain_of_trust" and \
                    "does not match supplied uri" in finding.lower():
                posture["hostname_match"] = False
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
