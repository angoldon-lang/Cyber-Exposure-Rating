"""Adapter checkdmarc: SPF, DKIM, DMARC, DNSSEC, MTA-STS, TLS-RPT, BIMI, DANE.

Il punteggio valuta la CONFIGURAZIONE, non la notorieta' del provider.
I selettori DKIM non vengono indovinati alla cieca: si usano il selettore
indicato dall'utente, quello estratto da un header e-mail o un numero
limitato di selettori standard.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, DiscoveredAsset, NormalizedEvidence
from adapters.synthetic import build_posture
from app.models.enums import AssetType, ConfidenceClass, ScoreCategoryKey, Severity

CATEGORY = ScoreCategoryKey.EMAIL_DNS_SECURITY.value
SPF_MAX_LOOKUPS = 10

# Provider riconoscibili dal record MX. La rilevazione e' dichiarata come
# "detected" (match diretto) o "probable" (indizio indiretto).
MX_PROVIDER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("protection.outlook.com", "Microsoft 365", "detected"),
    ("mail.protection.outlook.com", "Microsoft 365", "detected"),
    ("google.com", "Google Workspace", "detected"),
    ("googlemail.com", "Google Workspace", "detected"),
    ("mimecast.com", "Mimecast (secure email gateway)", "detected"),
    ("pphosted.com", "Proofpoint (secure email gateway)", "detected"),
    ("messagelabs.com", "Broadcom/Symantec (secure email gateway)", "detected"),
    ("barracudanetworks.com", "Barracuda (secure email gateway)", "detected"),
    ("libraesva", "Libraesva (secure email gateway)", "probable"),
    ("aruba.it", "Aruba", "probable"),
    ("register.it", "Register.it", "probable"),
)


class CheckDMARCAdapter(BaseAdapter):
    key = "checkdmarc"
    display_name = "checkdmarc"
    is_passive = True
    coverage_areas = (CATEGORY,)
    default_timeout = 120

    def check_available(self) -> tuple[bool, str]:
        try:
            import checkdmarc  # noqa: F401
        except ImportError:
            # Fallback nativo su dnspython: la copertura resta completa
            # per i controlli principali.
            try:
                import dns.resolver  # noqa: F401
            except ImportError:
                return False, "ne' checkdmarc ne' dnspython disponibili"
            return True, "fallback dnspython (checkdmarc non installato)"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout, resolver.lifetime = 5.0, 10.0
        evidences: list[NormalizedEvidence] = []
        assets: list[DiscoveredAsset] = []
        raw: dict[str, Any] = {}

        domains = self.context.scope_guard.filter_targets(self.context.domains, "hostname")
        for domain in domains:
            posture = self._probe(resolver, domain)
            raw[domain] = posture
            assets.append(DiscoveredAsset(
                asset_key=f"mail:{domain}", asset_type=AssetType.MAIL_SERVICE.value,
                display_name=f"Servizio di posta {domain}", discovered_by=self.key,
                attributes=posture))
            evidences.extend(self._analyse(domain, posture))

        return AdapterResult(
            tool=self.key,
            status=AdapterStatus.SUCCESS if domains else AdapterStatus.SKIPPED,
            evidences=evidences, assets=assets, target_count=len(domains),
            raw_output=self.dump_json(raw),
            error_message=None if domains else "nessun dominio in perimetro")

    def _probe(self, resolver: Any, domain: str) -> dict[str, Any]:
        def txt(name: str) -> list[str]:
            try:
                return [b"".join(r.strings).decode("utf-8", "replace") for r in resolver.resolve(name, "TXT")]
            except Exception:  # noqa: BLE001
                return []

        def exists(name: str, record_type: str) -> bool:
            try:
                resolver.resolve(name, record_type)
                return True
            except Exception:  # noqa: BLE001
                return False

        mx: list[str] = []
        try:
            mx = sorted(str(r.exchange).rstrip(".").lower() for r in resolver.resolve(domain, "MX"))
        except Exception:  # noqa: BLE001
            pass

        spf_records = [r for r in txt(domain) if r.lower().startswith("v=spf1")]
        dmarc_records = [r for r in txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
        dmarc = self._parse_dmarc(dmarc_records[0]) if dmarc_records else {}
        provider, confidence = self._detect_provider(mx)

        posture: dict[str, Any] = {
            "mx": mx,
            "provider": provider,
            "provider_confidence": confidence,
            "spf_present": bool(spf_records),
            "spf_record": spf_records[0] if spf_records else None,
            "spf_multiple": len(spf_records) > 1,
            "spf_valid": bool(spf_records) and self._spf_syntax_ok(spf_records[0]),
            "spf_lookups": self._count_spf_lookups(spf_records[0]) if spf_records else 0,
            "dmarc_present": bool(dmarc_records),
            "dmarc_record": dmarc_records[0] if dmarc_records else None,
            "dmarc_policy": dmarc.get("p"),
            "dmarc_subdomain_policy": dmarc.get("sp"),
            "dmarc_rua": bool(dmarc.get("rua")),
            "dmarc_syntax_ok": bool(dmarc_records) and "p" in dmarc,
            "dnssec": exists(domain, "DNSKEY"),
            "mta_sts": bool(txt(f"_mta-sts.{domain}")),
            "tls_rpt": bool(txt(f"_smtp._tls.{domain}")),
            "bimi": bool(txt(f"default._bimi.{domain}")),
            "dane": any(exists(f"_25._tcp.{host}", "TLSA") for host in mx[:3]),
            "caa": exists(domain, "CAA"),
            "dkim_selectors": self._probe_dkim(txt, domain),
            "starttls": None,  # verificato solo nei profili autorizzati
        }
        return posture

    def _probe_dkim(self, txt: Any, domain: str) -> list[str]:
        """Selettori DKIM: solo quelli forniti o un numero limitato di standard."""
        candidates = list(dict.fromkeys(
            self.context.dkim_selectors
            or list(self.config.get("options", {}).get("dkim_selectors_default", []))
            or ["default", "selector1", "selector2", "google", "k1", "mail"]
        ))
        limit = int(self.config.get("options", {}).get("dkim_max_lookups", 12))
        found: list[str] = []
        for selector in candidates[:limit]:
            if any("v=dkim1" in record.lower() for record in txt(f"{selector}._domainkey.{domain}")):
                found.append(selector)
        return found

    # ------------------------------------------------------------------
    @staticmethod
    def _detect_provider(mx_records: list[str]) -> tuple[str | None, str | None]:
        for host in mx_records:
            for needle, name, confidence in MX_PROVIDER_SIGNATURES:
                if needle in host:
                    return name, confidence
        return ("Provider non riconosciuto", "probable") if mx_records else (None, None)

    @staticmethod
    def _parse_dmarc(record: str) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for part in record.split(";"):
            key, _, value = part.strip().partition("=")
            if key and value:
                parsed[key.strip().lower()] = value.strip()
        return parsed

    @staticmethod
    def _spf_syntax_ok(record: str) -> bool:
        tokens = record.split()
        if not tokens or tokens[0].lower() != "v=spf1":
            return False
        return any(token.lower().endswith("all") for token in tokens)

    @staticmethod
    def _count_spf_lookups(record: str) -> int:
        mechanisms = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")
        return sum(1 for token in record.split()
                   if any(token.lower().startswith(m) or token.lower() == m.rstrip(":")
                          for m in mechanisms))

    # ------------------------------------------------------------------
    def _analyse(self, domain: str, posture: dict[str, Any]) -> list[NormalizedEvidence]:
        """Traduce la postura e-mail in evidenze normalizzate.

        Ogni evidenza e' `confirmed`: l'assenza di un record DNS pubblico e'
        un fatto verificabile, non un'inferenza.
        """
        out: list[NormalizedEvidence] = []

        def add(finding_type: str, title: str, description: str, severity: Severity,
                confidence: ConfidenceClass = ConfidenceClass.CONFIRMED,
                detail: str | None = None) -> None:
            out.append(NormalizedEvidence(
                tool=self.key, target=domain, asset_key=f"mail:{domain}",
                finding_type=finding_type, title=title, description=description, detail=detail,
                category=CATEGORY, severity=severity.value, confidence_class=confidence.value,
                data_source="DNS pubblico (SPF/DMARC/MTA-STS)", observed_at=datetime.now(UTC),
                attributes={"provider": posture.get("provider"),
                            "provider_confidence": posture.get("provider_confidence")}))

        # --- SPF ---
        if not posture["spf_present"]:
            add("spf_missing", "Record SPF assente",
                "Il dominio non pubblica un record SPF: chiunque puo' inviare messaggi "
                "dichiarando questo dominio come mittente senza essere respinto dai controlli SPF.",
                Severity.HIGH)
        else:
            if posture["spf_multiple"]:
                add("spf_multiple_records", "Record SPF multipli",
                    "Sono presenti piu' record SPF per lo stesso dominio. Le specifiche impongono "
                    "un solo record: la presenza di piu' record rende la valutazione SPF non valida.",
                    Severity.MEDIUM)
            if not posture["spf_valid"]:
                add("spf_invalid", "Record SPF non valido",
                    "Il record SPF presenta errori di sintassi o non termina con un meccanismo "
                    "`all`: la valutazione da parte dei destinatari e' inaffidabile.",
                    Severity.MEDIUM)
            if posture["spf_lookups"] > SPF_MAX_LOOKUPS:
                add("spf_too_many_lookups",
                    f"SPF con troppi lookup DNS ({posture['spf_lookups']})",
                    f"Il record SPF richiede {posture['spf_lookups']} lookup DNS a fronte di un "
                    f"massimo di {SPF_MAX_LOOKUPS}. Oltre il limite la verifica restituisce "
                    "`permerror` e il record perde efficacia.",
                    Severity.MEDIUM, detail=str(posture["spf_lookups"]))

        # --- DMARC ---
        if not posture["dmarc_present"]:
            add("dmarc_missing", "Record DMARC assente",
                "Il dominio non pubblica una policy DMARC: non esistono istruzioni per i "
                "destinatari sui messaggi non autenticati, ne' visibilita' tramite report aggregati.",
                Severity.HIGH)
        else:
            if not posture["dmarc_syntax_ok"]:
                add("dmarc_syntax_error", "Record DMARC con errori di sintassi",
                    "Il record DMARC non e' interpretabile correttamente: la policy dichiarata "
                    "potrebbe non essere applicata dai destinatari.", Severity.MEDIUM)
            if posture["dmarc_policy"] == "none":
                add("dmarc_policy_none", "Policy DMARC non protettiva (p=none)",
                    "La policy DMARC e' in sola osservazione: i messaggi non autenticati vengono "
                    "comunque consegnati. La policy va portata a `quarantine` e quindi `reject`.",
                    Severity.MEDIUM, detail="p=none")
            if posture.get("dmarc_subdomain_policy") == "none":
                add("dmarc_subdomain_policy_weak", "Policy DMARC dei sottodomini non protettiva",
                    "La direttiva `sp=none` lascia i sottodomini privi di protezione: sono un "
                    "vettore frequente di spoofing.", Severity.MEDIUM, detail="sp=none")
            if not posture["dmarc_rua"]:
                add("dmarc_no_reporting", "Reporting DMARC non configurato",
                    "Senza destinatario `rua=` non si ricevono i report aggregati e non e' "
                    "possibile verificare l'allineamento delle sorgenti di invio legittime.",
                    Severity.LOW)

        # --- spoofing complessivo ---
        if not posture["spf_present"] and not posture["dmarc_present"]:
            add("spoofing_possible", "Il dominio e' esposto allo spoofing",
                "In assenza di SPF e DMARC il dominio puo' essere utilizzato per inviare e-mail "
                "fraudolente a clienti, fornitori e dipendenti senza che i destinatari dispongano "
                "di un criterio di rifiuto.", Severity.HIGH)

        # --- DKIM ---
        if not posture["dkim_selectors"]:
            add("dkim_no_selector_found", "Nessun selettore DKIM verificabile",
                "Non e' stato individuato alcun selettore DKIM tra quelli indicati o standard. "
                "Senza DKIM l'allineamento DMARC si regge sul solo SPF, che non sopravvive "
                "agli inoltri.", Severity.MEDIUM, ConfidenceClass.PROBABLE)

        # --- trasporto e DNS ---
        if not posture["dnssec"]:
            add("dnssec_missing", "DNSSEC non attivo",
                "La zona DNS non e' firmata: la risoluzione non e' protetta da manipolazioni "
                "lungo il percorso.", Severity.LOW)
        if not posture["mta_sts"]:
            add("mta_sts_missing", "MTA-STS non configurato",
                "Senza MTA-STS la consegna SMTP puo' subire un downgrade a trasmissione in chiaro.",
                Severity.LOW)
        if not posture["tls_rpt"]:
            add("tls_rpt_missing", "SMTP TLS Reporting non configurato",
                "Non si ricevono report sugli errori di negoziazione TLS in ingresso.", Severity.INFO)
        # Il record CAA riguarda l'emissione di certificati per il dominio, non il
        # servizio di posta: e' l'adapter DNS ad ancorarlo all'asset dominio. Se lo
        # ripetessimo qui sull'asset "mail:" lo stesso problema comparirebbe due
        # volte nel report, con due impronte diverse.
        if posture.get("starttls") is False:
            add("starttls_unsupported", "STARTTLS non supportato dai server di posta",
                "Uno o piu' MX non negoziano STARTTLS: la posta transita in chiaro fra i server.",
                Severity.MEDIUM)
        return out

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        assets: list[DiscoveredAsset] = []
        raw: dict[str, Any] = {}
        allow_starttls = self.context.profile in {"verified_standard", "verified_extended"}

        for domain in self.context.domains:
            posture_model = build_posture(self.context.seed(domain), domain,
                                          self.context.company_name, severity_bias=self.context.severity_bias)
            posture = dict(posture_model.email)
            posture["starttls"] = posture["starttls"] if allow_starttls else None
            raw[domain] = posture
            assets.append(DiscoveredAsset(
                asset_key=f"mail:{domain}", asset_type=AssetType.MAIL_SERVICE.value,
                display_name=f"Servizio di posta {domain}", discovered_by=self.key,
                attributes=posture))
            evidences.extend(self._analyse(domain, posture))

        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             assets=assets, tool_version="checkdmarc 5.x (mock)", was_mocked=True,
                             target_count=len(self.context.domains), raw_output=self.dump_json(raw))
