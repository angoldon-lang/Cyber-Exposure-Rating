"""Adapter Ransomware.live: presenza dell'organizzazione sui leak site."""
from __future__ import annotations

import difflib
import re
from datetime import UTC, datetime
from typing import Any

import httpx

from adapters.http_sicuro import get_seguendo_redirect
from adapters.base import AdapterResult, AdapterStatus, BaseAdapter, NormalizedEvidence
from adapters.synthetic import build_posture
from app.models.enums import ConfidenceClass, ScoreCategoryKey, Severity

CATEGORY = ScoreCategoryKey.DARKWEB_BREACH.value
# Soglia di somiglianza oltre la quale la corrispondenza e' considerata
# affidabile. Sotto la soglia si produce un'evidenza `probable` da validare.
STRONG_MATCH_RATIO = 0.92
WEAK_MATCH_RATIO = 0.80

_LEGAL_SUFFIXES = re.compile(
    r"\b(s\.?p\.?a\.?|s\.?r\.?l\.?s?\.?|s\.?n\.?c\.?|s\.?a\.?s\.?|gmbh|ltd|llc|inc|plc|"
    r"corp|corporation|company|co|sa|ag|bv|nv)\b", re.IGNORECASE)


def normalize_company_name(name: str) -> str:
    cleaned = _LEGAL_SUFFIXES.sub(" ", name.lower())
    cleaned = re.sub(r"[^a-z0-9]+", " ", cleaned)
    return " ".join(cleaned.split())


class RansomwareLiveAdapter(BaseAdapter):
    key = "ransomware_live"
    display_name = "Ransomware.live"
    is_passive = True
    coverage_areas = (CATEGORY,)
    default_timeout = 60

    @property
    def base_url(self) -> str:
        return str(self.context.connector_config.get("ransomware_live", {})
                   .get("base_url", "https://api.ransomware.live")).rstrip("/")

    def check_available(self) -> tuple[bool, str]:
        try:
            httpx.get(f"{self.base_url}/recentvictims", timeout=10.0).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            return False, f"API non raggiungibile: {type(exc).__name__}"
        return True, "disponibile"

    # ------------------------------------------------------------------
    def execute(self) -> AdapterResult:
        needle = normalize_company_name(self.context.company_name)
        domain_roots = {domain.split(".")[0].lower() for domain in self.context.domains}
        matches: list[dict[str, Any]] = []
        try:
            with httpx.Client(timeout=30.0, follow_redirects=False) as client:
                # L'API risponde con un 302 legittimo: i salti si seguono, ma
                # ogni destinazione passa dal ScopeGuard.
                response = get_seguendo_redirect(
                    client, f"{self.base_url}/searchvictims/{needle.replace(' ', '%20')}")
                response.raise_for_status()
                candidates = response.json()
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.key, status=AdapterStatus.FAILED,
                                 error_message=f"errore Ransomware.live: {type(exc).__name__}",
                                 coverage_impact=self.coverage_weight)
        if not isinstance(candidates, list):
            candidates = []
        for entry in candidates:
            victim = normalize_company_name(str(entry.get("victim", "")))
            ratio = difflib.SequenceMatcher(None, needle, victim).ratio()
            domain_hit = any(root and root in victim for root in domain_roots)
            if ratio >= WEAK_MATCH_RATIO or domain_hit:
                matches.append({**entry, "match_ratio": round(ratio, 3), "domain_hit": domain_hit})

        evidences = [self._build(match) for match in matches]
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             target_count=1, raw_output=self.dump_json(matches))

    # ------------------------------------------------------------------
    def _build(self, entry: dict[str, Any]) -> NormalizedEvidence:
        """Costruisce l'evidenza.

        Il rating cap sulla pubblicazione ransomware richiede `confirmed`:
        una corrispondenza debole resta `probable` e non attiva il cap, ma
        viene comunque portata all'attenzione dell'analista.
        """
        ratio = float(entry.get("match_ratio", 0.0))
        strong = ratio >= STRONG_MATCH_RATIO or bool(entry.get("domain_hit"))
        group = str(entry.get("group_name") or entry.get("group") or "non identificato")
        published = entry.get("published") or entry.get("discovered")
        try:
            event_date = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            event_date = None
        anchor = self.context.domains[0] if self.context.domains else self.context.company_name
        return NormalizedEvidence(
            tool=self.key, target=self.context.company_name, asset_key=anchor,
            finding_type="ransomware_leak_publication",
            title=f"Pubblicazione su leak site ransomware attribuita al gruppo {group}",
            description=(
                "L'organizzazione risulta pubblicata su un leak site ransomware. La pubblicazione "
                "indica un'esfiltrazione di dati gia' avvenuta e resa nota. "
                + ("La corrispondenza del nome e' forte." if strong else
                   "La corrispondenza del nome e' parziale e richiede validazione da parte di un analista "
                   "prima di essere considerata confermata.")),
            detail=f"{group}:{str(published)[:10]}",
            category=CATEGORY, severity=Severity.CRITICAL.value,
            confidence_class=(ConfidenceClass.CONFIRMED if strong else ConfidenceClass.PROBABLE).value,
            data_source="Ransomware.live", source_url=str(entry.get("post_url") or "")[:1024],
            observed_at=datetime.now(UTC), event_date=event_date,
            # Nessun contenuto del leak viene conservato: solo i metadati.
            attributes={"group": group, "match_ratio": ratio,
                        "post_title": str(entry.get("post_title", ""))[:200],
                        "has_screenshot": bool(entry.get("screenshot"))})

    # ------------------------------------------------------------------
    def mock(self) -> AdapterResult:
        evidences: list[NormalizedEvidence] = []
        raw: list[dict[str, Any]] = []
        for domain in self.context.domains[:1]:
            posture = build_posture(self.context.seed(domain), domain, self.context.company_name,
                                    severity_bias=self.context.severity_bias)
            for post in posture.ransomware:
                entry = {"victim": self.context.company_name, "group_name": post["group"],
                         "published": post["published_at"], "post_title": post["post_title"],
                         "post_url": "https://example.invalid/leak-post-sintetico",
                         "screenshot": post["has_screenshot"], "match_ratio": 1.0, "domain_hit": True}
                raw.append(entry)
                evidences.append(self._build(entry))
        return AdapterResult(tool=self.key, status=AdapterStatus.SUCCESS, evidences=evidences,
                             tool_version="ransomware.live API v2 (mock)", was_mocked=True,
                             target_count=1, raw_output=self.dump_json(raw))
