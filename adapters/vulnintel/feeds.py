"""Client per i feed di vulnerability intelligence, con cache su disco."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class KEVEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str | None
    known_ransomware_use: bool


class FeedCache:
    """Cache su file con TTL: evita di interrogare i feed a ogni scansione."""

    def __init__(self, directory: Path, ttl_hours: int = 24) -> None:
        self.directory = directory
        self.ttl_seconds = ttl_hours * 3600
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = "".join(char for char in key if char.isalnum() or char in "-_")
        return self.directory / f"{safe}.json"

    def get(self, key: str) -> Any | None:
        path = self._path(key)
        if not path.is_file():
            return None
        if time.time() - path.stat().st_mtime > self.ttl_seconds:
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, key: str, value: Any) -> None:
        try:
            self._path(key).write_text(json.dumps(value), encoding="utf-8")
        except OSError as exc:  # pragma: no cover
            logger.warning("feed_cache_write_failed", error=str(exc))


def fetch_kev(url: str, cache: FeedCache | None = None) -> dict[str, KEVEntry]:
    """Scarica il catalogo CISA Known Exploited Vulnerabilities."""
    payload = cache.get("cisa_kev") if cache else None
    if payload is None:
        response = httpx.get(url, timeout=60.0, follow_redirects=True)
        response.raise_for_status()
        payload = response.json()
        if cache:
            cache.set("cisa_kev", payload)
    entries: dict[str, KEVEntry] = {}
    for item in payload.get("vulnerabilities", []):
        cve_id = str(item.get("cveID", "")).upper()
        if not cve_id:
            continue
        entries[cve_id] = KEVEntry(
            cve_id=cve_id,
            vendor=str(item.get("vendorProject", "")),
            product=str(item.get("product", "")),
            name=str(item.get("vulnerabilityName", "")),
            date_added=str(item.get("dateAdded", "")),
            due_date=str(item.get("dueDate", "")) or None,
            known_ransomware_use=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
        )
    return entries


def fetch_epss(cve_ids: list[str], base_url: str, cache: FeedCache | None = None) -> dict[str, float]:
    """Recupera gli score EPSS. EPSS e' una PROBABILITA' di sfruttamento,
    non una misura dell'impatto: non sostituisce mai il CVSS."""
    if not cve_ids:
        return {}
    scores: dict[str, float] = {}
    pending: list[str] = []
    for cve_id in cve_ids:
        cached = cache.get(f"epss_{cve_id}") if cache else None
        if cached is not None:
            scores[cve_id] = float(cached)
        else:
            pending.append(cve_id)
    for index in range(0, len(pending), 100):
        batch = pending[index:index + 100]
        try:
            response = httpx.get(base_url, params={"cve": ",".join(batch)}, timeout=30.0)
            response.raise_for_status()
            for item in response.json().get("data", []):
                cve_id = str(item.get("cve", "")).upper()
                score = float(item.get("epss", 0.0))
                scores[cve_id] = score
                if cache:
                    cache.set(f"epss_{cve_id}", score)
        except Exception as exc:  # noqa: BLE001
            logger.warning("epss_fetch_failed", error=type(exc).__name__, batch_size=len(batch))
    return scores
