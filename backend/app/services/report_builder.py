"""Assembla il contesto del report a partire dal database."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scanning import Finding, Remediation, Scan
from app.models.scope import Asset
from app.models.scoring import Score
from app.services.remediation import build_plan, quick_wins
from reporting.context import ReportContext, build_context


def _finding_payload(finding: Finding, asset_display: str | None,
                     remediation: Remediation | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "reference_code": finding.reference_code,
        "finding_type": finding.finding_type,
        "title": finding.title,
        "description": finding.description or "",
        "category": finding.category,
        "severity": finding.severity,
        "confidence_class": finding.confidence_class,
        "ownership_status": finding.ownership_status,
        "detail": finding.detail,
        "asset_display": asset_display or finding.detail or "n/d",
        "workflow_state": finding.workflow_state,
        "analyst_validation": finding.analyst_validation,
        "excluded_from_rating": finding.excluded_from_rating,
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "epss_score": finding.epss_score,
        "cisa_kev": finding.cisa_kev,
        "internet_facing": finding.internet_facing,
        "first_seen_at": finding.first_seen_at.strftime("%d/%m/%Y"),
        "last_seen_at": finding.last_seen_at.strftime("%d/%m/%Y"),
        "event_date": finding.event_date.strftime("%d/%m/%Y") if finding.event_date else None,
        "applied_deduction": finding.applied_deduction,
        "sources": finding.sources_json or [],
        "attributes": finding.attributes_json or {},
        "evidence_summary": _evidence_summary(finding),
        "impact_it": _impact(finding),
    }
    if remediation:
        payload["remediation"] = {
            "catalog_id": remediation.catalog_id,
            "title_it": remediation.title_it,
            "priority": remediation.priority,
            "effort": remediation.effort,
            "skills": remediation.skills_json or [],
            "immediate_action_it": remediation.immediate_action_it or "",
            "structural_solution_it": remediation.structural_solution_it or "",
            "verification_it": remediation.verification_it or "",
            "references": remediation.references_json or [],
            "commercial_services": remediation.commercial_services_json or [],
        }
    return payload


def evidence_summary(finding: Finding) -> str:
    """Sintesi delle evidenze: da quali strumenti proviene il rilievo."""
    return _evidence_summary(finding)


def _evidence_summary(finding: Finding) -> str:
    sources = ", ".join(finding.sources_json or []) or "n/d"
    return (f"Rilevato da: {sources}. "
            f"Evidenze correlate: {len(finding.evidence_ids_json or [])}.")


def _impact(finding: Finding) -> str:
    """Descrizione dell'impatto potenziale, coerente con la severita'."""
    if finding.cisa_kev:
        return ("Vulnerabilita' con evidenze pubbliche di sfruttamento reale: l'impatto "
                "potenziale include la compromissione del servizio esposto e il possibile "
                "accesso alla rete interna.")
    return {
        "critical": "Compromissione diretta di dati o servizi esposti su Internet.",
        "high": "Rischio concreto di accesso non autorizzato o di uso fraudolento del dominio.",
        "medium": "Riduzione delle difese: agevola attacchi che sfruttano altre debolezze.",
        "low": "Impatto limitato, ma contribuisce ad ampliare la superficie di attacco.",
        "info": "Nessun impatto diretto: informazione utile all'inventario e all'igiene tecnica.",
    }.get(finding.severity, "Vedi descrizione del rilievo.")


def _branding_del_tenant(db: Session, tenant_id) -> dict[str, Any]:  # noqa: ANN001
    """Personalizzazione da inserire nel report.

    Il logo viaggia come data URI: WeasyPrint riceve un solo documento e non
    deve risolvere alcun riferimento esterno durante la generazione del PDF.
    """
    import base64

    from app.models.organization import TenantBranding

    riga = db.execute(
        select(TenantBranding).where(TenantBranding.tenant_id == tenant_id)).scalar_one_or_none()
    if riga is None:
        return {}

    dati: dict[str, Any] = {
        "brand_name": riga.brand_name, "brand_owner": riga.brand_owner,
        "primary_color": riga.primary_color, "report_intro_it": riga.report_intro_it,
        "report_footer_it": riga.report_footer_it, "contact_block_it": riga.contact_block_it,
    }
    if riga.logo_bytes:
        codificato = base64.b64encode(riga.logo_bytes).decode("ascii")
        dati["logo_data_uri"] = f"data:{riga.logo_mime or 'image/png'};base64,{codificato}"
    return dati


def build_report_context(db: Session, scan: Scan, *, language: str = "it",
                         unmask_pii: bool = False,
                         comparison: dict[str, Any] | None = None) -> ReportContext:
    company = scan.company
    score = db.execute(select(Score).where(Score.scan_id == scan.id)).scalar_one_or_none()
    if score is None:
        raise ValueError("La scansione non ha un punteggio calcolato: report non generabile")

    findings = db.execute(
        select(Finding).where(Finding.scan_id == scan.id)
        .order_by(Finding.severity, Finding.reference_code)).scalars().all()
    assets = {
        row.id: row.display_name
        for row in db.execute(select(Asset).where(Asset.company_id == company.id)).scalars().all()
    }
    remediations = {
        row.id: row
        for row in db.execute(select(Remediation)).scalars().all()
    }

    payloads = [
        _finding_payload(f, assets.get(f.asset_id), remediations.get(f.remediation_id))
        for f in findings
    ]
    plan_items = build_plan([
        {"finding_type": f.finding_type, "reference_code": f.reference_code,
         "asset_key": assets.get(f.asset_id) or f.detail or "", "severity": f.severity,
         "applied_rules": f.applied_rules_json or []}
        for f in findings if not f.excluded_from_rating])

    asset_rows = list(db.execute(
        select(Asset).where(Asset.company_id == company.id)).scalars().all())
    if not scan.mock_mode:
        # Gli asset visti solo in modalita' dimostrativa restano nel database
        # fra una scansione e l'altra. In un report reale sarebbero
        # indistinguibili dai dati veri: un indirizzo e-mail inventato
        # comparirebbe come «proprieta' verificata».
        asset_rows = [a for a in asset_rows if not a.from_mock_scan]
    exposure = {
        "total_assets": len(asset_rows),
        "verified_assets": sum(1 for a in asset_rows if a.ownership_status == "verified_owned"),
        "domains": sum(1 for a in asset_rows if a.asset_type in {"domain", "subdomain"}),
        "web_services": sum(1 for a in asset_rows if a.asset_type == "web_service"),
        "ip_addresses": sum(1 for a in asset_rows if a.asset_type == "ip_address"),
        "open_ports": sum(1 for a in asset_rows if a.asset_type == "network_service"),
        "third_party": sum(1 for a in asset_rows if a.ownership_status == "third_party"),
        "findings_total": len(findings),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
    }
    inventario = _inventario_asset(asset_rows, unmask_pii=unmask_pii)

    from app.core.config import load_yaml_config

    label = ""
    for entry in load_yaml_config("scoring")["classes"]:
        if entry["code"] == score.rating_class:
            label = str(entry["label_it"])
            break

    return build_context(
        branding=_branding_del_tenant(db, scan.tenant_id),
        company={"legal_name": company.legal_name, "vat_number": company.vat_number},
        scan={"profile_key": scan.profile_key, "scope_snapshot": scan.scope_snapshot_json or {}},
        score={
            "overall_score": score.overall_score,
            "rating_class": score.rating_class,
            "rating_label_it": label,
            "is_provisional": score.is_provisional,
            "provisional_reason": score.provisional_reason,
            "applied_caps": score.applied_caps_json or [],
            "categories": [
                {"key": c.category_key, "label_it": c.label_it, "weight": c.weight,
                 "score": c.score, "total_deduction": c.total_deduction,
                 "finding_count": c.finding_count, "critical_count": c.critical_count,
                 "high_count": c.high_count}
                for c in score.categories],
            "confidence": {
                "value": score.confidence.confidence_value if score.confidence else 0.0,
                "label_it": score.confidence.label_it if score.confidence else "",
            },
        },
        findings=payloads,
        remediation_plan=[item.as_dict() for item in plan_items],
        quick_win_items=[item.as_dict() for item in quick_wins(plan_items)],
        comparison=comparison,
        coverage_matrix=(score.confidence.coverage_matrix_json or []) if score.confidence else [],
        exposure=exposure, asset_inventory=inventario,
        language=language, unmask_pii=unmask_pii)


TIPI_ASSET_IT = {
    "domain": "Domini", "subdomain": "Sottodomini", "ip_address": "Indirizzi IP",
    "network_range": "Reti", "asn": "Sistemi autonomi", "web_service": "Servizi web",
    "mail_service": "Servizi di posta", "network_service": "Servizi di rete",
    "email_address": "Indirizzi e-mail", "brand": "Marchi", "certificate": "Certificati",
}


def _inventario_asset(righe: list[Asset], *, unmask_pii: bool) -> list[dict[str, Any]]:
    """Elenco degli asset osservati, raggruppato per tipo.

    Gli asset scomparsi restano, marcati: un asset non piu' osservato puo'
    essere un servizio dismesso oppure un servizio che non ha risposto, e sono
    due cose diverse che il lettore deve poter distinguere.

    Il nome mostrato e' `display_name`, gia' mascherato all'origine per gli
    indirizzi e-mail; la chiave in chiaro compare solo per il ruolo
    autorizzato a vedere i dati personali.
    """
    gruppi: dict[str, list[dict[str, Any]]] = {}
    for riga in sorted(righe, key=lambda r: (r.asset_type, r.display_name)):
        nome = riga.asset_key if (unmask_pii and riga.asset_type == "email_address") \
            else riga.display_name
        tecnologie = ", ".join(
            " ".join(str(p) for p in (t.get("name"), t.get("version")) if p)
            for t in (riga.technologies_json or []))
        gruppi.setdefault(riga.asset_type, []).append({
            "name": nome,
            "ownership": riga.ownership_status,
            "technologies": tecnologie,
            "discovered_by": ", ".join(riga.discovered_by_json or []),
            "disappeared": riga.disappeared_at is not None,
            "excluded": riga.excluded_from_rating,
        })
    return [{"type": tipo, "label_it": TIPI_ASSET_IT.get(tipo, tipo), "items": voci}
            for tipo, voci in sorted(gruppi.items(), key=lambda v: -len(v[1]))]
