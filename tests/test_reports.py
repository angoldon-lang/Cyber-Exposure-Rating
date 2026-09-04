"""Test della generazione dei report (sezione 15)."""
from __future__ import annotations


import pytest

from reporting import service
from reporting.context import build_context, sanitize_finding


def _context(**overrides):
    findings = overrides.pop("findings", None) or [{
        "reference_code": "EML-001", "finding_type": "dmarc_missing",
        "title": "Record DMARC assente", "description": "Il dominio non pubblica DMARC.",
        "category": "email_dns_security", "severity": "high",
        "confidence_class": "confirmed", "ownership_status": "verified_owned",
        "detail": None, "asset_display": "mail:acme-test.example",
        "workflow_state": "scored", "analyst_validation": "not_reviewed",
        "excluded_from_rating": False, "cve_id": None, "cvss_score": None,
        "epss_score": None, "cisa_kev": False, "internet_facing": True,
        "first_seen_at": "01/06/2026", "last_seen_at": "03/09/2026",
        "event_date": None, "applied_deduction": 25.0, "sources": ["checkdmarc"],
        "attributes": {}, "evidence_summary": "Rilevato da: checkdmarc.",
        "impact_it": "Spoofing del dominio aziendale.",
        "remediation": {
            "catalog_id": "REM-EMAIL-DMARC", "title_it": "Implementare DMARC",
            "priority": "p1", "effort": "s", "skills": ["Sistemista DNS"],
            "immediate_action_it": "Pubblicare un record TXT `_dmarc`.",
            "structural_solution_it": "Passare a p=reject.",
            "verification_it": "Il record risolve con policy reject.",
            "references": ["RFC 7489"], "commercial_services": ["Defenix Email Security"],
        },
    }]
    defaults = dict(
        company={"legal_name": "ACME Test S.p.A.", "vat_number": "IT01234567890"},
        scan={"profile_key": "verified_standard",
              "scope_snapshot": {"domains": ["acme-test.example"],
                                 "verified_domains": ["acme-test.example"],
                                 "ip_addresses": [], "network_ranges": [], "excluded": []}},
        score={"overall_score": 63.2, "rating_class": "C",
               "rating_label_it": "Esposizione significativa", "is_provisional": False,
               "provisional_reason": None, "applied_caps": [],
               "categories": [{"key": "email_dns_security", "label_it": "Sicurezza e-mail e DNS",
                               "weight": 0.20, "score": 56.0, "total_deduction": 44.0,
                               "finding_count": 4, "critical_count": 0, "high_count": 2}],
               "confidence": {"value": 83.8, "label_it": "Buona affidabilita'"}},
        findings=findings,
        remediation_plan=[{
            "catalog_id": "REM-EMAIL-DMARC", "title_it": "Implementare DMARC",
            "area": "email_dns_security", "priority": "p1", "effort": "s",
            "skills": ["Sistemista DNS"], "risk_mitigated_it": "Spoofing del dominio.",
            "immediate_action_it": "Pubblicare il record.",
            "structural_solution_it": "Portare la policy a reject.",
            "verification_it": "Il record risolve.", "references": ["RFC 7489"],
            "commercial_services": ["Defenix Email Security"],
            "finding_codes": ["EML-001"], "max_severity": "high",
            "affected_asset_count": 1, "is_quick_win": True,
        }],
        quick_win_items=[], comparison=None,
        coverage_matrix=[{"tool": "checkdmarc", "status": "success",
                          "note_it": "eseguito con successo", "optional": False,
                          "mocked": True, "areas": ["email_dns_security"]}],
        exposure={"total_assets": 20, "verified_assets": 18, "domains": 12,
                  "web_services": 5, "ip_addresses": 3, "open_ports": 0,
                  "findings_total": 1, "critical": 0, "high": 1, "third_party": 2})
    defaults.update(overrides)
    return build_context(**defaults)


# --------------------------------------------------------------------------
# Formati
# --------------------------------------------------------------------------
def test_html_generato():
    report = service.generate_html(_context())
    testo = report.content.decode("utf-8")
    assert "ACME Test S.p.A." in testo
    assert "63" in testo
    assert "Classe C" in testo
    assert "penetration test" in testo


@pytest.mark.slow
def test_pdf_generato():
    report = service.generate_pdf(_context())
    assert report.content.startswith(b"%PDF")
    assert report.size > 10_000
    assert report.filename.endswith(".pdf")


@pytest.mark.slow
def test_docx_generato():
    report = service.generate_docx(_context())
    assert report.content.startswith(b"PK")  # archivio OOXML
    assert report.size > 5_000


def test_json_generato():
    import json

    payload = json.loads(service.generate_json(_context()).content)
    assert payload["company_name"] == "ACME Test S.p.A."
    assert payload["overall_score"] == 63.2
    assert payload["rating_class"] == "C"
    assert payload["schema_version"] == "1.0.0"


def test_csv_generato():
    import csv
    import io

    report = service.generate_csv(_context())
    testo = report.content.decode("utf-8-sig")
    righe = list(csv.DictReader(io.StringIO(testo), delimiter=";"))
    assert len(righe) == 1
    assert righe[0]["reference_code"] == "EML-001"
    assert righe[0]["severity"] == "high"
    assert righe[0]["remediation_id"] == "REM-EMAIL-DMARC"


def test_generazione_multipla():
    prodotti = service.generate(_context(), ["json", "csv", "html"])
    assert {r.format for r in prodotti} == {"json", "csv", "html"}


def test_formato_sconosciuto_ignorato():
    prodotti = service.generate(_context(), ["json", "formato-inesistente"])
    assert [r.format for r in prodotti] == ["json"]


def test_pdf_degrada_su_html(monkeypatch):
    """Se WeasyPrint non e' disponibile il contenuto resta consultabile."""
    def esplodi(*_args, **_kwargs):
        raise RuntimeError("WeasyPrint non disponibile")

    monkeypatch.setitem(service.GENERATORS, "pdf", esplodi)
    prodotti = service.generate(_context(), ["pdf"])
    assert [r.format for r in prodotti] == ["html"]


# --------------------------------------------------------------------------
# Contenuti vietati (sezione 15)
# --------------------------------------------------------------------------
def test_dati_sensibili_non_finiscono_nel_report():
    finding = dict(_context().findings[0])
    finding["attributes"] = {
        "password": "SuperSegreta123", "cookie": "session=abc123",
        "token": "eyJhbGciOi", "leak_content": "contenuto integrale del leak",
        "host": "www.acme-test.example",
    }
    contesto = _context(findings=[finding])
    for formato in ("html", "json", "csv"):
        contenuto = service.GENERATORS[formato](contesto).content.decode("utf-8", "replace")
        for vietato in ("SuperSegreta123", "session=abc123", "eyJhbGciOi",
                        "contenuto integrale del leak"):
            assert vietato not in contenuto


def test_email_mascherata_per_default():
    ripulito = sanitize_finding(
        {"attributes": {"account": "mario.rossi@acme-test.example"}}, unmask_pii=False)
    assert ripulito["attributes"]["account"] == "m*********i@acme-test.example"


def test_email_in_chiaro_con_permesso():
    ripulito = sanitize_finding(
        {"attributes": {"account": "mario.rossi@acme-test.example"}}, unmask_pii=True)
    assert ripulito["attributes"]["account"] == "mario.rossi@acme-test.example"


# --------------------------------------------------------------------------
# Contenuti obbligatori
# --------------------------------------------------------------------------
def test_disclaimer_sempre_presente():
    testo = service.generate_html(_context()).content.decode("utf-8")
    assert "non costituisce un penetration test" in testo.lower()
    assert "certificazione di sicurezza" in testo


def test_limiti_della_valutazione_presenti():
    testo = service.generate_html(_context()).content.decode("utf-8")
    assert "Limiti della valutazione" in testo
    assert "non costituisce prova di sicurezza" in testo


def test_valutazione_provvisoria_evidenziata():
    contesto = _context(score={
        "overall_score": 42.0, "rating_class": "D", "rating_label_it": "Rischio elevato",
        "is_provisional": True,
        "provisional_reason": "Valutazione provvisoria - evidenze insufficienti "
                              "per un rating attendibile.",
        "applied_caps": [], "categories": [],
        "confidence": {"value": 31.0, "label_it": "Affidabilita' insufficiente"}})
    testo = service.generate_html(contesto).content.decode("utf-8")
    assert "Valutazione provvisoria" in testo
    # Il punteggio numerico non viene presentato come definitivo.
    assert "42/100" not in testo


def test_cap_dichiarato_nel_report():
    contesto = _context(score={
        "overall_score": 39.0, "rating_class": "E", "rating_label_it": "Esposizione critica",
        "is_provisional": False, "provisional_reason": None,
        "applied_caps": [{"cap_id": "CAP-RANSOMWARE-ACTIVE", "max_score": 39.0,
                          "reason_it": "Pubblicazione ransomware attiva e confermata"}],
        "categories": [],
        "confidence": {"value": 88.0, "label_it": "Alta affidabilita'"}})
    testo = service.generate_html(contesto).content.decode("utf-8")
    assert "Limitazione del punteggio applicata" in testo
    assert "Pubblicazione ransomware attiva" in testo


def test_proposta_commerciale_separata():
    """La proposta commerciale deve essere distinta dalla raccomandazione tecnica."""
    testo = service.render_html(_context(), "technical.html.j2")
    assert "Servizi professionali collegabili" in testo
    assert "proposta commerciale, distinta dalle" in testo


def test_matrice_di_copertura_nel_report():
    testo = service.generate_html(_context()).content.decode("utf-8")
    assert "Copertura degli strumenti impiegati" in testo
    assert "checkdmarc" in testo


def test_markup_iniettato_non_eseguibile():
    """L'autoescape di Jinja impedisce l'iniezione di markup dai contenuti raccolti."""
    finding = dict(_context().findings[0])
    finding["title"] = "<script>alert('xss')</script>"
    testo = service.generate_html(_context(findings=[finding])).content.decode("utf-8")
    assert "<script>alert" not in testo
    assert "&lt;script&gt;" in testo
