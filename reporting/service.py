"""Generazione dei report: HTML, PDF, Word, JSON e CSV."""
from __future__ import annotations

import re

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from app.core.config import settings
from app.core.logging import get_logger
from reporting.context import (
    CONFIDENCE_LABEL_IT,
    OWNERSHIP_LABEL_IT,
    SEVERITY_LABEL_IT,
    TIPO_VERIFICA_IT,
    ReportContext,
)
from reporting.narrativa import sintesi_per_la_direzione

logger = get_logger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


@dataclass
class GeneratedReport:
    format: str
    content: bytes
    filename: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    @property
    def size(self) -> int:
        return len(self.content)


def _environment() -> Environment:
    # `autoescape` attivo: nessun contenuto raccolto da Internet puo' iniettare
    # markup nel report.
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True, lstrip_blocks=True)
    return env


def _stylesheet() -> str:
    return (TEMPLATE_DIR / "base.css").read_text(encoding="utf-8")


# I due documenti sono renderizzati separatamente e le pagine concatenate:
# `counter(pages)` vale percio' per ciascuno dei due, e nel PDF finale la
# numerazione riparte da uno a meta' documento. Non si puo' unificare senza
# unire i due modelli; si puo' pero' dire a quale dei due appartiene ogni
# numero, che e' cio' che serve a chi ha il documento in mano.
_NUMERAZIONE_ALLEGATO = """
@page {
  @bottom-right { content: "Allegato tecnico - pagina " counter(page) " di " counter(pages); }
}
"""


def render_html(context: ReportContext, template_name: str) -> str:
    template = _environment().get_template(template_name)
    # Il foglio di stile va passato come `Markup`, altrimenti l'autoescape gli
    # trasforma ogni virgoletta in `&#34;` e il CSS arriva a WeasyPrint con
    # tutte le stringhe rotte: `content: "Pagina "` non produce nulla,
    # `font-family: "DejaVu Sans"` cade sul ripiego generico. Il contenuto e'
    # nostro: l'unico valore che arriva dall'esterno e' il colore del tenant,
    # che `_stylesheet_per` accetta solo in notazione esadecimale.
    stile = _stylesheet_per(context)
    if template_name == "technical.html.j2":
        stile += _NUMERAZIONE_ALLEGATO
    return template.render(**context.as_dict(), stylesheet=Markup(stile))


def _stylesheet_per(context: ReportContext) -> str:
    """Foglio di stile con il colore del tenant, se impostato.

    Il valore e' gia' vincolato alla sola notazione esadecimale dallo schema di
    validazione: qui viene comunque riverificato, perche' il foglio di stile
    viene consegnato al modello come `Markup` e non passa quindi
    dall'autoescape.
    """
    base = _stylesheet()
    colore = (context.brand or {}).get("color") or ""
    if not re.fullmatch(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})", colore):
        return base
    return (f"{base}\n:root {{ --brand: {colore}; }}\n"
            f"h1, h2, h3 {{ color: {colore}; }}\n"
            f".masthead {{ border-bottom-color: {colore}; }}\n")


def _slug(value: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in value]
    return "".join(keep).strip("-")[:60] or "report"


# ---------------------------------------------------------------------------
def generate_html(context: ReportContext, *, include_technical: bool = True) -> GeneratedReport:
    parts = [render_html(context, "executive.html.j2")]
    if include_technical:
        parts.append(render_html(context, "technical.html.j2"))
    content = "\n".join(parts).encode("utf-8")
    name = f"defenix-security-rating-{_slug(context.company_name)}-{context.generated_at:%Y%m%d}"
    return GeneratedReport("html", content, f"{name}.html")


def generate_pdf(context: ReportContext, *, include_technical: bool = True) -> GeneratedReport:
    """PDF via WeasyPrint. Se la libreria non e' disponibile viene sollevata
    un'eccezione esplicita: il chiamante degrada su HTML."""
    from weasyprint import HTML  # import locale: dipendenze di sistema pesanti

    documents = [HTML(string=render_html(context, "executive.html.j2")).render()]
    if include_technical:
        documents.append(HTML(string=render_html(context, "technical.html.j2")).render())

    pages = [page for document in documents for page in document.pages]
    pdf_bytes = documents[0].copy(pages).write_pdf()
    name = f"defenix-security-rating-{_slug(context.company_name)}-{context.generated_at:%Y%m%d}"
    return GeneratedReport("pdf", pdf_bytes, f"{name}.pdf")


def generate_docx(context: ReportContext, *, include_technical: bool = True) -> GeneratedReport:
    """Report Word tramite python-docx.

    Segue la stessa scaletta del PDF, con gli stessi testi: chi esporta in
    Word perche' deve rimaneggiare il documento non deve ritrovarsi con una
    versione che dice altro.
    """
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Pt, RGBColor

    document = Document()
    direzione = sintesi_per_la_direzione(
        categories=context.categories, coverage_matrix=context.coverage_matrix,
        remediation_plan=context.remediation_plan, overall_score=context.overall_score)

    def _tabella(intestazioni: tuple[str, ...]):  # noqa: ANN202
        tabella = document.add_table(rows=1, cols=len(intestazioni))
        tabella.style = "Light Grid Accent 1"
        for indice, etichetta in enumerate(intestazioni):
            tabella.rows[0].cells[indice].text = etichetta
        return tabella

    # --- apertura ---
    if context.is_demo:
        avviso = document.add_paragraph()
        corsa = avviso.add_run("Documento dimostrativo - dati sintetici, "
                               "non una valutazione reale")
        corsa.bold = True
        corsa.font.color.rgb = RGBColor(0x9B, 0x1C, 0x1C)

    titolo = document.add_heading(
        "Quanto e' esposta l'azienda, spiegato in parole semplici", level=0)
    titolo.alignment = WD_ALIGN_PARAGRAPH.LEFT
    document.add_paragraph(
        "Questo documento riassume in poche pagine il risultato della verifica tecnica. "
        "Nessuna sigla senza spiegazione: che cosa abbiamo visto, che cosa puo' succedere "
        "e che cosa conviene fare.")

    anagrafica = document.add_table(rows=0, cols=2)
    anagrafica.style = "Light List Accent 1"
    domini = ", ".join(context.domini_analizzati()) or "nessuno"
    for etichetta, valore in (
        ("Azienda", context.company_name),
        ("P.IVA / VAT", context.company_vat or "-"),
        ("Domini analizzati" if len(context.domini_analizzati()) > 1 else "Dominio analizzato",
         domini),
        ("Data della verifica", f"{context.generated_at:%d/%m/%Y}"),
        ("Tipo di verifica", TIPO_VERIFICA_IT.get(
            context.profile_key, "Analisi dall'esterno, senza accesso ai sistemi aziendali")),
    ):
        riga = anagrafica.add_row().cells
        riga[0].text = etichetta
        riga[1].text = valore

    # --- il risultato ---
    document.add_heading("Il risultato in due righe", level=1)
    esito = document.add_paragraph()
    if context.is_provisional:
        corsa = esito.add_run("Valutazione provvisoria")
        corsa.font.size = Pt(20)
        corsa.font.color.rgb = RGBColor(0xC2, 0x41, 0x0C)
        document.add_paragraph(context.provisional_notice or "")
    else:
        corsa = esito.add_run(f"{context.overall_score:.0f}/100 - Classe {context.rating_class} "
                              f"- {context.rating_label.lower()}")
        corsa.bold = True
        corsa.font.size = Pt(20)
        document.add_paragraph(direzione["sintesi_risultato"])
    document.add_paragraph(f"In pratica: {direzione['in_pratica']}")

    if context.applied_caps:
        document.add_paragraph("Il punteggio e' stato limitato d'ufficio:").bold = True
        for cap in context.applied_caps:
            document.add_paragraph(
                f"{cap.get('reason_it', '')} - punteggio massimo consentito: "
                f"{int(cap.get('max_score', 0))}/100", style="List Bullet")

    # --- le aree ---
    document.add_heading(direzione["titolo_aree"], level=1)
    aree = _tabella(("Area", "Esito", "Che cosa significa"))
    for area in direzione["aree"]:
        riga = aree.add_row().cells
        riga[0].text = area["nome"]
        riga[1].text = f"{area['punteggio']:.0f}/100"
        riga[2].text = " ".join(x for x in (area["significato"], area["nota_copertura"]) if x)

    document.add_heading("Il perimetro osservato", level=1)
    perimetro = _tabella(("Elementi aziendali", "Domini e sottodomini",
                          "Indirizzi internet", "Rilievi complessivi"))
    riga = perimetro.add_row().cells
    riepilogo = context.exposure_summary
    riga[0].text = (f"{riepilogo.get('total_assets', 0)} "
                    f"({riepilogo.get('verified_assets', 0)} confermati dell'azienda)")
    riga[1].text = str(riepilogo.get("domains", 0))
    riga[2].text = str(riepilogo.get("ip_addresses", 0))
    riga[3].text = (f"{riepilogo.get('findings_total', 0)} "
                    f"({riepilogo.get('critical', 0)} critici, {riepilogo.get('high', 0)} gravi)")

    avvertenza = direzione["avvertenza_punteggio"]
    document.add_paragraph(avvertenza["titolo"]).bold = True
    document.add_paragraph(
        f"Affidabilita' della rilevazione: {context.confidence_value:.0f}%. Dove un controllo "
        f"non gira, l'area resta alta per assenza di prove, non perche' sia stato dimostrato "
        f"che tutto e' a posto. {avvertenza['chiusura']}")

    # --- che cosa abbiamo trovato ---
    document.add_page_break()
    document.add_heading("Che cosa abbiamo trovato", level=1)
    schede = direzione["rilievi"]["schede"]
    if schede:
        for indice, scheda in enumerate(schede, start=1):
            document.add_heading(
                f"{indice}. {scheda['titolo']} [{scheda['etichetta_gravita']}]", level=2)
            for etichetta, testo in (("Che cosa manca", scheda["manca"]),
                                     ("Un paragone", scheda["paragone"]),
                                     ("Che cosa comporta", scheda["comporta"]),
                                     ("Impegno per sistemarlo", scheda["tempo"])):
                if not testo:
                    continue
                paragrafo = document.add_paragraph()
                paragrafo.add_run(f"{etichetta}: ").bold = True
                paragrafo.add_run(testo)
        if direzione["rilievi"]["informativi"]:
            document.add_paragraph(
                "Rilievi puramente informativi, che non incidono sul punteggio: "
                + "; ".join(direzione["rilievi"]["informativi"]) + ".")
        if direzione["buona_notizia"]:
            document.add_paragraph("La buona notizia").bold = True
            document.add_paragraph(direzione["buona_notizia"])
    else:
        document.add_paragraph(
            "Nel perimetro analizzato non sono emersi rilievi che richiedano un intervento. "
            "L'assenza di rilievi non costituisce prova di sicurezza.")

    # --- che cosa puo' succedere ---
    scenario = direzione["scenario"]
    if scenario:
        document.add_heading("Che cosa puo' succedere davvero", level=1)
        document.add_paragraph(scenario["premessa"])
        document.add_paragraph(scenario["titolo"]).bold = True
        for passo in scenario["passi"]:
            document.add_paragraph(passo, style="List Number")
        if scenario["variante"]:
            document.add_paragraph(scenario["variante"])

        document.add_heading("Perche' il danno non e' solo economico", level=1)
        for voce in direzione["danno_oltre_il_denaro"]:
            paragrafo = document.add_paragraph(style="List Bullet")
            paragrafo.add_run(f"{voce['titolo']} ").bold = True
            paragrafo.add_run(voce["testo"])

    document.add_heading("Che cosa questa verifica non ha guardato", level=1)
    for voce in direzione["limiti_divulgativi"]:
        document.add_paragraph(voce, style="List Bullet")
    document.add_paragraph(
        f"La fotografia vale al {context.generated_at:%d/%m/%Y}. Un'esposizione puo' nascere "
        f"la settimana successiva, con un nuovo servizio pubblicato o un fornitore che cambia "
        f"configurazione.", style="List Bullet")

    # --- che cosa fare ---
    if direzione["interventi"]:
        document.add_page_break()
        document.add_heading("Che cosa fare, in ordine", level=1)
        piano = _tabella(("#", "Intervento", "Quando", "Come verificare che sia fatto"))
        for indice, voce in enumerate(direzione["interventi"], start=1):
            riga = piano.add_row().cells
            riga[0].text = str(indice)
            riga[1].text = " - ".join(x for x in (voce["titolo"], voce["in_parole"]) if x)
            riga[2].text = " - ".join(x for x in (voce["quando"], voce["tempo"]) if x)
            riga[3].text = voce["verifica"]

    domande = direzione["domande"]
    if domande.get("voci"):
        document.add_heading(direzione["titolo_domande"], level=1)
        document.add_paragraph(
            "Non serve altro per far partire la maggior parte del lavoro. "
            "Chiedi una risposta scritta.")
        for voce in domande["voci"]:
            paragrafo = document.add_paragraph(style="List Number")
            paragrafo.add_run(voce["domanda"]).bold = True
            paragrafo.add_run(f" {voce['attesa']}")

    raccomandazione = direzione["raccomandazione_finale"]
    document.add_heading(raccomandazione["titolo"], level=1)
    document.add_paragraph(raccomandazione["testo"])

    if context.contact_block:
        document.add_heading("Il passo successivo", level=1)
        document.add_paragraph(context.contact_block)

    # --- allegato tecnico ---
    if include_technical:
        document.add_page_break()
        document.add_heading("Allegato tecnico", level=1)
        document.add_paragraph(
            "Evidenze sanitizzate. Non sono riportati credenziali, token, cookie, contenuti "
            "integrali di leak, istruzioni di sfruttamento ne' payload offensivi.")
        for finding in context.findings:
            document.add_heading(
                f"{finding.get('reference_code')} - {finding.get('title')}", level=2)
            details = document.add_paragraph()
            details.add_run(
                f"Severita': {SEVERITY_LABEL_IT.get(str(finding.get('severity')), '')} | "
                f"Attendibilita': {CONFIDENCE_LABEL_IT.get(str(finding.get('confidence_class')), '')} | "
                f"Asset: {finding.get('asset_display') or finding.get('detail') or 'n/d'} "
                f"({OWNERSHIP_LABEL_IT.get(str(finding.get('ownership_status')), '')})").italic = True
            document.add_paragraph(str(finding.get("description", "")))
            if finding.get("cve_id"):
                document.add_paragraph(
                    f"CVE: {finding['cve_id']} | CVSS: {finding.get('cvss_score', 'n/d')} | "
                    f"EPSS: {finding.get('epss_score', 'n/d')} | "
                    f"CISA KEV: {'si' if finding.get('cisa_kev') else 'no'}")
            remediation = finding.get("remediation")
            if remediation:
                document.add_paragraph(f"Remediation: {remediation['title_it']}")
                document.add_paragraph(f"Azione immediata: {remediation['immediate_action_it']}")
                document.add_paragraph(f"Verifica: {remediation['verification_it']}")

    document.add_paragraph()
    nota = document.add_paragraph()
    nota.add_run("Nota metodologica. ").bold = True
    nota.add_run(
        f"Perimetro analizzato, inventario degli asset, copertura degli strumenti, elenco "
        f"integrale dei rilievi e piano di rimedio completo sono nell'allegato tecnico. "
        f"In caso di differenze fa fede l'allegato tecnico. {context.disclaimer} "
        f"Documento riservato prodotto da {context.brand['owner']}. Distribuzione limitata "
        f"al destinatario.").italic = True

    buffer = io.BytesIO()
    document.save(buffer)
    name = f"defenix-security-rating-{_slug(context.company_name)}-{context.generated_at:%Y%m%d}"
    return GeneratedReport("docx", buffer.getvalue(), f"{name}.docx")


def generate_json(context: ReportContext) -> GeneratedReport:
    payload = context.as_dict()
    payload.pop("severity_label", None)
    payload.pop("confidence_label_map", None)
    payload.pop("ownership_label", None)
    payload.pop("effort_label", None)
    payload.pop("priority_label", None)
    payload["generated_at"] = context.generated_at.isoformat()
    payload["schema_version"] = "1.0.0"
    content = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
    name = f"defenix-security-rating-{_slug(context.company_name)}-{context.generated_at:%Y%m%d}"
    return GeneratedReport("json", content, f"{name}.json")


CSV_COLUMNS = [
    "reference_code", "severity", "category", "finding_type", "title", "confidence_class",
    "ownership_status", "asset", "workflow_state", "analyst_validation", "excluded_from_rating",
    "cve_id", "cvss_score", "epss_score", "cisa_kev", "internet_facing",
    "first_seen_at", "last_seen_at", "event_date", "applied_deduction",
    "remediation_id", "remediation_title", "remediation_priority", "remediation_effort",
    "sources",
]


def generate_csv(context: ReportContext) -> GeneratedReport:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore",
                            delimiter=";", quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()
    for finding in context.findings:
        remediation = finding.get("remediation") or {}
        writer.writerow({
            "reference_code": finding.get("reference_code"),
            "severity": finding.get("severity"),
            "category": finding.get("category"),
            "finding_type": finding.get("finding_type"),
            "title": finding.get("title"),
            "confidence_class": finding.get("confidence_class"),
            "ownership_status": finding.get("ownership_status"),
            "asset": finding.get("asset_display") or finding.get("detail") or "",
            "workflow_state": finding.get("workflow_state"),
            "analyst_validation": finding.get("analyst_validation"),
            "excluded_from_rating": finding.get("excluded_from_rating"),
            "cve_id": finding.get("cve_id") or "",
            "cvss_score": finding.get("cvss_score") if finding.get("cvss_score") is not None else "",
            "epss_score": finding.get("epss_score") if finding.get("epss_score") is not None else "",
            "cisa_kev": finding.get("cisa_kev"),
            "internet_facing": finding.get("internet_facing"),
            "first_seen_at": finding.get("first_seen_at"),
            "last_seen_at": finding.get("last_seen_at"),
            "event_date": finding.get("event_date") or "",
            "applied_deduction": finding.get("applied_deduction", 0),
            "remediation_id": remediation.get("catalog_id") or remediation.get("id", ""),
            "remediation_title": remediation.get("title_it", ""),
            "remediation_priority": remediation.get("priority", ""),
            "remediation_effort": remediation.get("effort", ""),
            "sources": ", ".join(finding.get("sources") or []),
        })
    # BOM UTF-8: Excel in ambiente italiano apre correttamente il file.
    content = buffer.getvalue().encode("utf-8-sig")
    name = f"defenix-findings-{_slug(context.company_name)}-{context.generated_at:%Y%m%d}"
    return GeneratedReport("csv", content, f"{name}.csv")


GENERATORS = {
    "html": generate_html,
    "pdf": generate_pdf,
    "docx": generate_docx,
    "json": generate_json,
    "csv": generate_csv,
}


def generate(context: ReportContext, formats: list[str], *,
             include_technical: bool = True) -> list[GeneratedReport]:
    """Genera i formati richiesti. Un formato non disponibile non blocca gli altri."""
    produced: list[GeneratedReport] = []
    for fmt in formats:
        generator = GENERATORS.get(fmt)
        if generator is None:
            logger.warning("report_format_unknown", format=fmt)
            continue
        try:
            if fmt in {"html", "pdf", "docx"}:
                produced.append(generator(context, include_technical=include_technical))
            else:
                produced.append(generator(context))
        except Exception as exc:  # noqa: BLE001
            logger.error("report_generation_failed", format=fmt, error=str(exc))
            if fmt == "pdf":
                # Degrada su HTML: il contenuto resta consultabile.
                logger.warning("pdf_fallback_to_html")
                produced.append(generate_html(context, include_technical=include_technical))
    return produced


def store(report: GeneratedReport, scan_id: str, version: int,
          base_path: Path | None = None) -> str:
    base = (base_path or settings.report_storage_path) / str(scan_id) / f"v{version}"
    base.mkdir(parents=True, exist_ok=True)
    path = base / report.filename
    path.write_bytes(report.content)
    path.chmod(0o600)
    return str(path)
