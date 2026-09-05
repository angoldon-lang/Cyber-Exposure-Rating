"""Inventario degli asset osservati.

La dashboard ne mostrava soltanto il conteggio. Un numero non e' verificabile:
sapere che gli asset sono 47 non dice quali siano ne' chi li abbia trovati.
"""
from __future__ import annotations

import io
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from tests.test_company_crud import _azienda, admin, analista, cliente, client, tenant_unico  # noqa: F401

pytestmark = pytest.mark.security


def _asset(client, azienda: dict, **campi) -> None:  # noqa: F811, ANN003
    """Inserisce un asset osservato, come farebbe la persistenza di una scansione."""
    from app.models.scope import Asset

    adesso = datetime.now(UTC)
    with client.session_factory() as db:
        db.add(Asset(
            tenant_id=uuid.UUID(azienda["tenant_id"]), company_id=uuid.UUID(azienda["id"]),
            first_seen_at=adesso, last_seen_at=adesso,
            **{"ownership_status": "likely_owned", "display_name": campi.get("asset_key", ""),
               **campi}))
        db.commit()


@pytest.fixture
def azienda_con_asset(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    _asset(client, azienda, asset_key="www.acme.example", asset_type="subdomain",
           display_name="www.acme.example", ownership_status="verified_owned",
           discovered_by_json=["subfinder", "certificate_transparency"],
           technologies_json=[{"name": "nginx", "version": "1.24.0"}])
    _asset(client, azienda, asset_key="203.0.113.10", asset_type="ip_address",
           display_name="203.0.113.10", ownership_status="third_party",
           discovered_by_json=["ip_perimeter"],
           attributes_json={"provider": "Cloudflare", "network_type": "condivisa",
                            "is_cdn": True, "scannable": False})
    _asset(client, azienda, asset_key="mario.rossi@acme.example", asset_type="email_address",
           display_name="m*********i@acme.example", discovered_by_json=["spiderfoot"],
           attributes_json={"masked": True, "breach_count": 3})
    _asset(client, azienda, asset_key="vecchio.acme.example", asset_type="subdomain",
           display_name="vecchio.acme.example", discovered_by_json=["subfinder"],
           disappeared_at=datetime.now(UTC))
    return azienda


# ------------------------------------------------------------------- elenco
def test_l_inventario_elenca_gli_asset_con_la_provenienza(client, admin, azienda_con_asset):  # noqa: F811
    """La fonte e' la prima cosa che un analista controlla di un asset: senza,
    l'inventario dice cosa e' stato trovato ma non se ci si possa fidare."""
    risposta = client.get(f"/api/v1/companies/{azienda_con_asset['id']}/assets", headers=admin)
    assert risposta.status_code == 200, risposta.text
    voci = {v["display_name"]: v for v in risposta.json()["items"]}
    assert risposta.json()["total"] == 4
    assert voci["www.acme.example"]["discovered_by_json"] == [
        "subfinder", "certificate_transparency"]
    assert voci["203.0.113.10"]["attributes_json"]["provider"] == "Cloudflare"


def test_il_riepilogo_conta_l_inventario_non_la_pagina(client, admin, azienda_con_asset):  # noqa: F811
    """Derivare i conteggi dagli elementi mostrati darebbe numeri diversi a
    ogni filtro: sarebbero conteggi della vista, non dell'inventario."""
    risposta = client.get(f"/api/v1/companies/{azienda_con_asset['id']}/assets/summary",
                          headers=admin)
    assert risposta.status_code == 200, risposta.text
    riepilogo = risposta.json()
    assert riepilogo["total"] == 4
    assert riepilogo["disappeared"] == 1
    assert riepilogo["by_type"] == {"subdomain": 2, "email_address": 1, "ip_address": 1}
    assert riepilogo["by_tool"]["subfinder"] == 2


def test_filtri_per_tipo_proprieta_e_ricerca(client, admin, azienda_con_asset):  # noqa: F811
    base = f"/api/v1/companies/{azienda_con_asset['id']}/assets"

    per_tipo = client.get(f"{base}?asset_type=subdomain", headers=admin).json()
    assert per_tipo["total"] == 2

    per_proprieta = client.get(f"{base}?ownership_status=third_party", headers=admin).json()
    assert [v["display_name"] for v in per_proprieta["items"]] == ["203.0.113.10"]

    ricerca = client.get(f"{base}?q=VECCHIO", headers=admin).json()
    assert [v["display_name"] for v in ricerca["items"]] == ["vecchio.acme.example"]

    senza_scomparsi = client.get(f"{base}?include_disappeared=false", headers=admin).json()
    assert senza_scomparsi["total"] == 3


def test_il_filtro_per_strumento_impagina_sui_risultati_filtrati(client, admin,  # noqa: F811
                                                                 azienda_con_asset):
    """Lo strumento sta in una colonna JSON e il filtro vive in Python: se
    fosse applicato dopo l'impaginazione, le pagine sarebbero parzialmente
    vuote e il totale non corrisponderebbe a cio' che si vede."""
    base = f"/api/v1/companies/{azienda_con_asset['id']}/assets"
    esito = client.get(f"{base}?discovered_by=subfinder", headers=admin).json()
    assert esito["total"] == 2
    assert len(esito["items"]) == 2

    prima = client.get(f"{base}?discovered_by=subfinder&page_size=1&page=1", headers=admin).json()
    seconda = client.get(f"{base}?discovered_by=subfinder&page_size=1&page=2", headers=admin).json()
    assert prima["total"] == seconda["total"] == 2
    assert len(prima["items"]) == len(seconda["items"]) == 1
    assert prima["items"][0]["id"] != seconda["items"][0]["id"]


# ------------------------------------------------------------ dati personali
def test_l_indirizzo_e_mail_e_mascherato_senza_il_permesso(client, cliente,  # noqa: F811
                                                            azienda_con_asset):
    """`display_name` era gia' mascherato all'origine, `asset_key` no: per un
    indirizzo la chiave e' l'indirizzo in chiaro, ed e' quella che l'inventario
    mostra come identita' dell'asset."""
    voci = client.get(f"/api/v1/companies/{azienda_con_asset['id']}/assets",
                      headers=cliente).json()["items"]
    email = next(v for v in voci if v["asset_type"] == "email_address")
    assert email["asset_key"] == "m*********i@acme.example"
    assert "mario.rossi" not in str(voci)


def test_chi_ha_il_permesso_vede_l_indirizzo_completo(client, analista,  # noqa: F811
                                                       azienda_con_asset):
    """Mascherare per tutti renderebbe il rilievo non verificabile: il ruolo
    con `pii:unmask` deve poter risalire alla casella."""
    voci = client.get(f"/api/v1/companies/{azienda_con_asset['id']}/assets",
                      headers=analista).json()["items"]
    email = next(v for v in voci if v["asset_type"] == "email_address")
    assert email["asset_key"] == "mario.rossi@acme.example"


def test_la_ricerca_non_conferma_un_indirizzo_nascosto(client, cliente,  # noqa: F811
                                                        azienda_con_asset):
    """Cercare sulla chiave permetterebbe a chi non puo' vedere l'indirizzo di
    confermarlo per tentativi: la ricerca corre sul nome mostrato."""
    base = f"/api/v1/companies/{azienda_con_asset['id']}/assets"
    assert client.get(f"{base}?q=mario.rossi", headers=cliente).json()["total"] == 0
    assert client.get(f"{base}?q=acme.example", headers=cliente).json()["total"] > 0


# --------------------------------------------------------------- isolamento
def test_gli_asset_di_un_altra_azienda_non_sono_raggiungibili(client, admin,  # noqa: F811
                                                               azienda_con_asset):
    altra = _azienda(client, admin)
    assert client.get(f"/api/v1/companies/{altra['id']}/assets",
                      headers=admin).json()["total"] == 0


# ------------------------------------------------------------------- report
def _inventario_di_prova() -> list[dict]:
    return [
        {"type": "subdomain", "label_it": "Sottodomini", "items": [
            {"name": "www.acme-test.example", "ownership": "verified_owned",
             "technologies": "nginx 1.24.0", "discovered_by": "subfinder",
             "disappeared": False, "excluded": False},
            {"name": "vecchio.acme-test.example", "ownership": "likely_owned",
             "technologies": "", "discovered_by": "subfinder",
             "disappeared": True, "excluded": False}]},
        {"type": "email_address", "label_it": "Indirizzi e-mail", "items": [
            {"name": "m*********i@acme-test.example", "ownership": "likely_owned",
             "technologies": "", "discovered_by": "spiderfoot",
             "disappeared": False, "excluded": False}]},
    ]


@pytest.mark.slow
def test_l_allegato_tecnico_elenca_gli_asset():
    """Il report dava solo i conteggi. L'allegato tecnico esiste per permettere
    la verifica, e un numero non e' verificabile."""
    import pypdf

    from reporting import service as rs
    from tests.test_reports import _context

    pdf = rs.generate_pdf(_context(asset_inventory=_inventario_di_prova()),
                          include_technical=True)
    testo = "".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(pdf.content)).pages)
    assert "Asset osservati" in testo
    assert "www.acme-test.example" in testo
    assert "non piu' osservato" in testo
    assert "subfinder" in testo
    # Le entita' HTML dentro un'espressione Jinja vengono escapate e finiscono
    # nel PDF come testo: il trattino va scritto come carattere.
    assert "&mdash;" not in testo


@pytest.mark.slow
def test_il_report_non_espone_l_indirizzo_completo():
    """Il nome mostrato e' gia' mascherato all'origine: il report non deve
    reintrodurre l'indirizzo in chiaro passando dalla chiave."""
    import pypdf

    from reporting import service as rs
    from tests.test_reports import _context

    pdf = rs.generate_pdf(_context(asset_inventory=_inventario_di_prova()),
                          include_technical=True)
    testo = "".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(pdf.content)).pages)
    assert "mario.rossi@" not in testo
    # Il nome puo' andare a capo dentro la cella: si verifica la parte
    # mascherata, che a capo non va.
    assert "m*********i@" in testo


def test_l_inventario_del_report_rispetta_il_mascheramento():
    """Il ruolo con `pii:unmask` deve vedere l'indirizzo completo, gli altri no."""
    from app.models.scope import Asset
    from app.services.report_builder import _inventario_asset

    adesso = datetime.now(UTC)
    riga = Asset(asset_key="mario.rossi@acme.example", asset_type="email_address",
                 display_name="m*********i@acme.example", ownership_status="likely_owned",
                 first_seen_at=adesso, last_seen_at=adesso,
                 technologies_json=[], discovered_by_json=["spiderfoot"])

    mascherato = _inventario_asset([riga], unmask_pii=False)[0]["items"][0]["name"]
    in_chiaro = _inventario_asset([riga], unmask_pii=True)[0]["items"][0]["name"]
    assert mascherato == "m*********i@acme.example"
    assert in_chiaro == "mario.rossi@acme.example"


# --------------------------------------------------- catena completa
@pytest.mark.slow
def test_dalla_scansione_al_report_l_inventario_arriva_intero(client, admin):  # noqa: F811
    """Percorso reale: scansione, persistenza, contesto del report.

    I test precedenti verificano i pezzi con dati costruiti a mano. Questo
    verifica che si tengano: e' la catena in cui un campo dimenticato non
    genera errori, produce soltanto una sezione vuota.
    """
    from app.models.enums import ScanStatus
    from app.models.scanning import Scan
    from app.services.persistence import persist_outcome
    from app.services.report_builder import build_report_context
    from app.workers.pipeline import ScanPipeline, ScanRequest

    azienda = _azienda(client, admin)
    dominio = "acme-inventario.example"

    with client.session_factory() as db:
        scansione = Scan(
            tenant_id=uuid.UUID(azienda["tenant_id"]), company_id=uuid.UUID(azienda["id"]),
            profile_key="verified_extended", status=ScanStatus.RUNNING.value,
            mock_mode=True, started_at=datetime.now(UTC),
            scope_snapshot_json={"domains": [dominio], "verified_domains": [dominio]})
        db.add(scansione)
        db.commit()
        scan_id = scansione.id

    esito = ScanPipeline(ScanRequest(
        scan_id=str(scan_id), tenant_id=azienda["tenant_id"], company_id=azienda["id"],
        company_name=azienda["legal_name"], profile="verified_extended",
        domains=[dominio], verified_domains=[dominio], mock_mode=True,
        connector_config={"synthetic": {"severity_bias": 0.6}})).run()

    with client.session_factory() as db:
        scansione = db.get(Scan, scan_id)
        persist_outcome(db, scansione, esito)
        db.commit()

        contesto = build_report_context(db, db.get(Scan, scan_id)).as_dict()
        inventario = contesto["asset_inventory"]

        assert inventario, "l'inventario degli asset non arriva al report"
        assert sum(len(g["items"]) for g in inventario) == contesto["exposure_summary"]["total_assets"], (
            "l'elenco e il conteggio del riepilogo descrivono insiemi diversi")
        tipi = {g["type"] for g in inventario}
        assert {"subdomain", "ip_address"} <= tipi
        assert all(v["discovered_by"] for g in inventario for v in g["items"]), (
            "un asset senza strumento di provenienza non e' verificabile")

        # Gli indirizzi IP classificati devono essere finiti anche nel
        # perimetro, come inventario e mai come autorizzati.
        from app.models.scope import IPAddress

        indirizzi = db.execute(
            select(IPAddress)
            .where(IPAddress.company_id == uuid.UUID(azienda["id"]))).scalars().all()
        assert indirizzi, "gli indirizzi classificati non entrano nel perimetro"
        assert all(i.ownership_status != "verified_owned" for i in indirizzi)
        assert any(i.is_cdn for i in indirizzi), (
            "i dati sintetici devono includere un indirizzo dietro CDN")
