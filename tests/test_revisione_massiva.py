"""Revisione massiva dei rilievi.

Su una scansione con decine di rilievi, applicare la stessa azione uno alla
volta e' un lavoro che nessuno fa: il risultato e' che la revisione non viene
fatta affatto.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.models.enums import ScanStatus
from app.models.scanning import Finding, Scan
from tests.test_company_crud import _azienda, admin, analista, client, tenant_unico  # noqa: F401

pytestmark = pytest.mark.security


@pytest.fixture
def scansione_con_rilievi(client, admin):  # noqa: F811
    """Una scansione con rilievi di severita' diverse, nessuno revisionato."""
    azienda = _azienda(client, admin)
    adesso = datetime.now(UTC)
    with client.session_factory() as db:
        scan = Scan(tenant_id=uuid.UUID(azienda["tenant_id"]),
                    company_id=uuid.UUID(azienda["id"]), profile_key="public_passive",
                    status=ScanStatus.COMPLETED.value, mock_mode=True,
                    started_at=adesso, finished_at=adesso)
        db.add(scan)
        db.flush()
        for indice, severita in enumerate(("critical", "high", "medium", "low", "info")):
            db.add(Finding(
                tenant_id=scan.tenant_id, company_id=scan.company_id, scan_id=scan.id,
                reference_code=f"TST-{indice:03d}", finding_type="prova",
                title=f"Rilievo {indice}", category="attack_surface", severity=severita,
                confidence_class="confirmed", ownership_status="verified_owned",
                fingerprint=f"impronta-{indice}", first_seen_at=adesso, last_seen_at=adesso))
        db.commit()
        return {"scan_id": str(scan.id), "company": azienda}


def _rilievi(client, scan_id: str, headers) -> list[dict]:  # noqa: F811
    return client.get(f"/api/v1/scans/{scan_id}/findings", headers=headers).json()["items"]


# ------------------------------------------------------------------ successo
def test_una_sola_azione_su_piu_rilievi(client, admin, scansione_con_rilievi):  # noqa: F811
    scan_id = scansione_con_rilievi["scan_id"]
    scelti = [f["id"] for f in _rilievi(client, scan_id, admin)][:3]

    risposta = client.post(f"/api/v1/scans/{scan_id}/findings/bulk-review", headers=admin,
                           json={"finding_ids": scelti, "action": "false_positive",
                                 "reason": "servizio dismesso, verificato con il cliente"})
    assert risposta.status_code == 200, risposta.text
    esito = risposta.json()
    assert esito["applied"] == 3
    assert esito["failed"] == []
    assert esito["progress"]["reviewed"] == 3

    dopo = {f["id"]: f for f in _rilievi(client, scan_id, admin)}
    for identificativo in scelti:
        assert dopo[identificativo]["analyst_validation"] == "rejected_false_positive"
        assert dopo[identificativo]["excluded_from_rating"] is True


def test_ogni_rilievo_produce_la_propria_voce_di_audit(client, admin,  # noqa: F811
                                                        scansione_con_rilievi):
    """Una revisione massiva non e' un modo per registrarne una sola: sono
    decisioni distinte su rilievi distinti."""
    from app.models.audit import AuditLog

    scan_id = scansione_con_rilievi["scan_id"]
    scelti = [f["id"] for f in _rilievi(client, scan_id, admin)][:3]
    client.post(f"/api/v1/scans/{scan_id}/findings/bulk-review", headers=admin,
                json={"finding_ids": scelti, "action": "accept_risk",
                      "reason": "rischio accettato dalla direzione"})

    with client.session_factory() as db:
        voci = db.execute(
            select(AuditLog).where(AuditLog.entity_type == "finding")).scalars().all()
        assert len({v.entity_id for v in voci}) == 3


# ------------------------------------------------------------------ vincoli
def test_la_motivazione_resta_obbligatoria(client, admin, scansione_con_rilievi):  # noqa: F811
    """Le regole dell'azione sono le stesse della revisione singola: una
    massiva con controlli propri sarebbe la scorciatoia per aggirarli."""
    scan_id = scansione_con_rilievi["scan_id"]
    scelti = [f["id"] for f in _rilievi(client, scan_id, admin)][:2]

    risposta = client.post(f"/api/v1/scans/{scan_id}/findings/bulk-review", headers=admin,
                           json={"finding_ids": scelti, "action": "false_positive"})
    assert risposta.status_code == 200
    assert risposta.json()["applied"] == 0
    assert len(risposta.json()["failed"]) == 2
    assert "motivazione" in risposta.json()["failed"][0]["reason"]


def test_la_conferma_richiede_il_permesso_di_approvazione(client, analista,  # noqa: F811
                                                           scansione_con_rilievi):
    """Il permesso non e' aggirabile passando dalla via massiva."""
    scan_id = scansione_con_rilievi["scan_id"]
    scelti = [f["id"] for f in _rilievi(client, scan_id, analista)][:2]

    risposta = client.post(f"/api/v1/scans/{scan_id}/findings/bulk-review", headers=analista,
                           json={"finding_ids": scelti, "action": "confirm"})
    assert risposta.status_code == 403


def test_un_rilievo_di_un_altra_scansione_non_viene_toccato(client, admin,  # noqa: F811
                                                             scansione_con_rilievi):
    scan_id = scansione_con_rilievi["scan_id"]
    estraneo = str(uuid.uuid4())

    risposta = client.post(f"/api/v1/scans/{scan_id}/findings/bulk-review", headers=admin,
                           json={"finding_ids": [estraneo], "action": "request_retest"})
    assert risposta.json()["applied"] == 0
    assert risposta.json()["failed"][0]["reason"] == (
        "rilievo non appartenente a questa scansione")


def test_i_rilievi_validi_passano_anche_se_altri_falliscono(client, admin,  # noqa: F811
                                                             scansione_con_rilievi):
    """Su cinquanta selezionati, due in stato sbagliato non devono annullare
    gli altri quarantotto."""
    scan_id = scansione_con_rilievi["scan_id"]
    validi = [f["id"] for f in _rilievi(client, scan_id, admin)][:2]

    risposta = client.post(
        f"/api/v1/scans/{scan_id}/findings/bulk-review", headers=admin,
        json={"finding_ids": [*validi, str(uuid.uuid4())], "action": "request_retest"})
    assert risposta.json()["applied"] == 2
    assert len(risposta.json()["failed"]) == 1


def test_la_selezione_ha_un_tetto():
    """Un elenco senza limite diventa una richiesta che blocca il processo."""
    from pydantic import ValidationError

    from app.schemas.scanning import FindingBulkReview

    with pytest.raises(ValidationError):
        FindingBulkReview(finding_ids=[uuid.uuid4() for _ in range(501)], action="confirm")
    with pytest.raises(ValidationError):
        FindingBulkReview(finding_ids=[], action="confirm")
