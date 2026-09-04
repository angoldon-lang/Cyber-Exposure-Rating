"""I rilievi devono dire quale asset e' colpito e con quali dati osservati."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


def test_disclaimer_passivo_non_dichiara_autorizzazioni():
    """Il Public Passive Check consulta solo fonti pubbliche e non interroga i
    sistemi: dichiarare un'autorizzazione che non esiste sarebbe scorretto."""
    from reporting.context import disclaimer_for

    passivo = disclaimer_for("public_passive")
    assert "autorizzato" not in passivo
    assert "fonti pubbliche" in passivo
    assert "senza alcuna interazione" in passivo
    # La limitazione di fondo resta in entrambi i casi.
    assert "penetration test" in passivo


@pytest.mark.parametrize("profilo", ["verified_standard", "verified_extended"])
def test_disclaimer_verificato_dichiara_il_perimetro_autorizzato(profilo):
    """I profili verificati interrogano i sistemi: li' l'autorizzazione scritta
    e' un presupposto e va dichiarata."""
    from reporting.context import disclaimer_for

    testo = disclaimer_for(profilo)
    assert "perimetro dichiarato e autorizzato" in testo


def test_il_report_usa_il_disclaimer_del_profilo_eseguito():
    from reporting.context import build_context

    contesto = build_context(
        company={"legal_name": "ACME S.p.A."}, scan={"profile_key": "public_passive"},
        score={"overall_score": 80.0, "rating_class": "B", "confidence": {"value": 70.0}},
        findings=[], remediation_plan=[], quick_win_items=[], comparison=None,
        coverage_matrix=[], exposure={})
    assert "autorizzato" not in contesto.disclaimer
