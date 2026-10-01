"""Un'area verificata da un altro strumento non e' un'area scoperta.

naabu non pubblica binari per arm64, e sulla stessa area lavora `port_scan`,
integrato nella piattaforma: l'adapter si saltava da se' spiegandolo, ma
dichiarava comunque un impatto di copertura pieno. Il risultato era una
piattaforma che si scontava la fiducia e metteva fra le «aree non verificate»
un'area che aveva verificato.

La sostituzione la dichiara il catalogo; che il sostituto sia riuscito lo sa
solo chi ha davanti tutta la scansione, e per questo l'intervento sta nella
pipeline e non nell'adapter.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from adapters.base import AdapterResult, AdapterStatus
from app.workers.pipeline import _azzera_la_copertura_dei_sostituiti

RADICE = Path(__file__).resolve().parents[1]
PROFILO = "verified_extended"  # il solo in cui naabu e' ammesso


def _risultati(esito_del_sostituto: AdapterStatus) -> list[AdapterResult]:
    return [
        AdapterResult(tool="naabu", status=AdapterStatus.SKIPPED,
                      coverage_impact=1.0,
                      error_message="binario non presente per questa architettura"),
        AdapterResult(tool="port_scan", status=esito_del_sostituto),
    ]


def test_se_il_sostituto_riesce_la_lacuna_non_esiste():
    risultati = _risultati(AdapterStatus.SUCCESS)

    _azzera_la_copertura_dei_sostituiti(risultati, PROFILO)

    assert risultati[0].coverage_impact == 0.0
    assert "port_scan" in (risultati[0].error_message or ""), (
        "il motivo non dice chi ha coperto l'area: la riga resta incomprensibile")


def test_il_motivo_originale_non_viene_perso():
    """Perche' il binario non ci fosse resta un'informazione utile: la si
    aggiunge, non la si sostituisce."""
    risultati = _risultati(AdapterStatus.SUCCESS)

    _azzera_la_copertura_dei_sostituiti(risultati, PROFILO)

    assert "architettura" in (risultati[0].error_message or "")


def test_se_il_sostituto_fallisce_la_lacuna_resta():
    """Altrimenti basterebbe dichiarare una sostituzione nel catalogo per far
    sparire una lacuna reale."""
    for esito in (AdapterStatus.FAILED, AdapterStatus.SKIPPED, AdapterStatus.PARTIAL):
        risultati = _risultati(esito)
        _azzera_la_copertura_dei_sostituiti(risultati, PROFILO)
        assert risultati[0].coverage_impact == 1.0, esito


def test_uno_strumento_senza_sostituto_non_viene_toccato():
    risultati = [
        AdapterResult(tool="nuclei", status=AdapterStatus.FAILED, coverage_impact=1.0),
        AdapterResult(tool="port_scan", status=AdapterStatus.SUCCESS),
    ]

    _azzera_la_copertura_dei_sostituiti(risultati, PROFILO)

    assert risultati[0].coverage_impact == 1.0


# --------------------------------------------------------------------------
# Il catalogo
# --------------------------------------------------------------------------
def test_ogni_sostituto_dichiarato_esiste_e_copre_le_stesse_aree():
    """Una sostituzione verso uno strumento che non copre quell'area
    cancellerebbe una lacuna vera invece di spiegarla."""
    catalogo = yaml.safe_load(
        (RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))["tools"]

    dichiarate = {chiave: d["replaced_by"] for chiave, d in catalogo.items()
                  if d.get("replaced_by")}

    assert dichiarate, "nessuna sostituzione dichiarata: il test non guarda nulla"
    for chiave, sostituto in dichiarate.items():
        assert sostituto in catalogo, f"{chiave} rimanda a '{sostituto}', che non esiste"
        aree = set(catalogo[chiave].get("coverage_areas", []))
        aree_sostituto = set(catalogo[sostituto].get("coverage_areas", []))
        assert aree <= aree_sostituto, (
            f"{sostituto} non copre {sorted(aree - aree_sostituto)}, che {chiave} copriva")


def test_il_sostituto_e_ammesso_negli_stessi_profili():
    """Se il sostituto non e' nel profilo, in quel profilo non sostituisce
    nulla e la lacuna resterebbe senza che nessuno lo dica."""
    configurazione = yaml.safe_load(
        (RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))
    catalogo, profili = configurazione["tools"], configurazione["profiles"]

    for chiave, definizione in catalogo.items():
        sostituto = definizione.get("replaced_by")
        if not sostituto:
            continue
        for nome, profilo in profili.items():
            strumenti = profilo.get("tools", [])
            if chiave in strumenti:
                assert sostituto in strumenti, (
                    f"nel profilo {nome} c'e' {chiave} ma non {sostituto}")


def test_la_matrice_di_copertura_trasporta_sostituzione_e_attesa_di_input():
    """Il calcolo della fiducia legge la matrice, non il catalogo: un campo che
    si ferma nel file YAML non cambia niente."""
    from adapters.registry import coverage_matrix

    matrice = {voce["tool"]: voce for voce in coverage_matrix(PROFILO)}

    assert matrice["naabu"]["replaced_by"] == "port_scan"
    assert matrice["email_header"]["requires_input"] is True
    assert matrice["nuclei"]["replaced_by"] is None
    assert matrice["nuclei"]["requires_input"] is False
