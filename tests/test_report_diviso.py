"""Due documenti, non uno: si consegna il primo e si decide del secondo.

L'allegato tecnico contiene indirizzi, versioni dei prodotti e dettaglio dei
rilievi. Finche' le due parti erano un unico file, chi firma non aveva la
scelta: o mandava tutto, o niente.

E il rapporto per la direzione non diceva su che cosa fossero calcolati i suoi
numeri. Un punteggio alto su tre nomi e lo stesso punteggio su duecento sono
affermazioni molto diverse, ed e' la prima cosa che un destinatario verifica.
"""
from __future__ import annotations

import pytest

from reporting.context import MAX_NOMI_NEL_PERIMETRO, riepiloga_perimetro
from reporting.service import ESECUTIVO, SUFFISSO, TECNICO, _nome, _parti


def _inventario(quanti_sottodomini: int = 3):
    return [
        {"label_it": "Domini", "items": [
            {"name": "azienda.example", "ownership": "verified"}]},
        {"label_it": "Sottodomini", "items": [
            {"name": f"host{i}.azienda.example", "ownership": "verified"}
            for i in range(quanti_sottodomini)]},
        {"label_it": "Indirizzi IP", "items": [
            {"name": "203.0.113.1", "ownership": "verified"},
            {"name": "198.51.100.9", "ownership": "third_party", "excluded": True},
            {"name": "203.0.113.9", "ownership": "verified", "disappeared": True}]},
        {"label_it": "Vuoto", "items": []},
    ]


# --------------------------------------------------------------------------
# Il riepilogo del perimetro
# --------------------------------------------------------------------------
def test_il_riepilogo_conta_per_tipo():
    riepilogo = {g["label_it"]: g for g in riepiloga_perimetro(_inventario())}

    assert riepilogo["Sottodomini"]["totale"] == 3
    assert riepilogo["Indirizzi IP"]["totale"] == 3
    assert "Vuoto" not in riepilogo, "un tipo senza elementi non va mostrato"


def test_il_riepilogo_distingue_cio_che_non_conta_per_il_punteggio():
    """Gli asset di terze parti si dichiarano e non entrano nel rating: non
    sono amministrati dall'organizzazione, e attribuirgliene lo stato sarebbe
    sbagliato. Chi legge deve poterlo vedere."""
    ip = next(g for g in riepiloga_perimetro(_inventario())
              if g["label_it"] == "Indirizzi IP")

    assert ip["terze_parti"] == 1
    assert ip["non_piu_osservati"] == 1
    assert ip["verificati"] == 2


def test_un_elenco_lunghissimo_non_invade_il_rapporto():
    """Trecento sottodomini in un rapporto per la direzione non si leggono, e
    non sono quello che serve sapere: si dichiara il totale."""
    gruppo = next(g for g in riepiloga_perimetro(_inventario(300))
                  if g["label_it"] == "Sottodomini")

    assert gruppo["totale"] == 300
    assert len(gruppo["nomi"]) == MAX_NOMI_NEL_PERIMETRO
    assert gruppo["altri"] == 300 - MAX_NOMI_NEL_PERIMETRO


def test_un_elenco_corto_si_mostra_intero():
    gruppo = next(g for g in riepiloga_perimetro(_inventario(3))
                  if g["label_it"] == "Sottodomini")

    assert len(gruppo["nomi"]) == 3
    assert gruppo["altri"] == 0


def test_la_tabella_e_nel_rapporto_per_la_direzione():
    """Non solo nell'allegato tecnico: e' la domanda che precede ogni numero,
    e chi riceve il solo rapporto per la direzione deve potersela porre."""
    from pathlib import Path

    template = (Path(__file__).resolve().parents[1] / "reporting" / "templates"
                / "executive.html.j2").read_text(encoding="utf-8")

    assert "perimetro" in template
    assert "Gli elementi analizzati" in template


# --------------------------------------------------------------------------
# I due documenti
# --------------------------------------------------------------------------
def test_le_parti_predefinite_restano_quelle_di_prima():
    """La modalita' unita e' ancora la predefinita: nessun chiamante esistente
    cambia comportamento."""
    assert _parti(True, None) == (ESECUTIVO, TECNICO)
    assert _parti(False, None) == (ESECUTIVO,)


def test_il_nome_del_file_dice_quale_parte_contiene():
    """Due file nella stessa cartella con lo stesso nome sarebbero
    indistinguibili, e il secondo sovrascriverebbe il primo."""
    from datetime import UTC, datetime

    class Finto:
        company_name = "Azienda di Prova"
        generated_at = datetime(2026, 11, 24, tzinfo=UTC)

    uniti = _nome(Finto, (ESECUTIVO, TECNICO))
    direzione = _nome(Finto, (ESECUTIVO,))
    tecnico = _nome(Finto, (TECNICO,))

    assert direzione.endswith(SUFFISSO[ESECUTIVO])
    assert tecnico.endswith(SUFFISSO[TECNICO])
    assert direzione != tecnico
    assert not uniti.endswith(SUFFISSO[ESECUTIVO]), (
        "il documento completo non deve sembrare una parte sola")


@pytest.mark.parametrize("formato", ["html", "pdf", "docx"])
def test_separati_produce_due_documenti_per_formato(formato, monkeypatch):
    from reporting import service

    chiamate: list[tuple[str, ...] | None] = []

    def finto(_contesto, *, include_technical=True, parti=None):  # noqa: ANN001
        chiamate.append(parti)
        return service.GeneratedReport(formato, b"x", f"{len(chiamate)}.{formato}")

    monkeypatch.setitem(service.GENERATORS, formato, finto)

    prodotti = service.generate(object(), [formato], separati=True)

    assert len(prodotti) == 2, "una parte non e' stata prodotta"
    assert chiamate == [(ESECUTIVO,), (TECNICO,)]


def test_json_e_csv_non_si_dividono(monkeypatch):
    """Sono un'unica rappresentazione dei dati: due meta' non significherebbero
    niente, e due file identici sarebbero peggio."""
    from reporting import service

    monkeypatch.setitem(
        service.GENERATORS, "json",
        lambda _c: service.GeneratedReport("json", b"{}", "x.json"))

    prodotti = service.generate(object(), ["json"], separati=True)

    assert len(prodotti) == 1


def test_il_tipo_di_report_e_esposto_dall_api():
    from app.models.enums import ReportType

    assert ReportType.SPLIT.value == "split"


def test_la_riga_di_comando_lo_espone():
    """E' il modo con cui si guarda l'effetto di una modifica senza passare
    dall'interfaccia."""
    from pathlib import Path

    cli = (Path(__file__).resolve().parents[1] / "backend" / "app" / "cli.py"
           ).read_text(encoding="utf-8")

    assert "--separati" in cli
    assert "separati=args.separati" in cli
