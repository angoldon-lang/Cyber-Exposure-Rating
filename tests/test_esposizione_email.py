"""Esposizione degli indirizzi e-mail in violazioni di dati.

Cio' che il report deve dire e' *quale casella* e' esposta e *in quale
violazione*: e' l'unica forma verificabile e l'unica su cui si puo' agire.
La password non serve al rimedio e non deve mai essere letta ne' conservata.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from adapters.esposizione_email import separa_indirizzo_e_fonte, severita_violazione
from adapters.spiderfoot_adapter import SpiderFootAdapter
from adapters.xposedornot_adapter import XposedOrNotAdapter

pytestmark = pytest.mark.security

DOMINIO = "acme-test.example"


def _evento(tipo: str, dato: str) -> dict:
    return {"type": tipo, "data": dato}


def _mappa(context, eventi: list[dict]):
    return SpiderFootAdapter(context)._map_events(eventi)


# ---------------------------------------------------------------- SpiderFoot
def test_le_utenze_compromesse_diventano_rilievi(adapter_context):
    """Regressione: gli eventi di compromissione erano raccolti da SpiderFoot
    e poi scartati dalla mappatura, che produceva evidenze solo per le menzioni
    darknet. Il risultato era una sezione dark web vuota anche quando
    l'esposizione esisteva."""
    evidenze, _, _ = _mappa(adapter_context, [
        _evento("EMAILADDR_COMPROMISED", f"mario.rossi@{DOMINIO} [LinkedIn]")])
    tipi = {e.finding_type for e in evidenze}
    assert "email_exposed_in_breach" in tipi, "l'utenza compromessa non produce alcun rilievo"
    assert evidenze[0].detail == "LinkedIn"
    assert evidenze[0].asset_key == f"mario.rossi@{DOMINIO}"


def test_lo_stesso_indirizzo_da_due_eventi_non_si_perde(adapter_context):
    """Regressione: la deduplicazione era sul solo valore dell'evento, non
    sulla coppia (tipo, valore). Un indirizzo visto prima come EMAILADDR
    faceva sparire la successiva EMAILADDR_COMPROMISED, cioe' proprio
    l'informazione che interessa."""
    evidenze, asset, _ = _mappa(adapter_context, [
        _evento("EMAILADDR", f"mario.rossi@{DOMINIO}"),
        _evento("EMAILADDR_COMPROMISED", f"mario.rossi@{DOMINIO} [Collection #1]")])
    assert [e.detail for e in evidenze] == ["Collection #1"]
    assert len(asset) == 2


def test_la_password_non_viene_mai_conservata(adapter_context):
    """Il valore di una credenziale non entra ne' nelle evidenze, ne' negli
    asset, ne' nell'output grezzo archiviato. Vale anche per l'hash: un hash
    e' una credenziale, non un metadato."""
    segreto = "Password!2024"
    hash_segreto = "5f4dcc3b5aa765d61d8327deb882cf99"
    eventi = [_evento("EMAILADDR_COMPROMISED", f"mario.rossi@{DOMINIO} [Adobe]"),
              _evento("PASSWORD_COMPROMISED", segreto),
              _evento("HASH_COMPROMISED", hash_segreto)]

    evidenze, asset, credenziali = _mappa(adapter_context, eventi)
    assert credenziali == 2, "le credenziali viste vanno contate"

    grezzo = SpiderFootAdapter._senza_credenziali(eventi)
    testo = json.dumps([e.to_dict() for e in evidenze], default=str) + json.dumps(grezzo)
    testo += json.dumps([a.asset_key for a in asset])
    assert segreto not in testo
    assert hash_segreto not in testo


def test_gli_indirizzi_di_terzi_restano_fuori(adapter_context):
    """SpiderFoot raccoglie anche indirizzi di fornitori e contatti citati sul
    sito: sono dati personali estranei al perimetro valutato."""
    _, asset, _ = _mappa(adapter_context, [
        _evento("EMAILADDR", f"interno@{DOMINIO}"),
        _evento("EMAILADDR", "commerciale@fornitore-esterno.example")])
    assert [a.asset_key for a in asset] == [f"interno@{DOMINIO}"]


def test_l_indirizzo_e_mascherato_nel_rilievo(adapter_context):
    evidenze, asset, _ = _mappa(adapter_context, [
        _evento("EMAILADDR_COMPROMISED", f"mario.rossi@{DOMINIO} [Dropbox]")])
    assert evidenze[0].target == f"m*********i@{DOMINIO}"
    assert asset[0].display_name == f"m*********i@{DOMINIO}"
    assert "mario.rossi" in evidenze[0].asset_key, (
        "la chiave resta in chiaro: e' il mascheramento in lettura a proteggerla, "
        "altrimenti il ruolo autorizzato non potrebbe mai risalire alla casella")


def test_separazione_indirizzo_e_violazione():
    assert separa_indirizzo_e_fonte("mario@a.it [LinkedIn]") == ("mario@a.it", "LinkedIn")
    assert separa_indirizzo_e_fonte("  Mario@A.it  ") == ("mario@a.it", None)


# ------------------------------------------------------------- XposedOrNot
def test_saltato_senza_indirizzi_noti(adapter_context):
    adapter_context.email_addresses = []
    adapter_context.discovered_emails = []
    disponibile, motivo = XposedOrNotAdapter(adapter_context).check_available()
    assert not disponibile
    assert "indirizzo e-mail" in motivo


def test_interroga_solo_indirizzi_del_perimetro(adapter_context):
    adapter_context.discovered_emails = [f"info@{DOMINIO}", "tizio@altro-dominio.example",
                                         f"MARIO@{DOMINIO}", "senza-chiocciola"]
    assert XposedOrNotAdapter(adapter_context)._indirizzi() == [
        f"info@{DOMINIO}", f"mario@{DOMINIO}"]


def test_un_rilievo_per_violazione_e_uno_solo_per_credenziali_recenti(adapter_context):
    """Il dettaglio serve per violazione, la detrazione no: il rimedio e' un
    unico cambio password per casella, non uno per violazione."""
    anno = datetime.now(UTC).year - 1
    adattatore = XposedOrNotAdapter(adapter_context)
    evidenze = adattatore._evidenze(f"mario.rossi@{DOMINIO}", [
        {"breach": "LinkedIn", "domain": "", "year": str(anno), "records": 10,
         "data": ["email addresses", "passwords"]},
        {"breach": "Adobe", "domain": "", "year": str(anno), "records": 10,
         "data": ["email addresses", "passwords"]},
        {"breach": "Zynga", "domain": "", "year": "2019", "records": 10,
         "data": ["email addresses", "usernames"]}])

    per_violazione = [e for e in evidenze if e.finding_type == "email_exposed_in_breach"]
    recenti = [e for e in evidenze if e.finding_type == "email_credentials_recently_exposed"]
    assert sorted(e.detail for e in per_violazione) == ["Adobe", "LinkedIn", "Zynga"]
    assert len(recenti) == 1
    assert recenti[0].detail == str(anno)


def test_la_gravita_distingue_i_tre_casi():
    anno_recente = datetime.now(UTC).year - 1
    assert severita_violazione(anno_recente, {"Passwords"}) == "high"
    assert severita_violazione(2013, {"password (hash deboli)"}) == "medium"
    assert severita_violazione(anno_recente, {"nomi", "username"}) == "low"
    assert severita_violazione(None, {"Passwords"}) == "medium", (
        "senza data la recenza non e' dimostrabile e non va supposta")


def test_le_due_fonti_convergono_sulla_stessa_impronta(adapter_context):
    """SpiderFoot e XposedOrNot possono riportare la stessa violazione per lo
    stesso indirizzo. Se le impronte divergono, la stessa esposizione viene
    detratta due volte dal rating."""
    indirizzo = f"mario.rossi@{DOMINIO}"
    da_spiderfoot, _, _ = _mappa(adapter_context, [
        _evento("EMAILADDR_COMPROMISED", f"{indirizzo} [LinkedIn]")])
    da_xposedornot = XposedOrNotAdapter(adapter_context)._evidenze(indirizzo, [
        {"breach": "LinkedIn", "domain": "", "year": "2021", "records": 0,
         "data": ["email addresses"]}])

    impronte = {e.fingerprint for e in da_xposedornot
                if e.finding_type == "email_exposed_in_breach"}
    assert da_spiderfoot[0].fingerprint in impronte


# ------------------------------------------------------------------ profili
@pytest.mark.parametrize("profilo", ["public_passive", "verified_standard", "verified_extended"])
def test_disponibile_in_tutti_i_profili(profilo):
    from adapters.registry import tools_for_profile

    assert "xposedornot" in tools_for_profile(profilo)


def test_i_moduli_sulle_violazioni_hanno_un_raccoglitore_di_indirizzi():
    """I moduli SpiderFoot sulle violazioni lavorano sugli EMAILADDR prodotti
    da altri moduli: senza un raccoglitore non ricevono input e la sezione
    dark web resta vuota senza che nulla segnali un errore."""
    from adapters.registry import load_profiles

    moduli = load_profiles()["tools"]["spiderfoot"]["modules"]
    raccoglitori = {"sfp_email", "sfp_skymem", "sfp_emailformat", "sfp_hunter"}
    consumatori = {"sfp_psbdmp", "sfp_haveibeenpwned", "sfp_dehashed", "sfp_ahmia"}
    for profilo, elenco in moduli.items():
        attivi = set(elenco)
        if attivi & consumatori:
            assert attivi & raccoglitori, (
                f"il profilo {profilo} abilita moduli sulle violazioni "
                f"({sorted(attivi & consumatori)}) senza alcun raccoglitore di indirizzi")


def test_ogni_adapter_del_profilo_e_eseguito_dalla_pipeline():
    """Gli elenchi di strumenti nella pipeline sono scritti a mano: un adapter
    ammesso dal profilo ma dimenticato in quegli elenchi non verrebbe mai
    eseguito, in silenzio e senza ridurre la copertura dichiarata."""
    import inspect

    from adapters.registry import tools_for_profile
    from app.workers import pipeline

    sorgente = inspect.getsource(pipeline.ScanPipeline.run)
    mancanti = [tool for tool in tools_for_profile("verified_extended")
                if f'"{tool}"' not in sorgente]
    assert not mancanti, f"strumenti registrati ma mai eseguiti dalla pipeline: {mancanti}"


def test_i_nuovi_tipi_hanno_una_regola_di_scoring():
    """Un rilievo senza regola non toglie punti: comparirebbe nel report ma non
    nel rating, il che e' peggio che non produrlo."""
    from app.core.config import load_yaml_config

    regole = {r["match"].get("finding_type") for r in load_yaml_config("scoring")["rules"]}
    for tipo in ("email_exposed_in_breach", "email_credentials_recently_exposed",
                 "email_in_public_paste", "organisation_data_on_leak_site"):
        assert tipo in regole, f"nessuna regola di scoring per '{tipo}'"


# ------------------------------------------------------------------- demo
def test_i_dati_sintetici_mostrano_sempre_almeno_un_indirizzo_esposto(adapter_context):
    """In mock mode la verifica sulle violazioni deve vedersi sempre.

    L'esposizione sintetica derivava dall'elenco di violazioni dell'azienda
    demo, che per molti seed e' vuoto: la sezione restava vuota e la funzione
    sembrava non funzionare.
    """
    esito = XposedOrNotAdapter(adapter_context).run()
    per_violazione = [e for e in esito.evidences
                      if e.finding_type == "email_exposed_in_breach"]
    assert per_violazione, "nessuna esposizione nei dati sintetici"
    assert all("@" in e.asset_key for e in per_violazione)


def test_in_mock_mode_le_due_fonti_non_contano_due_volte(adapter_context):
    """Le due fonti raccontano la stessa azienda sintetica: se le impronte
    divergessero, la demo mostrerebbe il doppio dei rilievi reali."""
    da_xon = {e.fingerprint for e in XposedOrNotAdapter(adapter_context).run().evidences
              if e.finding_type == "email_exposed_in_breach"}
    da_sf = {e.fingerprint for e in SpiderFootAdapter(adapter_context).run().evidences
             if e.finding_type == "email_exposed_in_breach"}
    assert da_sf and da_xon
    assert da_sf == da_xon, "le due fonti producono impronte diverse per gli stessi fatti"
