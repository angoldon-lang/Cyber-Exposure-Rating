"""Il rapporto per la direzione deve essere leggibile da chi non fa questo mestiere.

I testi divulgativi stanno in `config/narrativa_direzione.yaml` e il motore vi
attinge per chiave: una chiave che manca non rompe niente: produce una scheda
muta, che e' peggio, perche' nessuno se ne accorge finche' il documento non e'
in mano al cliente. Questi controlli tengono allineati catalogo e narrativa.
"""
from __future__ import annotations

import pytest

from app.core.config import load_yaml_config
from reporting import narrativa
from tests.test_reports import _context

CATEGORIE = [
    {"key": "attack_surface", "label_it": "Attack surface e servizi esposti",
     "weight": 0.20, "score": 100.0, "finding_count": 0,
     "critical_count": 0, "high_count": 0},
    {"key": "email_dns_security", "label_it": "Sicurezza e-mail e DNS",
     "weight": 0.20, "score": 52.0, "finding_count": 6,
     "critical_count": 0, "high_count": 1},
]


def _voce(catalog_id: str, **extra):
    base = {
        "catalog_id": catalog_id, "title_it": "Titolo tecnico",
        "area": "email_dns_security", "priority": "p1", "effort": "s",
        "risk_mitigated_it": "Rischio.", "verification_it": "Verifica.",
        "finding_codes": ["EML-001"], "max_severity": "high",
    }
    base.update(extra)
    return base


# --------------------------------------------------------------------------
# Allineamento fra catalogo tecnico e lingua divulgativa
# --------------------------------------------------------------------------
def test_ogni_remediation_ha_una_traduzione():
    """Un intervento senza testo divulgativo compare nel rapporto per la
    direzione come una scheda senza spiegazione."""
    catalogo = {r["id"] for r in load_yaml_config("remediation_catalog")["remediations"]}
    tradotti = set(load_yaml_config("narrativa_direzione")["interventi"])

    assert not catalogo - tradotti, f"senza traduzione: {sorted(catalogo - tradotti)}"
    assert not tradotti - catalogo, f"traduzioni orfane: {sorted(tradotti - catalogo)}"


def test_ogni_traduzione_e_completa():
    """Le quattro voci della scheda: che cosa manca, un paragone, che cosa
    comporta, quanto costa. Se ne manca una la scheda esce monca."""
    mancanti = [
        f"{chiave}.{campo}"
        for chiave, voce in load_yaml_config("narrativa_direzione")["interventi"].items()
        for campo in ("semplice", "manca", "paragone", "comporta", "tempo")
        if not str(voce.get(campo) or "").strip()
    ]
    assert not mancanti, f"campi vuoti: {mancanti}"


def test_ogni_area_del_rating_ha_nome_scenario_e_domande():
    aree = set(load_yaml_config("scoring")["categories"])
    narrativa_cfg = load_yaml_config("narrativa_direzione")

    for sezione in ("aree", "scenari", "domande"):
        assert not aree - set(narrativa_cfg[sezione]), (
            f"aree senza «{sezione}»: {sorted(aree - set(narrativa_cfg[sezione]))}")


def test_i_nomi_delle_aree_stanno_sugli_assi_del_radar():
    """Il radar ha poco spazio: un nome lungo viene troncato a meta' parola."""
    lunghi = [
        f"{chiave}: {voce['nome_breve']}"
        for chiave, voce in load_yaml_config("narrativa_direzione")["aree"].items()
        if len(voce["nome_breve"]) > 24
    ]
    assert not lunghi, f"nomi troppo lunghi per il radar: {lunghi}"


# --------------------------------------------------------------------------
# Comportamento
# --------------------------------------------------------------------------
def test_un_area_senza_rilievi_dice_perche_e_a_cento():
    """«100/100» non e' una risposta: la riga deve dire che cosa e' stato
    guardato e non e' emerso."""
    aree = narrativa.aree_controllate(CATEGORIE, [])
    pulita = next(a for a in aree if a["chiave"] == "attack_surface")

    assert not pulita["critica"]
    assert "Non sono emersi" in pulita["significato"]


def test_un_area_a_cento_senza_controlli_lo_dichiara():
    """Un'area alta perche' nessuno l'ha guardata non e' un'area a posto:
    tacerlo rende il punteggio fuorviante proprio dove promette chiarezza."""
    copertura = [{"tool": "nmap", "status": "skipped", "optional": True,
                  "note_it": "La scansione delle porte non e' stata eseguita",
                  "areas": ["attack_surface"]}]
    aree = narrativa.aree_controllate(CATEGORIE, copertura)
    pulita = next(a for a in aree if a["chiave"] == "attack_surface")

    assert pulita["nota_copertura"].startswith("Verifica parziale:")
    assert pulita["nota_copertura"].endswith(".")


def test_uno_strumento_riuscito_non_lascia_note():
    copertura = [{"tool": "dns", "status": "success", "optional": False,
                  "note_it": "eseguito", "areas": ["attack_surface"]}]
    aree = narrativa.aree_controllate(CATEGORIE, copertura)

    assert next(a for a in aree if a["chiave"] == "attack_surface")["nota_copertura"] == ""


def test_le_schede_seguono_la_priorita_del_piano():
    piano = [_voce("REM-DNS-CAA", priority="p4", max_severity="low"),
             _voce("REM-EMAIL-DMARC", priority="p1", max_severity="high")]
    schede = narrativa.rilievi_spiegati(piano)["schede"]

    assert [s["etichetta_gravita"] for s in schede] == ["GRAVE", "BASSA"]
    assert "Nessuno controlla" in schede[0]["titolo"]
    assert schede[0]["paragone"]


def test_i_rilievi_informativi_non_diventano_schede():
    """Non incidono sul punteggio: un riquadro a testa li farebbe pesare
    quanto un rilievo grave."""
    piano = [_voce("REM-EMAIL-DMARC"),
             _voce("REM-WEB-SECURITYTXT", priority="p4", max_severity="info")]
    esito = narrativa.rilievi_spiegati(piano)

    assert len(esito["schede"]) == 1
    assert len(esito["informativi"]) == 1


def test_un_intervento_senza_traduzione_non_lascia_la_scheda_vuota():
    """Difesa in profondita': se il catalogo cresce e la narrativa resta
    indietro, la scheda ripiega sul titolo tecnico invece di uscire muta."""
    schede = narrativa.rilievi_spiegati(
        [_voce("REM-INESISTENTE", title_it="Titolo tecnico")])["schede"]

    assert schede[0]["titolo"] == "Titolo tecnico"
    assert schede[0]["comporta"] == "Rischio."



def test_la_buona_notizia_vale_solo_per_le_configurazioni():
    """«Nessun acquisto, nessun fermo» sposta la decisione. Dirlo quando non
    e' vero la sposta nella direzione sbagliata."""
    leggero = [_voce("REM-EMAIL-DMARC", effort="s"), _voce("REM-DNS-CAA", effort="xs")]
    pesante = leggero + [_voce("REM-VULN-UPGRADE", effort="l")]

    assert narrativa.buona_notizia(leggero)
    assert narrativa.buona_notizia(pesante) == ""
    assert narrativa.buona_notizia([]) == ""


def test_lo_scenario_segue_l_area_dell_intervento_piu_urgente():
    piano = [_voce("REM-AS-VPN", area="attack_surface", priority="p1"),
             _voce("REM-EMAIL-DMARC", area="email_dns_security", priority="p2")]

    assert narrativa.area_dominante(piano, CATEGORIE) == "attack_surface"
    assert narrativa.scenario("attack_surface")["passi"]


def test_senza_piano_lo_scenario_segue_l_area_piu_debole():
    """Una scansione senza interventi ha comunque un'area piu' esposta delle
    altre: e' quella di cui vale la pena raccontare il rischio."""
    assert narrativa.area_dominante([], CATEGORIE) == "email_dns_security"


def test_il_quando_e_una_data_non_una_sigla():
    """«p1» in un documento per la direzione non significa niente."""
    righe = narrativa.interventi_in_ordine([_voce("REM-EMAIL-DMARC", priority="p1")])

    assert righe[0]["quando"] == "Subito"
    assert righe[0]["verifica"] == "Verifica."
    assert righe[0]["in_parole"]


# --------------------------------------------------------------------------
# Il documento
# --------------------------------------------------------------------------
@pytest.mark.slow
def test_il_rapporto_non_usa_le_sigle_del_motore():
    """Le chiavi interne (`p1`, `email_dns_security`, `REM-...`) non devono
    affiorare nel documento che legge l'imprenditore."""
    from reporting import service as rs

    testo = rs.generate_html(_context(), include_technical=False).content.decode("utf-8")
    corpo = testo.split("<body>", 1)[1]

    for sigla in ("REM-EMAIL", "email_dns_security", "p1", "catalog_id"):
        assert sigla not in corpo, f"sigla interna nel rapporto: {sigla}"


@pytest.mark.slow
def test_il_rapporto_spiega_il_rilievo_e_non_solo_lo_nomina():
    from reporting import service as rs

    testo = rs.generate_html(_context(), include_technical=False).content.decode("utf-8")

    assert "Che cosa manca:" in testo
    assert "Un paragone:" in testo
    assert "Che cosa comporta:" in testo
    assert "Come verificare che sia fatto" in testo


def test_i_titoli_con_un_conteggio_si_accordano():
    """«Le uno aree controllate» e «Su uno aree» erano il prezzo di scrivere
    il numero nel modello invece che qui."""
    assert narrativa.titolo_aree(5) == "Le cinque aree controllate"
    assert narrativa.titolo_aree(1) == "L'unica area controllata"
    assert narrativa.titolo_domande(3, "a chi gestisce la posta").startswith("Le tre domande")

    sintesi = narrativa.sintesi_del_risultato(52.0, narrativa.aree_controllate(CATEGORIE, []))
    assert "Su due aree" in sintesi


@pytest.mark.slow
def test_il_rapporto_word_dice_le_stesse_cose_del_pdf():
    """Chi esporta in Word non deve ricevere un documento diverso."""
    import io

    from docx import Document

    from reporting import service as rs

    documento = Document(io.BytesIO(rs.generate_docx(_context(), include_technical=False).content))
    testo = "\n".join(p.text for p in documento.paragraphs)

    assert "Che cosa manca:" in testo
    assert "Un paragone:" in testo
    assert "Che cosa puo' succedere davvero" in testo
    assert "Distribuzione limitata" in testo
    assert "uno aree" not in testo
