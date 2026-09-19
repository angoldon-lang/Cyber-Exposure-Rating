"""Il catalogo di conformita' e lo stato dedotto dalla scansione.

Due cose vanno tenute ferme qui. La prima e' che il catalogo sia coerente: un
riferimento sbagliato in un file di contenuto non fa rumore, produce un
controllo che non copre niente, e ce ne si accorge davanti al cliente. La
seconda e' che l'assenza di rilievi non diventi una dichiarazione di
conformita': e' la disciplina che il motore applica al rating, e qui conta di
piu', perche' il risultato finisce in un documento mostrato a un'autorita'.
"""
from __future__ import annotations

import pytest

from app.models.enums import ConfidenceClass
from app.moduli.conformita import catalogo as cat
from app.moduli.conformita.enums import OrigineStato, StatoConformita
from app.moduli.conformita.valutazione import riepilogo, valuta


@pytest.fixture
def catalogo():
    cat.azzera_cache()
    return cat.carica()


def _rilievo(finding_type: str, **extra):
    base = {
        "reference_code": "EML-001", "finding_type": finding_type,
        "confidence_class": ConfidenceClass.CONFIRMED.value,
        "severity": "high", "excluded_from_rating": False,
    }
    base.update(extra)
    return base


def _copertura(*aree: str, status: str = "success"):
    return [{"tool": "finto", "status": status, "note_it": "", "optional": False,
             "areas": list(aree)}]


# --------------------------------------------------------------------------
# Il catalogo
# --------------------------------------------------------------------------
def test_il_catalogo_e_coerente(catalogo):
    """Ogni riferimento del catalogo deve risolvere: requisiti citati dai
    controlli, tipi di rilievo, aree e rimedi."""
    problemi = cat.verifica(catalogo)
    assert not problemi, "catalogo incoerente:\n  " + "\n  ".join(problemi)


def test_ogni_requisito_e_coperto_da_almeno_un_controllo(catalogo):
    """Un framework con requisiti scoperti direbbe «conforme» senza aver
    guardato niente."""
    for codice in catalogo.frameworks:
        coperti, totali = catalogo.copertura(codice)
        assert coperti == totali, f"{codice}: {totali - coperti} requisiti senza controlli"


def test_un_controllo_copre_requisiti_di_framework_diversi(catalogo):
    """E' la proprieta' per cui esiste la mappatura molti-a-molti: implementare
    una volta deve valere ovunque si applichi. Senza almeno un controllo che
    attraversa due framework, la struttura sarebbe una lista di spunte con un
    giro in piu'."""
    incrociati = [
        c for c in catalogo.controlli.values()
        if len({r.split(":", 1)[0] for r in c.soddisfa}) > 1
    ]
    assert incrociati, "nessun controllo copre piu' di un framework"


def test_un_requisito_risale_ai_suoi_controlli(catalogo):
    """La domanda che il modulo deve saper rispondere: «chi copre l'articolo
    21 comma 2 lettera d?»."""
    controlli = catalogo.controlli_per_requisito("NIS2:art.21.2.d")

    assert controlli, "la sicurezza della catena di fornitura non e' coperta"
    assert any(c.code == "CTRL-FORNITORI" for c in controlli)


def test_i_controlli_non_osservabili_dichiarano_che_prova_chiedere(catalogo):
    """Sono la ragione per cui serve il questionario. Uno che non dice quale
    evidenza si aspetta non e' compilabile."""
    muti = [c.code for c in catalogo.controlli.values()
            if not c.osservabile and not c.evidenza_attesa_it]
    assert not muti, f"controlli non osservabili senza evidenza attesa: {muti}"


# --------------------------------------------------------------------------
# Lo stato dedotto
# --------------------------------------------------------------------------
def test_un_rilievo_smentisce_il_controllo(catalogo):
    esiti = valuta(catalogo, findings=[_rilievo("dmarc_missing")],
                   coverage_matrix=_copertura("email_dns_security"))
    posta = next(e for e in esiti if e.controllo.code == "CTRL-POSTA-AUTENTICAZIONE")

    assert posta.stato == StatoConformita.ASSENTE.value
    assert posta.origine == OrigineStato.DEDOTTO.value
    assert posta.confidence_class == ConfidenceClass.CONFIRMED.value
    assert posta.rilievi == ["EML-001"]


def test_senza_rilievi_ma_con_lo_strumento_girato_il_controllo_risulta_dedotto(catalogo):
    """«Implementato» va bene, ma l'evidenza e' *dedotta* dall'assenza, non
    osservata: e' la classe piu' debole che la piattaforma ammette."""
    esiti = valuta(catalogo, findings=[], coverage_matrix=_copertura("email_dns_security"))
    posta = next(e for e in esiti if e.controllo.code == "CTRL-POSTA-AUTENTICAZIONE")

    assert posta.stato == StatoConformita.IMPLEMENTATO.value
    assert posta.confidence_class == ConfidenceClass.INFERRED.value


def test_senza_strumenti_che_abbiano_guardato_il_controllo_resta_non_valutato(catalogo):
    """E' il caso che un sistema disonesto colorerebbe di verde: nessun
    rilievo perche' nessuno ha guardato."""
    esiti = valuta(catalogo, findings=[], coverage_matrix=_copertura("web_security"))
    posta = next(e for e in esiti if e.controllo.code == "CTRL-POSTA-AUTENTICAZIONE")

    assert posta.stato == StatoConformita.NON_VALUTATO.value
    assert posta.origine is None
    assert "nessuno strumento" in posta.motivo_it.lower()


def test_uno_strumento_guasto_non_autorizza_a_dedurre(catalogo):
    esiti = valuta(catalogo, findings=[],
                   coverage_matrix=_copertura("email_dns_security", status="failed"))
    posta = next(e for e in esiti if e.controllo.code == "CTRL-POSTA-AUTENTICAZIONE")

    assert posta.stato == StatoConformita.NON_VALUTATO.value


def test_i_controlli_non_osservabili_restano_non_valutati(catalogo):
    esiti = valuta(catalogo, findings=[], coverage_matrix=_copertura(
        "email_dns_security", "web_security", "attack_surface",
        "technical_vulnerabilities", "darkweb_breach"))
    continuita = next(e for e in esiti if e.controllo.code == "CTRL-CONTINUITA")

    assert continuita.stato == StatoConformita.NON_VALUTATO.value
    assert "risposta dell'organizzazione" in continuita.motivo_it


def test_un_rilievo_escluso_dal_rating_non_smentisce_il_controllo(catalogo):
    """Un falso positivo gia' scartato dal revisore non deve tornare dalla
    finestra a far dichiarare non conforme un controllo."""
    esiti = valuta(catalogo,
                   findings=[_rilievo("dmarc_missing", excluded_from_rating=True)],
                   coverage_matrix=_copertura("email_dns_security"))
    posta = next(e for e in esiti if e.controllo.code == "CTRL-POSTA-AUTENTICAZIONE")

    assert posta.stato == StatoConformita.IMPLEMENTATO.value


def test_la_contraddizione_fra_dichiarato_e_osservato_viene_segnalata(catalogo):
    """E' cio' che una piattaforma fatta di soli questionari non puo'
    produrre: il fornitore dichiara, la scansione smentisce."""
    esiti = valuta(
        catalogo, findings=[_rilievo("dmarc_missing")],
        coverage_matrix=_copertura("email_dns_security"),
        dichiarazioni={"CTRL-POSTA-AUTENTICAZIONE": StatoConformita.IMPLEMENTATO.value})
    posta = next(e for e in esiti if e.controllo.code == "CTRL-POSTA-AUTENTICAZIONE")

    assert posta.contraddizione_it
    assert riepilogo(esiti)["contraddizioni"] == 1


# --------------------------------------------------------------------------
# Il riepilogo
# --------------------------------------------------------------------------
def test_la_percentuale_si_calcola_sui_controlli_valutati(catalogo):
    """Dividere per il totale farebbe scendere la conformita' ogni volta che
    si aggiunge un controllo che nessuno ha ancora guardato."""
    esiti = valuta(catalogo, findings=[_rilievo("dmarc_missing")],
                   coverage_matrix=_copertura("email_dns_security"))
    sintesi = riepilogo(esiti)

    assert sintesi["valutati"] < sintesi["totale"], "il caso di prova non e' significativo"
    valutati = sintesi["valutati"]
    implementati = sintesi["conteggi"][StatoConformita.IMPLEMENTATO.value]
    assert sintesi["percentuale_sui_valutati"] == pytest.approx(
        round(100.0 * implementati / valutati, 1))


def test_senza_nulla_di_valutato_la_percentuale_non_si_inventa(catalogo):
    """Zero su zero non e' 100%, ed e' esattamente l'errore che fa sembrare
    conforme un'azienda che non e' stata guardata."""
    sintesi = riepilogo(valuta(catalogo, findings=[], coverage_matrix=[]))

    assert sintesi["valutati"] == 0
    assert sintesi["percentuale_sui_valutati"] is None


# --------------------------------------------------------------------------
# Le tabelle
# --------------------------------------------------------------------------
def test_lo_stato_e_per_azienda_e_isolato_per_tenant(db_session, tenant, company):
    """Lo stesso controllo e' implementato da un fornitore e assente in un
    altro: lo stato non puo' essere globale."""
    from app.moduli.conformita.models import Controllo, StatoControllo

    controllo = Controllo(code="CTRL-PROVA", title_it="Controllo di prova")
    db_session.add(controllo)
    db_session.flush()

    db_session.add(StatoControllo(
        tenant_id=tenant.id, company_id=company.id, controllo_id=controllo.id,
        stato=StatoConformita.IMPLEMENTATO.value,
        origine=OrigineStato.DICHIARATO.value,
        confidence_class=ConfidenceClass.PROBABLE.value))
    db_session.flush()

    riga = db_session.query(StatoControllo).one()
    assert riga.tenant_id == tenant.id
    assert riga.company_id == company.id
