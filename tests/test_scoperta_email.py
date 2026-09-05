"""Scoperta degli indirizzi e-mail dell'organizzazione.

La verifica sulle violazioni ha bisogno di indirizzi da cercare. Finche'
l'unica fonte e' stata SpiderFoot, senza un'istanza configurata non c'era
alcun indirizzo e la sezione dark web restava vuota, senza che nulla dicesse
che la causa era una dipendenza mancante e non l'assenza di esposizione.
"""
from __future__ import annotations

import pytest

from adapters.base import AdapterStatus
from adapters.email_discovery_adapter import (
    EmailDiscoveryAdapter,
    indirizzi_da_dmarc,
    indirizzo_da_soa,
)

pytestmark = pytest.mark.security

DOMINIO = "acme-test.example"


# ------------------------------------------------------------------- DMARC
def test_estrae_tutte_le_destinazioni_dei_rapporti_dmarc():
    record = ("v=DMARC1; p=quarantine; rua=mailto:dmarc@acme.it!10m, "
              "mailto:report@acme.it; ruf=mailto:forense@acme.it")
    assert indirizzi_da_dmarc(record) == [
        "dmarc@acme.it", "report@acme.it", "forense@acme.it"]


def test_un_record_senza_destinazioni_non_produce_indirizzi():
    assert indirizzi_da_dmarc("v=DMARC1; p=none") == []
    assert indirizzi_da_dmarc("") == []


# --------------------------------------------------------------------- SOA
def test_il_rname_del_soa_diventa_un_indirizzo():
    """Nel SOA la chiocciola e' scritta come punto."""
    assert indirizzo_da_soa("hostmaster.acme.it.") == "hostmaster@acme.it"


def test_un_punto_protetto_fa_parte_del_nome_della_casella():
    assert indirizzo_da_soa(r"mario\.rossi.acme.it.") == "mario.rossi@acme.it"


def test_un_rname_troppo_corto_non_e_un_indirizzo():
    """Con due sole etichette il valore non e' un indirizzo: spezzarlo
    produrrebbe «acme@it», che verrebbe poi cercato sulle fonti."""
    assert indirizzo_da_soa("acme.it.") is None
    assert indirizzo_da_soa("") is None


# ----------------------------------------------------------------- adapter
def test_gli_indirizzi_di_terzi_non_vengono_raccolti(adapter_context):
    """Un `rua` che punta a un elaboratore DMARC di terzi e' la norma: e' un
    indirizzo del fornitore e un dato personale estraneo al perimetro."""
    adattatore = EmailDiscoveryAdapter(adapter_context)
    assert adattatore._in_perimetro(f"dmarc@{DOMINIO}")
    assert adattatore._in_perimetro(f"x@sub.{DOMINIO}")
    assert not adattatore._in_perimetro("rua@elaboratore-dmarc.example")
    assert not adattatore._in_perimetro("senza-chiocciola")


def test_gli_indirizzi_dichiarati_diventano_asset(adapter_context):
    """Senza, comparirebbero nei rilievi sulle violazioni ma non
    nell'inventario degli asset."""
    adapter_context.mock_mode = False
    adapter_context.email_addresses = [f"amministrazione@{DOMINIO}", "tizio@altro.example"]
    esito = EmailDiscoveryAdapter(adapter_context).run()
    assert esito.status is AdapterStatus.SUCCESS
    chiavi = {a.asset_key for a in esito.assets}
    assert f"amministrazione@{DOMINIO}" in chiavi
    assert "tizio@altro.example" not in chiavi


def test_gli_indirizzi_sono_mascherati_nell_asset(adapter_context):
    esito = EmailDiscoveryAdapter(adapter_context).run()
    assert esito.assets
    for asset in esito.assets:
        assert asset.display_name != asset.asset_key
        assert "*" in asset.display_name
        assert asset.attributes["masked"] is True


def test_l_output_grezzo_non_contiene_indirizzi_in_chiaro(adapter_context):
    """L'output grezzo viene archiviato: se contenesse gli indirizzi completi,
    mascherarli nel modello dati non servirebbe a nulla."""
    adapter_context.mock_mode = False
    adapter_context.email_addresses = [f"mario.rossi@{DOMINIO}"]
    esito = EmailDiscoveryAdapter(adapter_context).run()
    assert b"mario.rossi@" not in (esito.raw_output or b"")


# ------------------------------------------------------------- integrazione
@pytest.mark.parametrize("profilo", ["public_passive", "verified_standard", "verified_extended"])
def test_ammesso_in_tutti_i_profili(profilo):
    """Sono interrogazioni al DNS pubblico: nessun contatto con i sistemi
    dell'organizzazione."""
    from adapters.registry import tools_for_profile

    assert "email_discovery" in tools_for_profile(profilo)


def test_gli_indirizzi_scoperti_alimentano_la_verifica_sulle_violazioni():
    """L'ordine conta: la scoperta sta in discovery, la verifica in analisi.

    Invertirli lascerebbe XposedOrNot senza indirizzi, che e' esattamente il
    guasto silenzioso da cui nasce questo strumento.
    """
    import inspect

    from app.workers import pipeline

    sorgente = inspect.getsource(pipeline.ScanPipeline.run)
    posizione_scoperta = sorgente.index('"email_discovery"')
    posizione_verifica = sorgente.index('"xposedornot"')
    assert posizione_scoperta < posizione_verifica
    assert "discovered_emails=discovered_emails" in sorgente


def test_un_indirizzo_nel_perimetro_non_allarga_quello_degli_host():
    """Una voce di perimetro di tipo indirizzo e-mail non deve rendere
    scansionabile il dominio a cui appartiene."""
    from app.models.enums import ScopeEntryType
    from app.services.scope_guard import ScopeEntry, ScopeGuard

    guardia = ScopeGuard([ScopeEntry(ScopeEntryType.EMAIL_ADDRESS.value,
                                     "mario@acme-test.example")])
    assert not guardia.check_hostname("acme-test.example").allowed
    assert not guardia.check_hostname("www.acme-test.example").allowed


def test_la_voce_di_perimetro_valida_l_indirizzo():
    from pydantic import ValidationError

    from app.models.enums import ScopeEntryType
    from app.schemas.scope import ScopeEntryCreate

    voce = ScopeEntryCreate(entry_type=ScopeEntryType.EMAIL_ADDRESS,
                            value="  Mario.Rossi@ACME-Test.Example  ")
    assert voce.value == "mario.rossi@acme-test.example"
    with pytest.raises(ValidationError):
        ScopeEntryCreate(entry_type=ScopeEntryType.EMAIL_ADDRESS, value="senza-chiocciola")
