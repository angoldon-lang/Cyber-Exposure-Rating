"""Perimetro degli indirizzi IP pubblici e scansione dei servizi esposti.

Il port scanning era ammesso dal profilo Extended ma non aveva bersagli
possibili: il ScopeGuard ammette solo indirizzi coperti da una voce esplicita
di perimetro, e nessuna interfaccia permetteva di crearne una. Gli indirizzi
raggiunti dai domini restavano un sottoprodotto della risoluzione DNS, senza
mai diventare bersagli.
"""
from __future__ import annotations

import pytest

from adapters.base import AdapterStatus
from adapters.ip_perimeter_adapter import IPPerimeterAdapter
from app.services.ip_perimeter import classifica, indirizzo_pubblico
from tests.test_company_crud import _azienda, admin, cliente, client, tenant_unico  # noqa: F401

pytestmark = pytest.mark.security


# ------------------------------------------------------------ classificazione
def test_le_reti_condivise_non_sono_sondabili():
    """Sondare l'edge di una CDN significa sondare l'infrastruttura del
    fornitore, che risponde per molti clienti insieme: e' esattamente cio' che
    i profili vietano come `third_party_scanning`."""
    cdn = classifica("104.16.1.1", asn_org="Cloudflare, Inc.")
    assert cdn.is_cdn and not cdn.sondabile
    assert "Cloudflare" in cdn.motivo


def test_un_istanza_su_hosting_resta_sondabile():
    """La rete e' del fornitore ma l'istanza che risponde e' del cliente:
    escluderla renderebbe la funzione inutile per le PMI, che stanno quasi
    tutte su hosting."""
    istanza = classifica("1.2.3.4", asn_org="Aruba S.p.A.")
    assert istanza.tipo_rete == "hosting"
    assert istanza.sondabile and not istanza.is_cdn


def test_il_reverse_dns_basta_a_riconoscere_una_cdn():
    """RDAP puo' non nominare il fornitore: davanti a una CDN e' meglio un
    falso positivo che una scansione su infrastruttura di terzi."""
    voce = classifica("1.2.3.4", reverse_dns="edge.cloudflare.com",
                      asn_org="Nome Non Riconoscibile Ltd")
    assert voce.is_cdn and not voce.sondabile


def test_una_rete_sconosciuta_e_sondabile():
    assert classifica("5.6.7.8", asn_org="ACME S.p.A.").sondabile


def test_gli_indirizzi_non_instradabili_sono_scartati():
    """La definizione di «pubblico» e' quella del ScopeGuard, non una seconda:
    accettare nel perimetro un indirizzo che il ScopeGuard rifiuterebbe
    produrrebbe bersagli che non si possono scansionare."""
    for privato in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1",
                    "169.254.169.254", "non-un-ip"):
        assert not indirizzo_pubblico(privato), privato
    assert indirizzo_pubblico("8.8.8.8")
    # Le reti di documentazione servono ai dati sintetici e sono ammesse solo
    # in mock mode: la suite gira in mock mode, come il ScopeGuard.
    assert indirizzo_pubblico("203.0.113.10")


# ------------------------------------------------------------------- adapter
def test_l_adapter_classifica_gli_indirizzi_risolti(adapter_context):
    adapter_context.resolved_ips = {}
    esito = IPPerimeterAdapter(adapter_context).run()
    assert esito.status is AdapterStatus.SUCCESS
    tipi = {a.attributes["network_type"] for a in esito.assets}
    assert tipi == {"condivisa", "hosting"}, (
        "la demo deve mostrare entrambi gli esiti, altrimenti l'esclusione "
        "delle reti condivise non si vede mai")


def test_saltato_senza_indirizzi_pubblici(adapter_context):
    adapter_context.mock_mode = False
    adapter_context.resolved_ips = {"10.0.0.1": ["interno.example"]}
    adapter_context.ip_addresses = []
    disponibile, motivo = IPPerimeterAdapter(adapter_context).check_available()
    assert not disponibile
    assert "nessun indirizzo IP pubblico" in motivo


def test_e_ammesso_in_tutti_i_profili():
    """Reverse DNS e RDAP sono interrogazioni a registri pubblici: nessun
    contatto con i sistemi dell'organizzazione."""
    from adapters.registry import tools_for_profile

    for profilo in ("public_passive", "verified_standard", "verified_extended"):
        assert "ip_perimeter" in tools_for_profile(profilo)


# ------------------------------------------------------------------ pipeline
def test_gli_indirizzi_scoperti_diventano_bersagli_del_port_scanning():
    """Regressione: il port scanning riceveva solo gli indirizzi dichiarati a
    mano nel perimetro, mai quelli raggiunti dai domini. In assenza di
    un'interfaccia per dichiararli, non aveva mai bersagli."""
    import inspect

    from app.workers import pipeline

    sorgente = inspect.getsource(pipeline.ScanPipeline.run)
    assert '"ip_perimeter"' in sorgente
    assert "ip_addresses=ip_addresses" in sorgente, (
        "gli indirizzi classificati non vengono passati alla fase attiva")


def test_naabu_distingue_nessun_indirizzo_da_nessuna_autorizzazione(adapter_context):
    """Due situazioni diverse richiedono azioni diverse: perimetro incompleto
    oppure consenso mancante."""
    from adapters.phase2 import NaabuAdapter

    adapter_context.profile = "verified_extended"
    adapter_context.mock_mode = False
    adapter_context.ip_addresses = ["198.51.100.7"]
    esito = NaabuAdapter(adapter_context).execute()
    assert esito.status is AdapterStatus.SKIPPED
    assert "nessuno coperto da un'autorizzazione esplicita" in (esito.error_message or "")

    adapter_context.ip_addresses = []
    vuoto = NaabuAdapter(adapter_context).execute()
    assert "nessun indirizzo IP pubblico individuato" in (vuoto.error_message or "")


# ----------------------------------------------------------------------- API
def test_ciclo_di_vita_di_un_indirizzo(client, admin):  # noqa: F811
    """Prima di questi endpoint non esisteva alcun modo di inserire un
    indirizzo nel perimetro."""
    azienda = _azienda(client, admin)
    base = f"/api/v1/companies/{azienda['id']}/ips"

    creata = client.post(base, headers=admin, json={"address": "203.0.113.10"})
    assert creata.status_code == 201, creata.text
    voce = creata.json()
    assert voce["authorized"] is False, (
        "un indirizzo entra come inventario: sondarlo va scelto, non subito")

    duplicato = client.post(base, headers=admin, json={"address": "203.0.113.10"})
    assert duplicato.status_code == 409

    autorizzata = client.post(f"{base}/{voce['id']}/authorization", headers=admin,
                              json={"authorized": True})
    assert autorizzata.status_code == 200
    assert autorizzata.json()["authorized"] is True
    assert autorizzata.json()["ownership_status"] == "verified_owned"

    assert client.delete(f"{base}/{voce['id']}", headers=admin).status_code == 204
    assert client.get(base, headers=admin).json() == []


def test_gli_indirizzi_privati_sono_rifiutati(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    for privato in ("10.0.0.1", "127.0.0.1", "192.168.1.1"):
        risposta = client.post(f"/api/v1/companies/{azienda['id']}/ips", headers=admin,
                               json={"address": privato})
        assert risposta.status_code == 422, privato


def test_una_cdn_non_puo_essere_autorizzata(client, admin):  # noqa: F811
    """L'esclusione dev'essere applicata dal server: l'interfaccia nasconde il
    controllo, ma la decisione non puo' dipendere dall'interfaccia."""
    from app.models.scope import IPAddress

    azienda = _azienda(client, admin)
    creata = client.post(f"/api/v1/companies/{azienda['id']}/ips", headers=admin,
                         json={"address": "104.16.1.1"})
    identificativo = creata.json()["id"]
    with client.session_factory() as db:
        riga = db.get(IPAddress, __import__("uuid").UUID(identificativo))
        riga.is_cdn = True
        riga.cloud_provider = "Cloudflare"
        db.commit()

    rifiutata = client.post(
        f"/api/v1/companies/{azienda['id']}/ips/{identificativo}/authorization",
        headers=admin, json={"authorized": True})
    assert rifiutata.status_code == 409
    assert "Cloudflare" in rifiutata.json()["detail"]


def test_il_perimetro_di_rete_richiede_il_permesso(client, admin, cliente):  # noqa: F811
    azienda = _azienda(client, admin)
    risposta = client.post(f"/api/v1/companies/{azienda['id']}/ips", headers=cliente,
                           json={"address": "203.0.113.11"})
    assert risposta.status_code == 403


def test_le_reti_oltre_la_soglia_sono_rifiutate(client, admin):  # noqa: F811
    azienda = _azienda(client, admin)
    base = f"/api/v1/companies/{azienda['id']}/networks"
    assert client.post(base, headers=admin, json={"cidr": "8.8.8.0/24"}).status_code == 201
    assert client.post(base, headers=admin, json={"cidr": "10.0.0.0/8"}).status_code == 422
    assert client.post(base, headers=admin, json={"cidr": "1.0.0.0/8"}).status_code == 422


def test_l_autorizzazione_copre_solo_gli_indirizzi_provati():
    """Non e' la scansione ad autorizzare: e' il documento firmato che abilita
    il profilo, di cui il perimetro dell'organizzazione fa parte.

    Le condizioni sono due e servono entrambe. La proprieta' del dominio
    dev'essere **verificata** — una prova, non una deduzione — e l'indirizzo
    non deve stare su infrastruttura condivisa, dove sondarlo colpirebbe il
    fornitore invece del cliente. Tutto il resto resta una decisione
    esplicita dell'analista.
    """
    from adapters.base import AdapterResult, AdapterStatus, DiscoveredAsset
    from app.workers.pipeline import _ip_coperti_dall_autorizzazione

    def asset(indirizzo: str, *, sondabile: bool, verificato: bool) -> DiscoveredAsset:
        return DiscoveredAsset(
            asset_key=indirizzo, asset_type="ip_address", display_name=indirizzo,
            discovered_by="ip_perimeter",
            attributes={"scannable": sondabile, "from_verified_domain": verificato})

    esito = AdapterResult(tool="ip_perimeter", status=AdapterStatus.SUCCESS, assets=[
        asset("203.0.113.10", sondabile=True, verificato=True),    # ammesso
        asset("203.0.113.11", sondabile=True, verificato=False),   # dominio non verificato
        asset("203.0.113.12", sondabile=False, verificato=True),   # infrastruttura condivisa
        asset("203.0.113.13", sondabile=False, verificato=False),
    ])
    assert _ip_coperti_dall_autorizzazione([esito]) == {"203.0.113.10"}


def test_una_scansione_dimostrativa_non_autorizza_nulla(adapter_context):
    """In mock mode i domini «verificati» sono finti: promuovere i loro
    indirizzi renderebbe sondabile un perimetro inventato."""
    import inspect

    from app.services import persistence

    sorgente = inspect.getsource(persistence._persist_ip_inventory)
    # La promozione avviene solo per gli indirizzi che la pipeline ha
    # dichiarato coperti, mai per tutti quelli osservati.
    assert "if asset.asset_key in coperti:" in sorgente
    assert "OwnershipStatus.UNVERIFIED.value" in sorgente


def test_gli_indirizzi_coperti_diventano_bersagli_senza_intervento_manuale():
    """Regressione: gli indirizzi restavano tutti non autorizzati, il port
    scanning non partiva mai e l'unico rimedio era spuntarli a mano."""
    import inspect

    from app.workers import pipeline

    sorgente = inspect.getsource(pipeline.ScanPipeline.run)
    assert "_ip_coperti_dall_autorizzazione" in sorgente
    assert "ip_autorizzati=sorted(autorizzati)" in sorgente

    costruttore = inspect.getsource(pipeline.ScanPipeline.build_context)
    assert "self._ownership_context(ip_autorizzati)" in costruttore, (
        "gli indirizzi coperti devono entrare nel perimetro del ScopeGuard")


def test_la_promozione_arriva_fino_al_perimetro_salvato():
    """Se non finisse anche nel database, l'interfaccia continuerebbe a
    mostrarli come non autorizzati e la scansione successiva ripartirebbe da
    zero."""
    import inspect

    from app.services import persistence
    from app.workers import pipeline

    assert "ip_authorized_by_scope" in inspect.getsource(pipeline.ScanPipeline.run)
    assert "ip_authorized_by_scope" in inspect.getsource(persistence._persist_ip_inventory)
