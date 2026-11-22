"""Richieste HTTP verso fonti di intelligence, con redirect controllati.

I client degli adapter usano `follow_redirects=False` per una ragione precisa:
seguire un redirect alla cieca permetterebbe a una risposta di dirottare la
richiesta verso `127.0.0.1`, un indirizzo di rete interna o l'endpoint di
metadata del cloud provider. E' la stessa difesa che il ScopeGuard applica ai
target di scansione.

Rifiutare del tutto i redirect ha pero' un costo: diversi servizi legittimi ne
usano di normali (`api.ransomware.live` risponde 302, i server RDAP rimandano
al registro competente), e la fonte veniva dichiarata irraggiungibile.

Qui i redirect si seguono, ma ogni salto e' rivalutato dal ScopeGuard prima di
essere percorso: le destinazioni non pubbliche restano bloccate.
"""
from __future__ import annotations

import ipaddress
import time
from urllib.parse import urlsplit

import httpx

from app.services.scope_guard import (
    CLOUD_METADATA_ADDRESSES,
    normalize_hostname,
    resolve_hostname,
)

# Piu' di pochi salti non e' un redirect legittimo: e' un anello o un tentativo
# di aggirare il controllo sfinendolo.
MAX_SALTI = 4


# Nomi che non devono mai essere contattati, anche quando il risolutore non e'
# disponibile per confermarlo.
NOMI_LOCALI = frozenset({"localhost", "localhost.localdomain", "ip6-localhost",
                         "metadata", "metadata.google.internal"})


class RedirectNonConsentito(RuntimeError):
    """Un salto puntava a una destinazione non consentita."""


def destinazione_consentita(url: str) -> tuple[bool, str]:
    """Vera se l'URL punta a un host pubblico raggiungibile senza rischi.

    Qui NON si applica il perimetro autorizzato della scansione: queste
    richieste vanno a fonti di intelligence di terze parti, che con il
    perimetro del cliente non hanno nulla a che vedere. Il controllo e' quello
    contro l'SSRF: nessun indirizzo di loopback, privato, link-local o di
    metadata del cloud provider.
    """
    parti = urlsplit(url)
    if parti.scheme not in {"http", "https"}:
        return False, f"schema non ammesso: {parti.scheme or 'assente'}"
    if parti.username or parti.password:
        return False, "URL con credenziali incorporate"
    if not parti.hostname:
        return False, "host assente"

    try:
        host = normalize_hostname(parti.hostname)
    except Exception as errore:  # noqa: BLE001
        return False, f"host non valido: {errore}"

    if host in CLOUD_METADATA_ADDRESSES or host in NOMI_LOCALI:
        return False, f"destinazione locale o di metadata: {host}"

    # Host indicato come indirizzo: si valuta direttamente.
    try:
        indirizzo = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not indirizzo.is_global or indirizzo.is_loopback or indirizzo.is_link_local:
            return False, f"indirizzo non pubblico: {host}"
        return True, "consentito"

    # Host indicato come nome: si valutano gli indirizzi risolti, per impedire
    # che un nome pubblico punti alla rete interna (DNS rebinding). Se la
    # risoluzione non produce nulla non si blocca: succede anche in modalita'
    # simulata e con risolutori indisponibili, e in quel caso la richiesta
    # fallirebbe comunque da se'. Gli attacchi realistici usano un indirizzo
    # letterale o un nome che risolve davvero: entrambi restano coperti.
    for grezzo in resolve_hostname(host):
        if grezzo in CLOUD_METADATA_ADDRESSES:
            return False, "endpoint di metadata del cloud provider"
        try:
            indirizzo = ipaddress.ip_address(grezzo)
        except ValueError:
            return False, f"indirizzo non valido: {grezzo}"
        if not indirizzo.is_global or indirizzo.is_loopback or indirizzo.is_link_local:
            return False, f"il nome {host} risolve a un indirizzo non pubblico: {grezzo}"
    return True, "consentito"


def get_da_servizio_configurato(client: httpx.Client, url: str, *, base: str,
                                parametri: dict[str, str] | None = None,
                                intestazioni: dict[str, str] | None = None,
                                max_salti: int = MAX_SALTI) -> httpx.Response:
    """GET verso un servizio indicato dall'operatore, non verso un bersaglio.

    `destinazione_consentita` rifiuta gli indirizzi non pubblici, ed e' cio'
    che deve fare per i bersagli: serve a impedire che un dominio in
    scansione, o il redirect di un sito scansionato, porti la piattaforma a
    interrogare la propria rete interna.

    Un servizio come SpiderFoot non e' un bersaglio: e' infrastruttura, il cui
    indirizzo lo scrive un amministratore nella configurazione, come per il
    database. Farlo passare da quel controllo lo rendeva inutilizzabile
    proprio nella distribuzione tipica, dove gira accanto al worker su un
    indirizzo privato.

    La protezione che resta e' quella che qui conta: i redirect non possono
    uscire dall'origine configurata. Un servizio compromesso non puo' usarci
    per raggiungere qualcos'altro.
    """
    origine = httpx.URL(base)
    # I parametri si aggiungono qui e non concatenandoli all'indirizzo: la
    # codifica la fa la libreria, e un valore che contenga `&` o `#` non puo'
    # diventare un parametro in piu'.
    if parametri:
        url = str(httpx.URL(url).copy_merge_params(parametri))

    def stessa_origine(indirizzo: str) -> bool:
        altro = httpx.URL(indirizzo)
        return (altro.scheme == origine.scheme and altro.host == origine.host
                and altro.port == origine.port)

    if not stessa_origine(url):
        raise RedirectNonConsentito(
            f"indirizzo fuori dal servizio configurato: {url}")

    corrente = url
    for _ in range(max_salti):
        risposta = client.get(corrente, headers=intestazioni or {})
        if not risposta.is_redirect:
            return risposta
        destinazione = risposta.headers.get("location")
        if not destinazione:
            return risposta
        destinazione = str(httpx.URL(corrente).join(destinazione))
        if not stessa_origine(destinazione):
            raise RedirectNonConsentito(
                f"il servizio configurato reindirizza fuori da se stesso: {destinazione}")
        corrente = destinazione

    raise RedirectNonConsentito(f"superati {max_salti} redirect consecutivi")


# Quante volte si ritenta una fonte pubblica che risponde male. Due tentativi
# in tutto: un 502 di crt.sh e' transitorio e passa al secondo colpo, mentre
# insistere oltre trasforma una fonte lenta in una scansione che non finisce.
TENTATIVI = 2
ATTESA_FRA_TENTATIVI = 2.0


def get_con_ritentativi(client: httpx.Client, url: str, *,
                        params: dict[str, str] | None = None,
                        tentativi: int = TENTATIVI,
                        attesa: float = ATTESA_FRA_TENTATIVI) -> httpx.Response:
    """GET verso una fonte di intelligence pubblica, con un secondo tentativo.

    Vale per le FONTI (crt.sh, i feed CISA), non per i bersagli di una
    scansione: la' ritentare significa raddoppiare il traffico verso i sistemi
    di un'azienda, e la cortesia verso il bersaglio e' un requisito, non una
    preferenza.

    Si ritenta soltanto cio' che ha senso ritentare:

      * 5xx -- il guasto e' del server, e crt.sh ne produce spesso di
        transitori (502 Bad Gateway sotto carico);
      * errori di trasporto -- connessione rifiutata, DNS, timeout.

    NON si ritenta un 4xx: un 404 e' una risposta legittima («nessun
    certificato per questo dominio») e un 429 e' la fonte che chiede di
    rallentare, non di riprovare subito.
    """
    ultimo_errore: Exception | None = None
    for tentativo in range(1, max(1, tentativi) + 1):
        try:
            risposta = client.get(url, params=params)
        except httpx.HTTPError as errore:
            ultimo_errore = errore
        else:
            if risposta.status_code < 500 or tentativo == tentativi:
                return risposta
            ultimo_errore = httpx.HTTPStatusError(
                f"HTTP {risposta.status_code}", request=risposta.request,
                response=risposta)
        if tentativo < tentativi:
            time.sleep(attesa)
    assert ultimo_errore is not None
    raise ultimo_errore


def get_seguendo_redirect(client: httpx.Client, url: str,
                          max_salti: int = MAX_SALTI) -> httpx.Response:
    """GET che segue i redirect validando ogni destinazione.

    `client` deve essere costruito con `follow_redirects=False`: il controllo
    dev'essere qui, non delegato alla libreria.
    """
    consentito, motivo = destinazione_consentita(url)
    if not consentito:
        raise RedirectNonConsentito(f"destinazione non consentita: {motivo}")

    corrente = url
    for _ in range(max_salti):
        risposta = client.get(corrente)
        if not risposta.is_redirect:
            return risposta

        destinazione = risposta.headers.get("location")
        if not destinazione:
            return risposta
        # La destinazione puo' essere relativa.
        destinazione = str(httpx.URL(corrente).join(destinazione))

        consentito, motivo = destinazione_consentita(destinazione)
        if not consentito:
            raise RedirectNonConsentito(f"redirect non consentito: {motivo}")
        corrente = destinazione

    raise RedirectNonConsentito(f"superati {max_salti} redirect consecutivi")
