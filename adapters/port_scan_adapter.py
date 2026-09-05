"""Rilevazione dei servizi in ascolto sugli indirizzi IP autorizzati.

Perche' non basta Naabu
-----------------------
Naabu non pubblica binari per linux/arm64 (usa libpcap tramite CGO). Sulle
macchine Apple Silicon il binario non e' nel worker, l'adapter si dichiara non
disponibile e il port scanning non parte mai: il profilo Extended risultava
completo senza aver mai guardato una porta.

Questo adapter fa la stessa cosa senza dipendenze native: una connessione TCP
completa verso ciascuna coppia indirizzo/porta. E' la forma meno invasiva di
rilevazione — nessun pacchetto costruito a mano, nessun raw socket, nessun
privilegio speciale — ed e' anche quella che un servizio registra come una
normale connessione chiusa subito.

Vincoli mantenuti
-----------------
* Solo nel profilo Verified Extended, come Naabu.
* Solo su indirizzi ammessi dal ScopeGuard: l'autorizzazione resta l'unico
  cancello, e questo adapter non ne apre un secondo.
* Elenco di porte fisso e dichiarato, ritmo limitato, timeout breve.
* Le evidenze prodotte sono le stesse di Naabu: stesso tipo, stessa chiave
  d'asset, stessa impronta. Le due fonti descrivono lo stesso fatto e non
  devono contarlo due volte.
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from adapters.base import AdapterResult, AdapterStatus, BaseAdapter
from adapters.phase2 import NaabuAdapter

# Porte controllate quando la configurazione non ne dichiara altre. Sono
# servizi che non hanno ragione di rispondere da Internet, piu' i due
# amministrativi che ne hanno una solo dietro accesso controllato.
PORTE_PREDEFINITE = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587,
                     993, 995, 1433, 1723, 3306, 3389, 4443, 5432, 5900, 5985, 6379,
                     8000, 8080, 8443, 8888, 9200, 9300, 10000, 27017)


class PortScanAdapter(BaseAdapter):
    key = "port_scan"
    display_name = "Rilevazione servizi TCP"
    is_passive = False
    coverage_areas = NaabuAdapter.coverage_areas
    default_timeout = 900

    def check_available(self) -> tuple[bool, str]:
        if self.context.profile != "verified_extended":
            return False, "la rilevazione dei servizi e' ammessa solo nel profilo Verified Extended Check"
        # Esattamente uno dei due strumenti gira. Dove Naabu c'e' e' piu'
        # rapido e fa la stessa cosa; farli girare entrambi raddoppierebbe le
        # connessioni verso il cliente per ottenere gli stessi rilievi.
        from adapters.runner import is_available

        if is_available(NaabuAdapter.BINARY):
            return False, "Naabu e' presente nel worker e copre gia' la rilevazione dei servizi"
        return True, "disponibile (Naabu non presente per questa architettura)"

    # ------------------------------------------------------------------
    @property
    def porte(self) -> tuple[int, ...]:
        dichiarate = self.config.get("default_ports") or PORTE_PREDEFINITE
        return tuple(sorted({int(p) for p in dichiarate if 0 < int(p) < 65536}))

    def execute(self) -> AdapterResult:
        indirizzi = self.context.scope_guard.filter_targets(self.context.ip_addresses, "ip")
        if not indirizzi:
            scoperti = len([a for a in self.context.ip_addresses if a])
            return AdapterResult(
                tool=self.key, status=AdapterStatus.SKIPPED,
                error_message=(
                    f"{scoperti} indirizzi IP pubblici individuati, nessuno coperto da "
                    "un'autorizzazione esplicita: autorizzarli in Gestione azienda "
                    "prima di eseguire la rilevazione dei servizi"
                    if scoperti else
                    "nessun indirizzo IP pubblico individuato per i domini in perimetro"),
                coverage_impact=self.coverage_weight)

        porte = self.porte
        attesa = float(self.config.get("connect_timeout_seconds", 2.0))
        paralleli = max(1, int(self.config.get("max_concurrency", 32)))
        al_secondo = max(1, int(self.config.get("rate_limit_per_second", 100)))
        scadenza = time.monotonic() + int(
            self.config.get("timeout_seconds", self.default_timeout))

        coppie = [(indirizzo, porta) for indirizzo in indirizzi for porta in porte]
        aperte: list[dict[str, Any]] = []
        interrotto = False
        intervallo = 1.0 / al_secondo
        prossima = time.monotonic()

        def sonda(coppia: tuple[str, int]) -> tuple[str, int] | None:
            indirizzo, porta = coppia
            famiglia = socket.AF_INET6 if ":" in indirizzo else socket.AF_INET
            with socket.socket(famiglia, socket.SOCK_STREAM) as presa:
                presa.settimeout(attesa)
                try:
                    # `connect_ex` non solleva: una porta chiusa e' un esito
                    # normale, non un errore da gestire con un'eccezione.
                    if presa.connect_ex((indirizzo, porta)) == 0:
                        return coppia
                except OSError:
                    return None
            return None

        with ThreadPoolExecutor(max_workers=paralleli) as pool:
            futuri = []
            for coppia in coppie:
                if time.monotonic() > scadenza:
                    interrotto = True
                    break
                # Il ritmo si regola all'invio: limitarlo dopo non servirebbe,
                # le connessioni sarebbero gia' partite tutte insieme.
                ritardo = prossima - time.monotonic()
                if ritardo > 0:
                    time.sleep(ritardo)
                prossima = time.monotonic() + intervallo
                futuri.append(pool.submit(sonda, coppia))
            for futuro in futuri:
                esito = futuro.result()
                if esito is not None:
                    aperte.append({"ip": esito[0], "port": esito[1],
                                   "service": None, "product": None})

        evidenze, assets = self._evidenze(aperte)
        return AdapterResult(
            tool=self.key,
            status=AdapterStatus.PARTIAL if interrotto else AdapterStatus.SUCCESS,
            evidences=evidenze, assets=assets, target_count=len(indirizzi),
            tool_version="connessione TCP integrata",
            error_message=("tempo massimo raggiunto: non tutte le porte sono state "
                           "controllate" if interrotto else None),
            coverage_impact=self.coverage_weight * 0.3 if interrotto else 0.0,
            raw_output=self.dump_json({"addresses": indirizzi, "ports": list(porte),
                                       "open": aperte}),
            config_snapshot={"ports": len(porte), "addresses": len(indirizzi),
                             "open_services": len(aperte)})

    # ------------------------------------------------------------------
    def _evidenze(self, aperte: list[dict[str, Any]]):  # noqa: ANN202
        """Costruisce le evidenze con la logica di Naabu, ma a proprio nome.

        La forma dell'evidenza deve essere la stessa — le due fonti descrivono
        lo stesso fatto e devono convergere sulla stessa impronta — ma la
        provenienza no: dichiarare «rilevato da naabu» su una macchina dove
        Naabu non e' nemmeno installato renderebbe il rilievo non verificabile.
        L'impronta non dipende dallo strumento, quindi riscriverla e' sicuro.
        """
        evidenze, assets = NaabuAdapter(self.context)._build(aperte)
        for evidenza in evidenze:
            evidenza.tool = self.key
            evidenza.data_source = "Rilevazione servizi TCP autorizzata"
        for asset in assets:
            asset.discovered_by = self.key
        return evidenze, assets

    def mock(self) -> AdapterResult:
        esito = NaabuAdapter(self.context).mock()
        esito.tool = self.key
        esito.tool_version = "connessione TCP integrata (mock)"
        esito.evidences, esito.assets = self._evidenze(
            [{"ip": a.attributes["ip"], "port": a.attributes["port"],
              "service": None, "product": None} for a in esito.assets])
        return esito
