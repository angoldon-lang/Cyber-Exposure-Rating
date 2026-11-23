#!/usr/bin/env python3
"""Avverte quando lo stack sta per avviare un servizio che nessuno usera'.

Il caso e' silenzioso e si ripete: `COMPOSE_PROFILES=osint` e' in `.env`, i
contenitori di theHarvester e SpiderFoot partono regolarmente, e in scansione
gli adapter dicono «servizio non configurato» -- perche' manca l'indirizzo che
dice loro dove trovarli. Due cose separate che sembrano una sola: il servizio
esiste, ma la piattaforma non sa che esiste.

Fin qui il disallineamento si scopriva solo a scansione finita, leggendo la
tabella delle aree non verificate. Qui si scopre prima di avviare.

Non legge il database: una variabile impostata da Personalizzazione ->
Strumenti vince su `.env` e non comparirebbe qui. Per questo l'avviso rimanda a
`make strumenti`, che il database lo interroga, invece di affermare che manchi.

Esce sempre con 0: e' un avviso, non un cancello. Avviare lo stack con uno
strumento non configurato e' legittimo -- si perde copertura, e il report lo
dichiara.
"""
from __future__ import annotations

import re
from pathlib import Path

RADICE = Path(__file__).resolve().parents[1]
ASSEGNAZIONE = re.compile(r"^(?P<chiave>[A-Z][A-Z0-9_]*)=(?P<valore>.*)$")


def _valori_env(percorso: Path) -> dict[str, str]:
    valori: dict[str, str] = {}
    if not percorso.is_file():
        return valori
    for riga in percorso.read_text(encoding="utf-8").splitlines():
        trovata = ASSEGNAZIONE.match(riga)
        if trovata:
            valori[trovata["chiave"]] = trovata["valore"].strip()
    return valori


def variabili_di_indirizzo() -> dict[str, str]:
    """Strumento -> variabile che ne porta l'indirizzo, letta dal sorgente.

    Si legge il file invece di importarlo. `app.services.tool_config` importa
    le impostazioni, che validano `JWT_SECRET_KEY`: make non esporta `.env`,
    quindi l'import falliva e l'intero controllo taceva. Un avviso che non
    compare mai e' peggio di nessun avviso, perche' si crede di averlo.

    Un test confronta questa lettura con l'elenco vero, dove le impostazioni
    si caricano davvero.
    """
    sorgente = (RADICE / "backend" / "app" / "services" / "tool_config.py"
                ).read_text(encoding="utf-8")
    coppie = re.findall(
        r'nome="([A-Z][A-Z0-9_]*_URL)",\s*strumento="([a-z_]+)"', sorgente)
    return {strumento: nome for nome, strumento in coppie}


def main() -> int:
    try:
        import yaml
    except ImportError:
        return 0  # senza PyYAML non si avvisa: questo non deve bloccare un avvio

    env = _valori_env(RADICE / ".env")
    profili_attivi = {p.strip() for p in env.get("COMPOSE_PROFILES", "").split(",") if p.strip()}
    if not profili_attivi:
        return 0  # il caso «nessun profilo» ha gia' il suo avviso

    catalogo = yaml.safe_load(
        (RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))["tools"]
    indirizzo_di = variabili_di_indirizzo()

    mancanti: list[tuple[str, str, str]] = []  # (servizio, variabile, suggerimento)
    for chiave, voce in catalogo.items():
        servizio = voce.get("compose_service")
        if not servizio or voce.get("compose_profile") not in profili_attivi:
            continue
        variabile = indirizzo_di.get(chiave)
        if variabile and not env.get(variabile):
            porta = {"spiderfoot": 5001, "theharvester": 5000, "zap": 8090}.get(servizio, 80)
            mancanti.append((servizio, variabile, f"{variabile}=http://{servizio}:{porta}"))

    if not mancanti:
        return 0

    print("AVVISO: questi servizi verranno avviati, ma la piattaforma non sa")
    print("        dove trovarli, e in scansione risulteranno non configurati:")
    print()
    for servizio, _variabile, suggerimento in mancanti:
        print(f"  {servizio:14s} aggiungere a .env:  {suggerimento}")
    print()
    print("  Se li hai gia' impostati da Personalizzazione -> Strumenti, quelli")
    print("  valgono e questo avviso non si applica: `make strumenti` lo conferma.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
