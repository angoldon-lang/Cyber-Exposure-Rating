#!/usr/bin/env python3
"""Aggiunge a `.env` le variabili comparse in `.env.example`, senza toccare
i valori che ci sono.

Un `.env` nasce come copia di `.env.example` e poi non cambia piu'. Ogni
variabile nuova -- e in queste settimane ne sono comparse diverse:
COMPOSE_PROFILES, THEHARVESTER_URL -- resta fuori dal file di chi ha
installato prima, e nessuno lo dice. Lo strumento risulta non configurato,
si corregge il file, non succede niente, e la causa e' che la riga non c'e'
affatto.

`make env FORCE=1` le aggiungerebbe tutte, ma rigenerando i segreti: con un
volume postgres esistente significa non aprire piu' quel database. Qui si
aggiunge soltanto, non si sostituisce nulla.

Uso:  python3 scripts/integra_env.py [--dry-run] [--env .env]
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

RADICE = Path(__file__).resolve().parents[1]
ASSEGNAZIONE = re.compile(r"^(?P<chiave>[A-Z][A-Z0-9_]*)=(?P<valore>.*)$")

# Variabili che NON si aggiungono mai da qui: sono segreti, e una riga vuota
# aggiunta in coda a `.env` farebbe sembrare configurato cio' che non lo e',
# oppure -- peggio -- sovrascriverebbe il valore in vigore se il file ne
# avesse gia' uno piu' in alto.
# EVIDENCE_ENCRYPTION_KEY sta qui, e non fra quelle generate sotto, perche'
# e' la chiave con cui sono cifrate le prove gia' raccolte: rigenerarla
# significa non poterle piu' leggere.
SEGRETI = frozenset({"POSTGRES_PASSWORD", "JWT_SECRET_KEY", "KEYCLOAK_ADMIN_PASSWORD",
                     "EVIDENCE_ENCRYPTION_KEY"})

# Le chiavi dei servizi dello stack sono il caso opposto: aggiungerle vuote
# non servirebbe a niente, e generarle non puo' rompere nulla, perche' il
# servizio le rilegge a ogni avvio. Senza, il contenitore parte e rifiuta
# ogni richiesta -- che e' esattamente il guasto che arriva a scansione
# iniziata invece che come «non configurato».
try:
    from generate_env import CHIAVI_DI_SERVIZIO
except ImportError:  # pragma: no cover - solo se lo script viene spostato
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from generate_env import CHIAVI_DI_SERVIZIO


def _porte_dei_servizi() -> dict[str, set[str]]:
    """Le porte che ogni servizio del compose dichiara di ascoltare.

    Si legge il file come testo, senza PyYAML: questo script deve girare con
    il solo interprete di sistema, perche' chi lo lancia non ha ancora
    l'ambiente dell'applicazione.
    """
    percorso = RADICE / "docker-compose.yml"
    if not percorso.is_file():
        return {}
    porte: dict[str, set[str]] = {}
    servizio: str | None = None
    dentro_i_servizi = False
    for riga in percorso.read_text(encoding="utf-8").splitlines():
        if riga.startswith("services:"):
            dentro_i_servizi = True
            continue
        if not dentro_i_servizi or not riga.strip() or riga.lstrip().startswith("#"):
            continue
        if riga[:1] not in (" ", "\t") and riga.rstrip().endswith(":"):
            dentro_i_servizi = False
            continue
        intestazione = re.match(r"^  ([a-z0-9][a-z0-9_-]*):\s*$", riga)
        if intestazione:
            servizio = intestazione[1]
            porte.setdefault(servizio, set())
            continue
        if servizio and (trovata := re.match(
                r"^\s+(?:expose|ports):\s*\[(?P<elenco>[^\]]*)\]", riga)):
            for voce in trovata["elenco"].split(","):
                pulita = voce.strip().strip("\"'")
                if pulita:
                    porte[servizio].add(pulita.split(":")[-1].split("/")[0])
    return porte


def _non_puo_funzionare(valore: str, porte: dict[str, set[str]]) -> str | None:
    """Perche' questo indirizzo non puo' funzionare, se non puo'.

    Un indirizzo che punta a un servizio del compose su una porta che quel
    servizio non ascolta non e' una scelta di chi installa: e' un valore
    rimasto indietro. Distinguerlo conta, perche' il rimedio e' opposto --
    il resto del file va lasciato stare, questo va corretto -- e perche'
    altrimenti la diagnosi dice «non raggiungibile» e manda a riavviare un
    contenitore che e' gia' acceso.
    """
    pezzi = urlsplit(valore)
    nome = (pezzi.hostname or "").lower()
    dichiarate = porte.get(nome)
    if not dichiarate:
        return None
    porta = str(pezzi.port or ("443" if pezzi.scheme == "https" else "80"))
    if porta in dichiarate:
        return None
    return (f"il servizio `{nome}` del compose ascolta sulla porta "
            f"{', '.join(sorted(dichiarate))}, non sulla {porta}")


def _chiavi(testo: str) -> list[str]:
    return [m["chiave"] for riga in testo.splitlines()
            if (m := ASSEGNAZIONE.match(riga))]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=RADICE / ".env")
    parser.add_argument("--example", type=Path, default=RADICE / ".env.example")
    parser.add_argument("--dry-run", action="store_true",
                        help="elenca cosa aggiungerebbe, senza scrivere")
    args = parser.parse_args()

    if not args.env.is_file():
        print(f"{args.env} non esiste: qui non c'e' niente da integrare.\n"
              "  make env    lo crea", file=sys.stderr)
        return 1

    esempio = args.example.read_text(encoding="utf-8")
    attuale = args.env.read_text(encoding="utf-8")
    presenti = set(_chiavi(attuale))

    # Si copiano le righe dell'esempio con il loro commento, che e' la sola
    # documentazione che quelle variabili hanno.
    da_aggiungere: list[str] = []
    commento: list[str] = []
    nomi: list[str] = []
    for riga in esempio.splitlines():
        trovata = ASSEGNAZIONE.match(riga)
        if trovata is None:
            if riga.startswith("#") and not riga.startswith("# ---"):
                commento.append(riga)
            elif not riga.strip():
                commento.clear()
            continue
        chiave = trovata["chiave"]
        if chiave in SEGRETI or chiave in CHIAVI_DI_SERVIZIO:
            commento.clear()
            continue
        if chiave in presenti:
            commento.clear()
            continue
        da_aggiungere.extend(commento)
        da_aggiungere.append(riga)
        nomi.append(chiave)
        commento.clear()

    # Un valore PRESENTE ma vecchio non si aggiunge e non si corregge -- non e'
    # lecito sovrascrivere una scelta di chi installa -- ma va detto. Si
    # guardano solo gli indirizzi: un endpoint cambiato a monte e' un guasto
    # (`api.ransomware.live` e' diventato `/v2`), mentre porte e password
    # divergono per scelta e segnalarle sarebbe rumore.
    attesi = {m["chiave"]: m["valore"].strip()
              for riga in esempio.splitlines() if (m := ASSEGNAZIONE.match(riga))}
    correnti = {m["chiave"]: m["valore"].strip()
                for riga in attuale.splitlines() if (m := ASSEGNAZIONE.match(riga))}
    vecchi = [(k, correnti[k], atteso) for k, atteso in attesi.items()
              if atteso.startswith("http") and k in correnti
              and correnti[k] and correnti[k] != atteso]
    porte = _porte_dei_servizi()
    rotti = [(k, adesso, atteso, motivo) for k, adesso, atteso in vecchi
             if (motivo := _non_puo_funzionare(adesso, porte))]
    scelte = [v for v in vecchi if v[0] not in {r[0] for r in rotti}]
    if scelte:
        print("Indirizzi che in `.env.example` sono cambiati:")
        for chiave, adesso, atteso in scelte:
            print(f"  {chiave}")
            print(f"    nel tuo .env: {adesso}")
            print(f"    nell'esempio: {atteso}")
        print("  Non li tocco: il valore e' una scelta di chi installa. Ma se non")
        print("  e' deliberata, va allineato a mano.")
        print()
    if rotti:
        print("Indirizzi che NON possono funzionare:")
        for chiave, adesso, atteso, motivo in rotti:
            print(f"  {chiave}={adesso}")
            print(f"    {motivo}")
            print(f"    lo porto a: {atteso}")
        print("  Non e' una scelta da rispettare: su quella porta non risponde")
        print("  nessuno, e la diagnosi direbbe «non raggiungibile» mandando a")
        print("  riavviare un contenitore che e' gia' acceso.")
        print()

    # Assenti, o presenti e vuote: in entrambi i casi il servizio non ha una
    # chiave, e in entrambi i casi la si puo' generare.
    da_generare = [nome for nome in CHIAVI_DI_SERVIZIO
                   if not correnti.get(nome, "").strip()]
    if da_generare:
        print("Chiavi dei servizi dello stack che mancano:")
        for nome in da_generare:
            print(f"  {nome}")
        print("  Le genero: le sceglie chi installa, non un fornitore, e senza")
        print("  di esse il servizio parte e rifiuta ogni richiesta.")
        print()

    if not nomi and not rotti and not da_generare:
        print("Niente da integrare: `.env` ha tutte le variabili dell'esempio.")
        return 0

    if nomi:
        print(f"Variabili presenti in .env.example e assenti da {args.env.name}:")
        for nome in nomi:
            print(f"  {nome}")
        print()
    if args.dry_run:
        print("(--dry-run: non ho scritto niente)")
        return 0

    salvataggio = args.env.with_name(
        f"{args.env.name}.{datetime.now(UTC):%Y%m%d-%H%M%S}.bak")
    shutil.copy2(args.env, salvataggio)
    salvataggio.chmod(0o600)

    testo = attuale if attuale.endswith("\n") else attuale + "\n"
    for chiave, adesso, atteso, _motivo in rotti:
        testo = re.sub(rf"^{re.escape(chiave)}=.*$", f"{chiave}={atteso}",
                       testo, count=1, flags=re.MULTILINE)
    for nome in da_generare:
        valore = CHIAVI_DI_SERVIZIO[nome]()
        if nome in correnti:
            testo = re.sub(rf"^{re.escape(nome)}=.*$", f"{nome}={valore}",
                           testo, count=1, flags=re.MULTILINE)
        else:
            da_aggiungere.append(f"{nome}={valore}")
    if da_aggiungere:
        testo += ("\n# --- Aggiunte da `make env-integra` "
                  f"({datetime.now(UTC):%Y-%m-%d}) ---\n")
        testo += "\n".join(da_aggiungere) + "\n"
    args.env.write_text(testo, encoding="utf-8")
    args.env.chmod(0o600)

    if nomi:
        print(f"Aggiunte {len(nomi)} variabili.", end=" ")
    if rotti:
        quanti = ("1 indirizzo che non poteva funzionare" if len(rotti) == 1
                  else f"{len(rotti)} indirizzi che non potevano funzionare")
        print(f"Corretto {quanti}." if len(rotti) == 1
              else f"Corretti {quanti}.", end=" ")
    if da_generare:
        print("Generata 1 chiave di servizio." if len(da_generare) == 1
              else f"Generate {len(da_generare)} chiavi di servizio.", end=" ")
    print(f"Copia del precedente: {salvataggio.name}")
    print("Nessun altro valore e' stato toccato.")
    if da_generare or rotti:
        print("I servizi leggono queste variabili all'avvio: va rifatto "
              "`make up` (e `docker compose --profile osint up -d` per gli "
              "strumenti OSINT).")
    print("Ora: controllare i nuovi valori e `make up`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
