"""Test del percorso di installazione documentato.

Un errore in `.env.example` o in `docker-compose.yml` non fa fallire nessun
test applicativo, ma impedisce l'avvio a chi segue le istruzioni del README.
Questi test presidiano proprio quel percorso.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = REPO_ROOT / ".env.example"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

# Chiave=valore, escluse righe vuote e commenti.
ASSIGNMENT = re.compile(r"^(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>.*)$")


def _entries() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        match = ASSIGNMENT.match(line)
        if match:
            entries[match["key"]] = match["value"]
    return entries


def test_env_example_senza_commenti_a_fine_riga():
    """Il parser `.env` di Compose non riconosce i commenti a fine riga.

    `CHIAVE=valore  # nota` assegna alla variabile l'intera stringa commento
    compresa: un segreto lasciato vuoto risulterebbe valorizzato con il testo
    del commento, aggirando i controlli `:?` del compose file.
    """
    colpevoli = {k: v for k, v in _entries().items() if "#" in v}
    assert not colpevoli, (
        "commento a fine riga: il valore includerebbe il commento -> "
        f"{colpevoli}")


def test_segreti_obbligatori_restano_vuoti_nell_esempio():
    """Nessun segreto preimpostato: il file di esempio non deve essere usabile
    cosi' com'e', altrimenti si finisce in esercizio con una chiave nota."""
    entries = _entries()
    for chiave in ("POSTGRES_PASSWORD", "JWT_SECRET_KEY", "EVIDENCE_ENCRYPTION_KEY",
                   "KEYCLOAK_ADMIN_PASSWORD", "HIBP_API_KEY"):
        assert entries.get(chiave, "") == "", f"{chiave} ha un valore di default"


def test_env_example_copre_le_variabili_richieste_dal_compose():
    """Ogni `${VAR:?...}` del compose deve esistere in `.env.example`, altrimenti
    l'utente scopre la variabile mancante solo al primo `docker compose up`."""
    testo = COMPOSE_FILE.read_text(encoding="utf-8")
    richieste = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", testo))
    assert richieste, "nessuna variabile obbligatoria trovata nel compose file"
    mancanti = richieste - set(_entries())
    assert not mancanti, f"variabili obbligatorie assenti da .env.example: {mancanti}"


def test_profili_opzionali_non_bloccano_l_installazione_base():
    """Compose interpola l'intero file a prescindere dai profili attivi: una
    variabile obbligatoria dichiarata da un servizio opzionale impedirebbe
    l'avvio anche a chi quel servizio non lo usa."""
    import yaml

    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    opzionali = {nome: definizione
                 for nome, definizione in compose["services"].items()
                 if definizione.get("profiles")}
    assert opzionali, "nessun servizio con profilo trovato"
    for nome, definizione in opzionali.items():
        obbligatorie = re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", yaml.safe_dump(definizione))
        assert not obbligatorie, (
            f"il servizio opzionale '{nome}' (profili {definizione['profiles']}) "
            f"dichiara {obbligatorie} come obbligatorie: bloccherebbe anche "
            "l'installazione base")


@pytest.mark.parametrize("variabile", ["ALLOW_PRIVATE_IP_SCANNING", "SCAN_MOCK_MODE"])
def test_default_prudenti(variabile):
    """L'esempio non deve invogliare configurazioni pericolose: la scansione di
    reti private resta disabilitata e la modalita' simulata resta attiva."""
    valore = _entries()[variabile]
    atteso = "false" if variabile == "ALLOW_PRIVATE_IP_SCANNING" else "true"
    assert valore == atteso, f"{variabile}={valore}, atteso {atteso}"


def test_cors_origins_dell_esempio_e_leggibile_dalle_impostazioni(monkeypatch, tmp_path):
    """`CORS_ORIGINS` e' un elenco separato da virgole: pydantic-settings tenta
    di decodificarlo come JSON se il campo non e' annotato `NoDecode`, e l'API
    non parte affatto."""
    from app.core.config import Settings

    monkeypatch.setenv("CORS_ORIGINS", _entries()["CORS_ORIGINS"])
    settings = Settings(_env_file=None)
    assert settings.cors_origins == ["http://localhost:8080", "http://localhost:5173"]


# --------------------------------------------------------------------------
# Generazione del file .env
# --------------------------------------------------------------------------
def _genera(tmp_path, **kwargs):
    from scripts.generate_env import genera

    destinazione = tmp_path / ".env"
    genera(ENV_EXAMPLE, destinazione, **{"con_keycloak": False, **kwargs})
    return destinazione


def _valori(percorso: Path) -> dict[str, str]:
    return {m["key"]: m["value"]
            for m in (ASSIGNMENT.match(r) for r in percorso.read_text().splitlines()) if m}


def test_env_generato_valorizza_i_segreti_obbligatori(tmp_path):
    valori = _valori(_genera(tmp_path))
    for chiave in ("POSTGRES_PASSWORD", "JWT_SECRET_KEY", "EVIDENCE_ENCRYPTION_KEY"):
        assert len(valori[chiave]) >= 20, f"{chiave} troppo corta o vuota"
    # Keycloak resta vuota se non richiesta: serve solo al profilo `oidc`.
    assert valori["KEYCLOAK_ADMIN_PASSWORD"] == ""
    assert _valori(_genera(tmp_path, con_keycloak=True))["KEYCLOAK_ADMIN_PASSWORD"]


def test_segreti_generati_non_rompono_il_parser_env(tmp_path):
    """I valori finiscono in un file `.env` letto sia da Compose sia da
    pydantic-settings: niente spazi, virgolette, `#` o `$`, che altrimenti
    verrebbero interpretati o troncherebbero il valore."""
    valori = _valori(_genera(tmp_path, con_keycloak=True))
    vietati = set(" \t\"'#$`\\")
    for chiave in ("POSTGRES_PASSWORD", "JWT_SECRET_KEY", "EVIDENCE_ENCRYPTION_KEY",
                   "KEYCLOAK_ADMIN_PASSWORD"):
        assert not (set(valori[chiave]) & vietati), f"{chiave} contiene caratteri ambigui"


def test_chiave_evidenze_utilizzabile_da_fernet(tmp_path):
    """La chiave deve essere accettata da `cryptography`, non solo casuale."""
    from cryptography.fernet import Fernet

    chiave = _valori(_genera(tmp_path))["EVIDENCE_ENCRYPTION_KEY"]
    messaggio = b"evidenza riservata"
    assert Fernet(chiave.encode()).decrypt(Fernet(chiave.encode()).encrypt(messaggio)) == messaggio


def test_i_segreti_sono_diversi_a_ogni_generazione(tmp_path):
    primo = _valori(_genera(tmp_path))
    secondo = _valori(_genera(tmp_path))
    for chiave in ("POSTGRES_PASSWORD", "JWT_SECRET_KEY", "EVIDENCE_ENCRYPTION_KEY"):
        assert primo[chiave] != secondo[chiave], f"{chiave} rigenerata identica"


def test_env_generato_leggibile_solo_dal_proprietario(tmp_path):
    assert _genera(tmp_path).stat().st_mode & 0o077 == 0, "il file dei segreti e' leggibile da altri"


def test_readme_non_usa_sed_in_place():
    """`sed -i` non e' portabile: GNU vuole `sed -i`, BSD/macOS `sed -i ''`.
    Con la sintassi GNU macOS fallisce con "invalid command code". Le
    istruzioni di installazione devono restare portabili."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "sed -i" not in readme, "istruzione `sed -i` non portabile nel README"


def test_le_migrazioni_girano_dove_sta_alembic_ini():
    """`alembic.ini` sta in `backend/`, che nell'immagine e' `/srv/backend`.

    Lanciato dalla directory sbagliata, alembic non fallisce dicendo che il
    file manca: dice «No config file 'alembic.ini' found, or file has no
    '[alembic]' section», che sembra un file corrotto e manda a cercare nel
    posto sbagliato. Il comando deve quindi dichiarare la directory di lavoro.
    """
    assert (REPO_ROOT / "backend" / "alembic.ini").exists()

    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    bersaglio = makefile.split("compose-migrate: require-env", 1)[1].split("\n.PHONY", 1)[0]
    comando = [r for r in bersaglio.splitlines() if "alembic" in r and not r.strip().startswith("@#")]
    assert comando, "il target compose-migrate non esegue alembic"
    assert any("/srv/backend" in r for r in comando), (
        "il comando di migrazione non dichiara la directory di alembic.ini")


def test_le_migrazioni_non_richiedono_l_api_gia_avviata():
    """Con `exec` il comando fallisce quando l'API non e' su, dicendo che il
    container non esiste: un messaggio che non suggerisce cosa fare."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    bersaglio = makefile.split("compose-migrate: require-env", 1)[1].split("\n.PHONY", 1)[0]
    comando = " ".join(r for r in bersaglio.splitlines() if "alembic" in r)
    assert "run --rm" in comando
    assert "exec" not in comando


# --------------------------------------------------------------------------
# Contesto di build delle immagini
# --------------------------------------------------------------------------
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
DOCKERFILES = ("backend/Dockerfile", "workers/Dockerfile", "frontend/Dockerfile")


def _regole_dockerignore() -> list[tuple[str, bool]]:
    """Ritorna (pattern, e_negazione) nell'ordine di dichiarazione."""
    regole = []
    for riga in DOCKERIGNORE.read_text(encoding="utf-8").splitlines():
        riga = riga.strip()
        if not riga or riga.startswith("#"):
            continue
        negato = riga.startswith("!")
        regole.append((riga.lstrip("!").rstrip("/"), negato))
    return regole


def _escluso(percorso: str) -> bool:
    """Applica le regole in ordine: vince l'ultima che corrisponde, come Docker."""
    from fnmatch import fnmatch

    esito = False
    for pattern, negato in _regole_dockerignore():
        parti = percorso.split("/")
        corrisponde = any(
            fnmatch("/".join(parti[:i + 1]), pattern) or fnmatch(parti[i], pattern)
            for i in range(len(parti)))
        if corrisponde:
            esito = not negato
    return esito


def _sorgenti_copiate() -> set[str]:
    """Percorsi del contesto referenziati dalle istruzioni COPY dei Dockerfile."""
    sorgenti: set[str] = set()
    for nome in DOCKERFILES:
        for riga in (REPO_ROOT / nome).read_text(encoding="utf-8").splitlines():
            riga = riga.strip()
            if not riga.upper().startswith("COPY "):
                continue
            argomenti = [a for a in riga.split()[1:] if not a.startswith("--")]
            if any(a.startswith("--from=") for a in riga.split()):
                continue  # proviene da uno stage precedente, non dal contesto
            sorgenti.update(a.rstrip("/") for a in argomenti[:-1])
    return sorgenti


def test_dockerignore_non_esclude_i_file_necessari_alla_build():
    """Un `.dockerignore` troppo aggressivo fa fallire la build con
    "file not found in build context", errore che si manifesta solo in
    container e mai nei test applicativi."""
    for sorgente in sorted(_sorgenti_copiate()):
        pulito = sorgente.rstrip("*")
        if not pulito:
            continue
        assert not _escluso(pulito), (
            f"'{sorgente}' e' referenziato da un COPY ma escluso dal contesto")


@pytest.mark.parametrize("percorso", [
    "frontend/node_modules", ".venv", ".git", "frontend/dist",
    ".env", ".demo-credentials.json", "demo.db", "sample-output",
])
def test_dockerignore_esclude_host_e_segreti(percorso):
    """`frontend/node_modules` contiene pacchetti specifici della piattaforma
    (`@esbuild/darwin-arm64` su Mac, `@rollup/rollup-linux-x64-gnu` su Linux):
    copiato nell'immagine sovrascrive quelli installati da `npm ci` e fa
    fallire `npm run build`. I segreti non devono comunque mai finire in
    un'immagine."""
    assert _escluso(percorso), f"'{percorso}' finirebbe nel contesto di build"


def test_env_example_resta_nel_contesto():
    """Escluso da `.env.*`, va riammesso: e' l'unico file di configurazione
    che ha senso distribuire."""
    assert not _escluso(".env.example")


# --------------------------------------------------------------------------
# Salvataggio delle credenziali dimostrative
# --------------------------------------------------------------------------
def test_seed_non_fallisce_se_la_destinazione_non_e_scrivibile(monkeypatch, tmp_path, capsys):
    """Il container API gira con filesystem in sola lettura.

    Il file delle credenziali e' una comodita': se non e' scrivibile il comando
    deve avvisare e proseguire. Farlo fallire distruggerebbe l'unica copia in
    chiaro di password gia' scritte nel database, dove restano solo come hash e
    dove un nuovo `seed` non le rigenera per utenti che esistono gia'.
    """
    import errno

    from app.cli import salva_credenziali

    def sola_lettura(*_args, **_kwargs):
        raise OSError(errno.EROFS, "Read-only file system")

    # Il test gira spesso come root, che ignora i permessi di directory: si
    # riproduce direttamente l'errore restituito dal container (Errno 30).
    monkeypatch.setattr("app.cli.CREDENTIALS_FILE", tmp_path / ".demo-credentials.json")
    monkeypatch.setattr(Path, "write_text", sola_lettura)

    credenziali = {"users": [{"email": "a@b.example", "role": "reviewer", "password": "x"}]}
    assert salva_credenziali(credenziali) is None

    errori = capsys.readouterr().err
    assert "impossibile salvare" in errori
    assert "copiarle adesso" in errori


def test_credenziali_salvate_con_permessi_ristretti(monkeypatch, tmp_path):
    from app.cli import salva_credenziali

    destinazione = tmp_path / "stato" / ".demo-credentials.json"
    monkeypatch.setattr("app.cli.CREDENTIALS_FILE", destinazione)
    credenziali = {"users": [{"email": "a@b.example", "role": "reviewer", "password": "x"}]}

    assert salva_credenziali(credenziali) == destinazione
    assert destinazione.stat().st_mode & 0o077 == 0, "file leggibile da altri utenti"


def test_percorso_credenziali_configurabile(monkeypatch, tmp_path):
    """Nel compose il percorso punta a un volume scrivibile."""
    import importlib

    monkeypatch.setenv("DEMO_CREDENTIALS_PATH", str(tmp_path / "altrove.json"))
    modulo = importlib.reload(importlib.import_module("app.cli"))
    try:
        assert modulo.CREDENTIALS_FILE == tmp_path / "altrove.json"
    finally:
        monkeypatch.delenv("DEMO_CREDENTIALS_PATH")
        importlib.reload(modulo)


def test_il_compose_indirizza_le_credenziali_su_un_volume_scrivibile():
    """`DEMO_CREDENTIALS_PATH` deve cadere sotto un volume montato sull'API,
    altrimenti si torna a scrivere sul filesystem in sola lettura."""
    import yaml

    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    percorso = compose["x-common-env"]["DEMO_CREDENTIALS_PATH"]
    montaggi = [m.split(":")[1] for m in compose["services"]["api"]["volumes"]]
    assert any(percorso.startswith(f"{m}/") for m in montaggi), (
        f"{percorso} non e' sotto uno dei volumi dell'API: {montaggi}")
