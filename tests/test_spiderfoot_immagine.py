"""SpiderFoot costruito da noi: perche' Python 3.9, e perche' niente porte.

Il progetto non pubblica un'immagine utilizzabile, ed era stato tolto dallo
stack per questo. Il sorgente invece c'e': l'immagine la costruiamo noi da un
commit pubblico, non modificato, fissato per impronta.

Due vincoli non sono preferenze e un test deve tenerli fermi.

Il primo e' Python 3.9. `requirements.txt` di SpiderFoot 4.0 chiede
`pyyaml>=5.4.1,<6`, e di pyyaml 5.4.1 esistono wheel per arm64 soltanto per
cp38 e cp39; da sorgente non si costruisce piu' (Cython 3 interrompe con
«cython_sources»). Misurato, non supposto: su 3.10 e 3.11 l'installazione
fallisce, ed e' la ragione per cui un'immagine funzionante di questo progetto
non esiste. Chi un giorno «aggiornera' la base a una versione mantenuta»
riprodurra' quel guasto, e questo test gli dice prima perche'.

Il secondo e' che la porta non si pubblica. SpiderFoot senza file `passwd` non
chiede autenticazione: la definizione che c'era fino alla 0.18.1 mappava la
5001 sull'host, ed esponeva un motore di scansione comandabile da chiunque
fosse sulla stessa rete.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

RADICE = Path(__file__).resolve().parents[1]
DOCKERFILE = (RADICE / "deploy" / "spiderfoot" / "Dockerfile").read_text(encoding="utf-8")
COMPOSE = yaml.safe_load((RADICE / "docker-compose.yml").read_text(encoding="utf-8"))
SERVIZIO = COMPOSE["services"]["spiderfoot"]


# --------------------------------------------------------------------------
# Il vincolo che non si puo' togliere senza rompere la costruzione
# --------------------------------------------------------------------------
def test_la_base_resta_python_3_9():
    """`pyyaml<6` non ha wheel arm64 oltre cp39 e non si costruisce da
    sorgente: su una base piu' recente l'immagine non si costruisce affatto."""
    basi = set(re.findall(r"^FROM (\S+)", DOCKERFILE, re.MULTILINE))

    assert basi, "nessuna immagine di base dichiarata"
    for base in basi:
        assert base.startswith("python:3.9"), (
            f"base {base}: SpiderFoot 4.0 richiede Python 3.9 per `pyyaml<6`, "
            "le cui wheel arm64 si fermano a cp39 e la cui costruzione da "
            "sorgente non riesce piu'")


def test_il_motivo_della_versione_e_scritto_nel_dockerfile():
    """Senza la spiegazione accanto al vincolo, il primo che prova ad
    aggiornare la base scopre il perche' con venti minuti di costruzione
    fallita."""
    assert "pyyaml" in DOCKERFILE
    assert "arm64" in DOCKERFILE or "aarch64" in DOCKERFILE


def test_i_pacchetti_che_si_compilano_arrivano_solo_come_wheel():
    """Se una di quelle wheel sparisse, la costruzione deve fermarsi e dirlo:
    nell'immagine non ci sono compilatori, e un tentativo di compilazione
    sarebbe venti minuti per arrivare allo stesso errore."""
    trovato = re.search(r"--only-binary=(\S+)", DOCKERFILE)

    assert trovato, "nessun vincolo sulle wheel: una compilazione silenziosa e' possibile"
    dichiarati = {p.lower() for p in trovato.group(1).split(",")}
    assert {"lxml", "cryptography", "pyyaml"} <= dichiarati, (
        f"mancano pacchetti che si compilano: {dichiarati}")


# --------------------------------------------------------------------------
# Il sorgente, fissato
# --------------------------------------------------------------------------
def test_il_sorgente_e_fissato_per_impronta_di_commit():
    """Un tag si puo' spostare. Per un progetto che non pubblica immagini, il
    commit e' l'unico ancoraggio immutabile."""
    commit = SERVIZIO["build"]["args"]["SPIDERFOOT_COMMIT"]

    assert re.fullmatch(r"[0-9a-f]{40}", str(commit)), (
        f"il commit non e' un'impronta completa: {commit}")
    assert commit in DOCKERFILE, (
        "il Dockerfile non dichiara lo stesso commit come valore predefinito: "
        "costruendolo a mano si otterrebbe un'altra versione")


def test_la_costruzione_verifica_l_impronta_che_ha_scaricato():
    """Chiedere un commit e usare quel che arriva sono due cose diverse."""
    assert "git rev-parse HEAD" in DOCKERFILE
    assert 'test "$(git rev-parse HEAD)" = "${SPIDERFOOT_COMMIT}"' in DOCKERFILE, (
        "l'impronta scaricata non viene confrontata con quella richiesta")


def test_la_licenza_dichiarata_e_quella_vera():
    """Fino alla 0.18.7 il catalogo diceva MIT. SpiderFoot 4.0 e' GPL-2.0, e
    per un prodotto commerciale la differenza non e' accademica."""
    catalogo = yaml.safe_load(
        (RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))
    licenza = catalogo["tools"]["spiderfoot"]["license"]

    assert "GPL" in licenza, f"licenza dichiarata: {licenza}"
    notices = (RADICE / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    sezione = notices.split("### SpiderFoot", 1)[1].split("###", 1)[0]
    assert "GPL-2.0" in sezione, "i notices non dichiarano la licenza vera"
    assert "MIT" not in sezione.replace("MIT**", ""), (
        "i notices dichiarano ancora MIT da qualche parte")
    assert "LICENSE" in DOCKERFILE or "LICENSE" in sezione, (
        "l'obbligo sul sorgente corrispondente non e' documentato")


# --------------------------------------------------------------------------
# Senza autenticazione, quindi senza porte
# --------------------------------------------------------------------------
def test_la_porta_non_viene_pubblicata_sull_host():
    """SpiderFoot senza file `passwd` non chiede autenticazione. La
    definizione precedente mappava la 5001 sull'host: un motore di scansione
    comandabile da chiunque fosse sulla stessa rete."""
    assert "ports" not in SERVIZIO, (
        f"il servizio pubblica {SERVIZIO.get('ports')}: senza autenticazione, "
        "non va esposto fuori dalla rete interna")
    assert SERVIZIO.get("expose") == ["5001"]
    assert SERVIZIO.get("networks") == ["backend"], (
        "deve stare sulla sola rete interna, dove lo raggiunge il worker")


def test_gira_senza_privilegi_aggiuntivi():
    assert SERVIZIO.get("cap_drop") == ["ALL"]
    assert "no-new-privileges:true" in SERVIZIO.get("security_opt", [])
    assert "USER spiderfoot" in DOCKERFILE, "il processo girerebbe come root"


def test_i_dati_stanno_su_un_volume():
    """Cache e database di SpiderFoot non devono vivere nel filesystem del
    contenitore: a ogni ricostruzione si ripartirebbe da zero."""
    montaggi = SERVIZIO.get("volumes") or []

    assert any("/var/lib/spiderfoot" in m for m in montaggi), montaggi
    assert "spiderfoot-data" in COMPOSE["volumes"]


# --------------------------------------------------------------------------
# L'integrazione con il resto
# --------------------------------------------------------------------------
def test_e_nel_profilo_osint_e_quindi_parte_con_make_up():
    assert SERVIZIO.get("profiles") == ["osint"]

    ambiente = (RADICE / ".env.example").read_text(encoding="utf-8")
    assert "COMPOSE_PROFILES=osint" in ambiente
    assert "SPIDERFOOT_URL=http://spiderfoot:5001" in ambiente, (
        "l'indirizzo predefinito non punta al servizio: lo strumento "
        "risulterebbe non configurato appena installato")


def test_il_catalogo_non_lo_dichiara_piu_sostituito():
    """Era `replaced_by: theharvester` perche' non si poteva installare. Ora si
    puo', e lasciare la sostituzione gli azzererebbe il costo di copertura
    quando invece un suo guasto e' un guasto."""
    catalogo = yaml.safe_load(
        (RADICE / "config" / "tool_profiles.yaml").read_text(encoding="utf-8"))

    assert not catalogo["tools"]["spiderfoot"].get("replaced_by")


def test_il_controllo_delle_versioni_copre_il_commit_fissato():
    checker = (RADICE / "scripts" / "check_pinned_versions.py").read_text(encoding="utf-8")

    assert "COMMIT_ARG" in checker, (
        "il commit fissato non viene verificato: un tag spostato a monte "
        "cambierebbe cosa costruiamo senza che nessuno lo noti")


@pytest.mark.parametrize("endpoint", ["/ping", "/startscan"])
def test_l_adapter_usa_gli_endpoint_che_il_servizio_espone(endpoint):
    """Verificati su un'istanza avviata davvero: `/ping` risponde
    `["SUCCESS", "4.0.0"]`."""
    adapter = (RADICE / "adapters" / "spiderfoot_adapter.py").read_text(encoding="utf-8")

    assert endpoint in adapter
