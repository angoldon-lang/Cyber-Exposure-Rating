"""Il motore non deve dipendere dai moduli.

La scelta e' «un repository, due prodotti»: Defenix Security Rating, che si
vende gia' oggi, e i moduli che gli si appoggiano sopra — conformita', NIS2
Starter, TPRM. Perche' restino separabili davvero, la dipendenza va in una
direzione sola:

    i moduli importano dal motore; il motore non importa mai dai moduli.

Se un giorno il motore importasse dai moduli, estrarlo come prodotto a se'
diventerebbe un lavoro di districamento invece che una cancellazione di
cartelle. Una regola del genere non regge sulla buona volonta': dopo tre mesi
nessuno la ricorda, e il primo import sbagliato non fa rumore. Qui viene letta
dagli import di ogni file sorgente.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parents[1]

# Il motore: quello che si vende come Security Rating, senza moduli.
MOTORE = (
    RADICE / "backend" / "app" / "core",
    RADICE / "backend" / "app" / "models",
    RADICE / "backend" / "app" / "services",
    RADICE / "backend" / "app" / "api",
    RADICE / "backend" / "app" / "schemas",
    RADICE / "backend" / "app" / "workers",
    RADICE / "adapters",
    RADICE / "reporting",
)

# I moduli: i contesti applicativi costruiti sopra.
MODULI = RADICE / "backend" / "app" / "moduli"

PREFISSO_MODULI = "app.moduli"


def _sorgenti(radice: Path) -> list[Path]:
    return [p for p in radice.rglob("*.py") if "__pycache__" not in p.parts]


def _moduli_importati(percorso: Path) -> set[str]:
    """I moduli importati da un file, sia `import x` sia `from x import y`.

    Gli import relativi non servono a questo controllo: restano dentro il
    pacchetto che li contiene, e un pacchetto del motore non puo' raggiungere
    i moduli per via relativa.
    """
    albero = ast.parse(percorso.read_text(encoding="utf-8"), filename=str(percorso))
    nomi: set[str] = set()
    for nodo in ast.walk(albero):
        if isinstance(nodo, ast.Import):
            nomi.update(alias.name for alias in nodo.names)
        elif isinstance(nodo, ast.ImportFrom) and nodo.level == 0 and nodo.module:
            nomi.add(nodo.module)
    return nomi


def test_il_motore_non_importa_dai_moduli():
    violazioni = []
    for radice in MOTORE:
        if not radice.is_dir():
            continue
        for percorso in _sorgenti(radice):
            for nome in _moduli_importati(percorso):
                if nome == PREFISSO_MODULI or nome.startswith(PREFISSO_MODULI + "."):
                    violazioni.append(f"{percorso.relative_to(RADICE)} importa {nome}")

    assert not violazioni, (
        "il motore dipende dai moduli, e cosi' i due prodotti non sono piu' "
        "separabili:\n  " + "\n  ".join(violazioni))


def test_il_registro_dei_modelli_del_motore_resta_pulito():
    """`app/models/__init__.py` e' il punto in cui la regola si romperebbe per
    comodita': basta importarvi una tabella dei moduli perche' Alembic la
    veda. I moduli tengono il proprio registro, e l'ambiente di migrazione
    importa entrambi."""
    percorso = RADICE / "backend" / "app" / "models" / "__init__.py"
    testo = percorso.read_text(encoding="utf-8")

    assert PREFISSO_MODULI not in testo, (
        "il registro dei modelli del motore importa dai moduli: usare il "
        "registro in app/moduli/__init__.py e importarlo da alembic/env.py")


def test_l_ambiente_di_migrazione_vede_entrambi_i_registri():
    """Se `env.py` non importa il registro dei moduli, le loro tabelle non
    finiscono in `Base.metadata` e le migrazioni le ignorano in silenzio."""
    percorso = RADICE / "backend" / "alembic" / "env.py"
    testo = percorso.read_text(encoding="utf-8")

    assert "from app.models import" in testo
    assert PREFISSO_MODULI in testo, (
        "alembic/env.py non importa il registro dei moduli: le loro tabelle "
        "non verrebbero viste dalle migrazioni")


@pytest.mark.parametrize("pacchetto", ["nis2", "tprm"])
def test_i_moduli_non_si_importano_fra_loro_se_non_dal_comune(pacchetto):
    """Un modulo puo' appoggiarsi a `conformita`, che e' il fondamento comune,
    ma non al modulo accanto: NIS2 Starter e TPRM si vendono separatamente, e
    un import incrociato li salda."""
    radice = MODULI / pacchetto
    if not radice.is_dir():
        pytest.skip(f"il modulo «{pacchetto}» non esiste ancora")

    fratelli = {p.name for p in MODULI.iterdir()
                if p.is_dir() and p.name not in {pacchetto, "conformita", "__pycache__"}}
    violazioni = [
        f"{percorso.relative_to(RADICE)} importa {nome}"
        for percorso in _sorgenti(radice)
        for nome in _moduli_importati(percorso)
        if any(nome.startswith(f"{PREFISSO_MODULI}.{f}") for f in fratelli)
    ]
    assert not violazioni, "moduli saldati fra loro:\n  " + "\n  ".join(violazioni)
