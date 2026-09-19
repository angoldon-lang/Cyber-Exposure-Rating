"""Caricamento e verifica del catalogo di conformita'.

Il catalogo vive in `config/framework_*.yaml` perche' e' contenuto, non
codice: si corregge in una revisione leggibile, senza toccare il programma.
Qui viene letto e soprattutto **verificato**, perche' un riferimento sbagliato
in un file di contenuto non fa rumore: produce un controllo che non copre
niente, o un ponte verso un tipo di rilievo che non esiste, e ce ne si accorge
davanti al cliente.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from app.core.config import load_yaml_config, settings

# I file del catalogo. Aggiungerne uno per DORA o ISO 27001 significa creare
# il file e nominarlo qui: i controlli esistenti lo agganciano dichiarando i
# nuovi requisiti in `soddisfa`.
FILE_CATALOGO = ("framework_nis2",)


@dataclass(frozen=True)
class RequisitoCfg:
    framework: str
    code: str
    title_it: str
    text_it: str = ""
    ordinamento: int = 0

    @property
    def riferimento(self) -> str:
        """La chiave con cui i controlli lo citano: «NIS2:art.21.2.d»."""
        return f"{self.framework}:{self.code}"


@dataclass(frozen=True)
class FrameworkCfg:
    code: str
    name_it: str
    authority: str = ""
    version: str = ""
    description_it: str = ""
    requisiti: tuple[RequisitoCfg, ...] = ()


@dataclass(frozen=True)
class ControlloCfg:
    code: str
    title_it: str
    description_it: str = ""
    area: str | None = None
    evidenza_attesa_it: str = ""
    remediation: str | None = None
    finding_types: tuple[str, ...] = ()
    soddisfa: tuple[str, ...] = ()

    @property
    def osservabile(self) -> bool:
        """Se la scansione da sola puo' rispondere a questo controllo.

        I controlli non osservabili non sono un difetto del catalogo: sono la
        ragione per cui serve il questionario, e vanno mostrati come «non
        valutati» invece che taciuti.
        """
        return bool(self.finding_types)


@dataclass
class Catalogo:
    frameworks: dict[str, FrameworkCfg] = field(default_factory=dict)
    controlli: dict[str, ControlloCfg] = field(default_factory=dict)

    @property
    def requisiti(self) -> dict[str, RequisitoCfg]:
        return {r.riferimento: r
                for f in self.frameworks.values() for r in f.requisiti}

    def controlli_per_requisito(self, riferimento: str) -> list[ControlloCfg]:
        """I controlli che coprono un requisito.

        E' la domanda che giustifica la mappatura molti-a-molti: un requisito
        e' soddisfatto da piu' controlli, e lo stesso controllo ne copre di
        framework diversi.
        """
        return [c for c in self.controlli.values() if riferimento in c.soddisfa]

    def requisiti_del_controllo(self, code: str) -> list[RequisitoCfg]:
        controllo = self.controlli.get(code)
        if controllo is None:
            return []
        tutti = self.requisiti
        return [tutti[r] for r in controllo.soddisfa if r in tutti]

    def copertura(self, framework: str) -> tuple[int, int]:
        """Quanti requisiti di un framework hanno almeno un controllo.

        Un framework i cui requisiti non sono coperti da nessun controllo e'
        una promessa vuota: la valutazione direbbe «conforme» senza avere
        guardato niente.
        """
        fw = self.frameworks.get(framework)
        if fw is None:
            return 0, 0
        coperti = sum(1 for r in fw.requisiti if self.controlli_per_requisito(r.riferimento))
        return coperti, len(fw.requisiti)


def _percorso(nome: str) -> Path:
    return settings.config_dir / f"{nome}.yaml"


def _leggi(nome: str) -> dict:
    percorso = _percorso(nome)
    if not percorso.is_file():
        raise FileNotFoundError(f"Catalogo di conformita' mancante: {percorso}")
    with percorso.open("r", encoding="utf-8") as handle:
        dati = yaml.safe_load(handle)
    if not isinstance(dati, dict):
        raise ValueError(f"Il catalogo {nome} deve essere un mapping YAML")
    return dati


def _testo(valore: object) -> str:
    """YAML `>-` conserva gli a capo del sorgente: qui servono frasi."""
    return " ".join(str(valore or "").split())


def carica(nomi: tuple[str, ...] = FILE_CATALOGO) -> Catalogo:
    """Legge i file del catalogo e li fonde in un'unica struttura."""
    catalogo = Catalogo()
    for nome in nomi:
        dati = _leggi(nome)
        for voce in dati.get("frameworks") or []:
            code = str(voce["code"])
            requisiti = tuple(
                RequisitoCfg(
                    framework=code,
                    code=str(r["code"]),
                    title_it=_testo(r.get("title_it")),
                    text_it=_testo(r.get("text_it")),
                    ordinamento=int(r.get("ordinamento", indice)),
                )
                for indice, r in enumerate(voce.get("requisiti") or [])
            )
            if code in catalogo.frameworks:
                raise ValueError(f"Framework duplicato nel catalogo: {code}")
            catalogo.frameworks[code] = FrameworkCfg(
                code=code, name_it=_testo(voce.get("name_it")),
                authority=_testo(voce.get("authority")),
                version=_testo(voce.get("version")),
                description_it=_testo(voce.get("description_it")),
                requisiti=requisiti)

        for voce in dati.get("controlli") or []:
            code = str(voce["code"])
            if code in catalogo.controlli:
                raise ValueError(f"Controllo duplicato nel catalogo: {code}")
            catalogo.controlli[code] = ControlloCfg(
                code=code,
                title_it=_testo(voce.get("title_it")),
                description_it=_testo(voce.get("description_it")),
                area=voce.get("area") or None,
                evidenza_attesa_it=_testo(voce.get("evidenza_attesa_it")),
                remediation=voce.get("remediation") or None,
                finding_types=tuple(voce.get("finding_types") or ()),
                soddisfa=tuple(voce.get("soddisfa") or ()))
    return catalogo


def verifica(catalogo: Catalogo) -> list[str]:
    """Gli errori del catalogo, in chiaro. Lista vuota significa coerente.

    Restituisce invece di sollevare: un catalogo con tre errori va corretto in
    un giro solo, non in tre.
    """
    problemi: list[str] = []
    riferimenti = set(catalogo.requisiti)

    tipi_noti = {
        str(r["match"]["finding_type"])
        for r in load_yaml_config("scoring").get("rules", [])
        if r.get("match", {}).get("finding_type")
    }
    aree_note = set(load_yaml_config("scoring").get("categories", {}))
    rimedi_noti = {
        str(r["id"]) for r in load_yaml_config("remediation_catalog").get("remediations", [])
    }

    for controllo in catalogo.controlli.values():
        if not controllo.soddisfa:
            problemi.append(f"{controllo.code}: non copre alcun requisito")
        for riferimento in controllo.soddisfa:
            if riferimento not in riferimenti:
                problemi.append(f"{controllo.code}: requisito inesistente «{riferimento}»")
        for tipo in controllo.finding_types:
            if tipo not in tipi_noti:
                problemi.append(f"{controllo.code}: tipo di rilievo inesistente «{tipo}»")
        if controllo.area and controllo.area not in aree_note:
            problemi.append(f"{controllo.code}: area inesistente «{controllo.area}»")
        if controllo.remediation and controllo.remediation not in rimedi_noti:
            problemi.append(f"{controllo.code}: rimedio inesistente «{controllo.remediation}»")
        if not controllo.osservabile and not controllo.evidenza_attesa_it:
            problemi.append(
                f"{controllo.code}: non e' osservabile dall'esterno e non dichiara "
                f"quale prova chiedere")

    for framework in catalogo.frameworks.values():
        for requisito in framework.requisiti:
            if not catalogo.controlli_per_requisito(requisito.riferimento):
                problemi.append(
                    f"{requisito.riferimento}: nessun controllo lo copre")
    return problemi


@lru_cache(maxsize=1)
def catalogo() -> Catalogo:
    """Il catalogo caricato una volta sola. `azzera_cache()` per i test."""
    return carica()


def azzera_cache() -> None:
    catalogo.cache_clear()
