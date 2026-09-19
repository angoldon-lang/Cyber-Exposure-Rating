"""Conformita': framework, requisiti, controlli e stato per azienda.

## La decisione che questo file incarna

Il modo sbagliato di modellare la conformita' e' una lista di spunte per
normativa: una tabella NIS2, una DORA, una ISO 27001. Sembra semplice il
primo giorno e si paga per sempre, perche' ogni direttiva nuova e' un modulo
nuovo, e la stessa misura — poniamo l'autenticazione del dominio di posta —
viene chiesta, risposta e dimostrata tre volte.

Qui la struttura e' un'altra, e ha tre pezzi:

* il **requisito** appartiene a un framework e ne parla la lingua
  («art. 21, comma 2, lettera d»): e' quello che il legislatore chiede;
* il **controllo** e' cio' che l'organizzazione fa davvero, e non appartiene
  ad alcun framework: e' l'unita' di lavoro;
* fra i due c'e' una relazione **molti-a-molti**, ed e' li' che vive la
  proprieta' che conta: *un controllo implementato una volta vale ovunque si
  applichi*. Aggiungere DORA significa aggiungere i suoi requisiti e
  collegarli ai controlli che esistono gia', non ricominciare.

Lo **stato** e' per azienda, non globale: lo stesso controllo e' implementato
da un fornitore e assente in un altro.

## Che cosa sta qui e che cosa sta in configurazione

Il catalogo — framework, requisiti, controlli e i loro collegamenti — e' un
contenuto versionato, e vive in `config/framework_*.yaml` come il modello di
scoring e il catalogo delle remediation. Queste tabelle ne sono il riflesso,
riempito dal caricatore: servono perche' lo stato per azienda abbia qualcosa
a cui agganciarsi e perche' le domande vere («quali controlli coprono
l'articolo 21 lettera d, e come stanno sui miei quaranta fornitori») siano
una join e non un ciclo in Python.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    GUID,
    Base,
    JSONType,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    tenant_column,
)

# Il cuore della scelta: un controllo soddisfa piu' requisiti, di framework
# diversi; un requisito e' soddisfatto da piu' controlli. Nessuna delle due
# direzioni e' una eccezione.
controllo_requisiti = Table(
    "conformita_controllo_requisiti",
    Base.metadata,
    Column("controllo_id", GUID(), ForeignKey("conformita_controlli.id", ondelete="CASCADE"),
           primary_key=True),
    Column("requisito_id", GUID(), ForeignKey("conformita_requisiti.id", ondelete="CASCADE"),
           primary_key=True),
)


class Framework(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Una fonte normativa o uno standard: NIS2, DORA, ISO/IEC 27001, GDPR."""

    __tablename__ = "conformita_framework"
    __table_args__ = (UniqueConstraint("code", name="uq_conformita_framework_code"),)

    code: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name_it: Mapped[str] = mapped_column(String(255), nullable=False)
    # Chi lo emana: serve a distinguere l'obbligo di legge dallo standard
    # volontario quando si presenta il risultato a chi decide.
    authority: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(32))
    description_it: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    requisiti: Mapped[list["Requisito"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan")


class Requisito(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Un requisito di un framework, citato con il suo riferimento originale.

    Il riferimento va conservato alla lettera: quando un cliente contesta una
    valutazione, la risposta e' l'articolo, non una parafrasi.
    """

    __tablename__ = "conformita_requisiti"
    __table_args__ = (
        UniqueConstraint("framework_id", "code", name="uq_conformita_requisito_code"),
    )

    framework_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("conformita_framework.id", ondelete="CASCADE"),
        nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    title_it: Mapped[str] = mapped_column(String(512), nullable=False)
    text_it: Mapped[str | None] = mapped_column(Text)
    ordinamento: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    framework: Mapped[Framework] = relationship(back_populates="requisiti")
    controlli: Mapped[list["Controllo"]] = relationship(
        secondary=controllo_requisiti, back_populates="requisiti")


class Controllo(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Cio' che l'organizzazione implementa. Indipendente dal framework.

    `finding_types_json` e' il ponte verso il motore di rating: i tipi di
    rilievo che, se presenti, dimostrano che il controllo *non* e'
    implementato. E' l'unico punto in cui la conformita' tocca le evidenze, e
    va in una direzione sola — la scansione risponde al controllo, il
    controllo non cambia il punteggio.
    """

    __tablename__ = "conformita_controlli"
    __table_args__ = (UniqueConstraint("code", name="uq_conformita_controllo_code"),)

    code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title_it: Mapped[str] = mapped_column(String(512), nullable=False)
    description_it: Mapped[str | None] = mapped_column(Text)
    # Corrisponde alle aree del modello di rating: permette di leggere la
    # conformita' con lo stesso vocabolario del punteggio.
    area: Mapped[str | None] = mapped_column(String(64), index=True)
    # Che prova si chiede all'organizzazione quando il controllo non e'
    # osservabile dall'esterno. Senza, «implementato» resta una parola.
    evidenza_attesa_it: Mapped[str | None] = mapped_column(Text)
    # Il rimedio corrispondente nel catalogo esistente, quando c'e': evita di
    # riscrivere in altri termini un intervento gia' descritto.
    remediation_catalog_id: Mapped[str | None] = mapped_column(String(64), index=True)
    finding_types_json: Mapped[list | None] = mapped_column(JSONType, default=list)

    requisiti: Mapped[list[Requisito]] = relationship(
        secondary=controllo_requisiti, back_populates="controlli")


class StatoControllo(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Stato di un controllo per una singola azienda.

    `origine` e `confidence_class` sono la coppia che tiene onesto il
    risultato. Una dichiarazione senza prova allegata non vale quanto un
    rilievo osservato, e il documento deve poterlo dire: il motore ha gia' le
    classi di evidenza, qui si riusano invece di inventarne altre.

    `valido_fino_al` esiste perche' le prove scadono. Un certificato allegato
    due anni fa non dimostra niente oggi, e un sistema che non lo sa invecchia
    silenziosamente verso il verde.
    """

    __tablename__ = "conformita_stato_controlli"
    __table_args__ = (
        UniqueConstraint("company_id", "controllo_id", name="uq_conformita_stato_azienda"),
        Index("ix_conformita_stato_tenant_company", "tenant_id", "company_id"),
    )

    tenant_id: Mapped[uuid.UUID] = tenant_column()
    company_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    controllo_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("conformita_controlli.id", ondelete="CASCADE"),
        nullable=False, index=True)

    stato: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    origine: Mapped[str] = mapped_column(String(24), nullable=False)
    confidence_class: Mapped[str] = mapped_column(String(24), nullable=False)

    note_it: Mapped[str | None] = mapped_column(Text)
    evidenza_riferimento: Mapped[str | None] = mapped_column(String(512))
    valido_fino_al: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rilevato_il: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Chi ha risposto: un utente della piattaforma, oppure nessuno quando lo
    # stato e' dedotto dalla scansione.
    dichiarato_da: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), index=True)

    controllo: Mapped[Controllo] = relationship()
