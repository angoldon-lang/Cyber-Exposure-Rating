"""Interruttore della sezione di contesto nel rapporto per la direzione.

La sezione apre l'esecutivo con i dati di settore che spiegano perche'
l'esposizione esterna vada misurata. E' attiva salvo diversa indicazione: chi
consegna a un destinatario che quel contesto lo ha gia' preferisce due pagine
in meno.

Revision ID: 0005
Revises: 0004
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

TABELLA = "tenant_branding"
COLONNA = "show_context_section"


def _presente(connessione) -> bool:  # noqa: ANN001
    ispettore = sa.inspect(connessione)
    if not ispettore.has_table(TABELLA):
        return True
    return COLONNA in {c["name"] for c in ispettore.get_columns(TABELLA)}


def upgrade() -> None:
    if _presente(op.get_bind()):
        return
    # `server_default` non e' decorativo: le righe esistenti sono anteriori
    # alla colonna e senza valore predefinito resterebbero NULL su una colonna
    # dichiarata non nulla.
    op.add_column(TABELLA, sa.Column(COLONNA, sa.Boolean(), nullable=False,
                                     server_default=sa.true()))


def downgrade() -> None:
    if not _presente(op.get_bind()):
        return
    op.drop_column(TABELLA, COLONNA)
