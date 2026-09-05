"""Distingue gli asset osservati in modalita' dimostrativa.

Gli asset restano nel database fra una scansione e l'altra: quelli prodotti
dai dati sintetici finivano nell'inventario e nei report di scansioni reali,
indistinguibili dai dati veri. La colonna li marca; il valore viene azzerato
non appena una scansione reale osserva lo stesso asset.

Revision ID: 0003
Revises: 0002
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

COLONNA = "from_mock_scan"


def _presente(connessione) -> bool:  # noqa: ANN001
    ispettore = sa.inspect(connessione)
    if not ispettore.has_table("assets"):
        return True
    return COLONNA in {c["name"] for c in ispettore.get_columns("assets")}


def upgrade() -> None:
    # La 0001 crea lo schema dai modelli SQLAlchemy: su un'installazione nuova
    # la colonna esiste gia'. Questa revisione serve ai database creati prima.
    connessione = op.get_bind()
    if _presente(connessione):
        return
    op.add_column("assets", sa.Column(COLONNA, sa.Boolean(), nullable=False,
                                      server_default=sa.false()))


def downgrade() -> None:
    connessione = op.get_bind()
    if sa.inspect(connessione).has_table("assets") and not _presente(connessione):
        return
    if sa.inspect(connessione).has_table("assets"):
        op.drop_column("assets", COLONNA)
