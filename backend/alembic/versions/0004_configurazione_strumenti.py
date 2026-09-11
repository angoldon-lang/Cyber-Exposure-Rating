"""Valori di configurazione degli strumenti, impostabili dall'interfaccia.

Le chiavi delle fonti esterne stavano solo nelle variabili d'ambiente: per
attivare uno strumento serviva accedere al server, modificare `.env` e
riavviare. La tabella le conserva cifrate; il valore in chiaro non lascia mai
il server.

Revision ID: 0004
Revises: 0003
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

TABELLA = "tool_settings"


def _esiste(connessione) -> bool:  # noqa: ANN001
    # La 0001 crea lo schema dai modelli: su un database nuovo la tabella
    # c'e' gia'. Le migrazioni successive devono essere idempotenti.
    return sa.inspect(connessione).has_table(TABELLA)


def upgrade() -> None:
    if _esiste(op.get_bind()):
        return
    op.create_table(
        TABELLA,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("variable", sa.String(length=128), nullable=False),
        sa.Column("value_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
    )
    op.create_index(f"ix_{TABELLA}_variable", TABELLA, ["variable"], unique=True)


def downgrade() -> None:
    if _esiste(op.get_bind()):
        op.drop_index(f"ix_{TABELLA}_variable", table_name=TABELLA)
        op.drop_table(TABELLA)
