"""Conformita': framework, requisiti, controlli e stato per azienda.

Le tabelle del catalogo non portano `tenant_id`: framework e controlli sono
contenuto condiviso, caricato da `config/framework_*.yaml`. Lo stato invece e'
per azienda, quindi `conformita_stato_controlli` e' isolato per tenant come
tutte le altre tabelle che contengono dati dei clienti.

Revision ID: 0006
Revises: 0005
"""
from __future__ import annotations

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

TABELLE = (
    "conformita_framework",
    "conformita_requisiti",
    "conformita_controlli",
    "conformita_controllo_requisiti",
    "conformita_stato_controlli",
)

# L'unica con dati di un cliente dentro.
TABELLA_TENANT = "conformita_stato_controlli"


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    # L'import del registro dei moduli e' cio' che mette queste tabelle in
    # `Base.metadata`: senza, `create_all` non le vedrebbe.
    import app.moduli  # noqa: F401
    from app.models import Base

    bind = op.get_bind()
    ispettore = op.get_bind().dialect.has_table
    da_creare = [Base.metadata.tables[nome] for nome in TABELLE
                 if nome in Base.metadata.tables and not ispettore(bind, nome)]
    if da_creare:
        Base.metadata.create_all(bind=bind, tables=da_creare)

    if not _is_postgres():
        return

    op.execute(f"ALTER TABLE {TABELLA_TENANT} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {TABELLA_TENANT} FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY {TABELLA_TENANT}_tenant_isolation ON {TABELLA_TENANT}
        USING (
            current_setting('defenix.tenant_id', true) IS NULL
            OR current_setting('defenix.tenant_id', true) = ''
            OR tenant_id::text = current_setting('defenix.tenant_id', true)
        )
    """)


def downgrade() -> None:
    if _is_postgres():
        op.execute(
            f"DROP POLICY IF EXISTS {TABELLA_TENANT}_tenant_isolation ON {TABELLA_TENANT}")
    for nome in reversed(TABELLE):
        op.execute(f"DROP TABLE IF EXISTS {nome}")
