"""Personalizzazione dei report per tenant.

Aggiunge `tenant_branding`: nome e proprietario del marchio, colore, testi
liberi inseriti nei report e logo. Il logo sta nel database perche' il
container API gira con filesystem in sola lettura e un file su volume andrebbe
replicato e messo in backup separatamente rispetto ai dati che descrive.

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # La 0001 crea lo schema dai modelli SQLAlchemy: su un'installazione nuova
    # questa tabella esiste gia'. Questa revisione serve ai database creati
    # prima che il modello esistesse, quindi agisce solo se manca davvero.
    connessione = op.get_bind()
    if sa.inspect(connessione).has_table("tenant_branding"):
        return

    op.create_table(
        "tenant_branding",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                  nullable=False, unique=True, index=True),
        sa.Column("brand_name", sa.String(128)),
        sa.Column("brand_owner", sa.String(255)),
        sa.Column("primary_color", sa.String(9)),
        sa.Column("report_intro_it", sa.Text()),
        sa.Column("report_footer_it", sa.Text()),
        sa.Column("contact_block_it", sa.Text()),
        sa.Column("logo_bytes", sa.LargeBinary()),
        sa.Column("logo_mime", sa.String(64)),
        sa.Column("logo_filename", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
    )

    # La tabella ha `tenant_id`: riceve la stessa policy RLS delle altre.
    if connessione.dialect.name == "postgresql":
        op.execute("ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE tenant_branding FORCE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY tenant_isolation_tenant_branding ON tenant_branding "
            "USING (tenant_id = current_setting('app.tenant_id', true)::uuid)")


def downgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("tenant_branding"):
        op.drop_table("tenant_branding")
