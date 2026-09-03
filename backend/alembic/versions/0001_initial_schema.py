"""Schema iniziale Defenix Exposure Rating.

Crea tutte le tabelle dai modelli SQLAlchemy e applica le difese PostgreSQL:
  * Row Level Security su ogni tabella con `tenant_id`;
  * audit log append-only (trigger che blocca UPDATE e DELETE).

Revision ID: 0001
Revises:
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# Tabelle con `tenant_id`: ricevono una policy RLS.
TENANT_TABLES = [
    "companies", "users", "connectors", "api_key_references", "retention_policies",
    "authorizations", "scopes", "domains", "email_domains", "ip_addresses",
    "network_ranges", "brands", "assets", "asset_relationships",
    "scans", "tool_runs", "evidences", "findings",
    "scores", "score_categories", "confidence_scores",
    "reports", "report_versions",
]


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    from app.models import Base

    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    if not _is_postgres():
        return

    # ---------------------------------------------------------------
    # Row Level Security: difesa in profondita' oltre ai filtri applicativi.
    # Il ruolo applicativo NON deve essere superuser ne' avere BYPASSRLS.
    # ---------------------------------------------------------------
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
            USING (
                current_setting('defenix.tenant_id', true) IS NULL
                OR current_setting('defenix.tenant_id', true) = ''
                OR tenant_id::text = current_setting('defenix.tenant_id', true)
            )
        """)

    # ---------------------------------------------------------------
    # Audit log immutabile: nessun UPDATE o DELETE, nemmeno applicativo.
    # ---------------------------------------------------------------
    op.execute("""
        CREATE OR REPLACE FUNCTION defenix_audit_append_only()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs e'' append-only: % non consentito', TG_OP;
        END;
        $$ LANGUAGE plpgsql
    """)
    op.execute("""
        CREATE TRIGGER audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION defenix_audit_append_only()
    """)
    op.execute("""
        CREATE TRIGGER audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION defenix_audit_append_only()
    """)

    # Indici aggiuntivi per le query piu' frequenti della dashboard.
    op.create_index("ix_findings_company_severity", "findings",
                    ["company_id", "severity"], unique=False)
    op.create_index("ix_scores_company_computed", "scores",
                    ["company_id", "computed_at"], unique=False)
    op.create_index("ix_evidences_scan_fingerprint", "evidences",
                    ["scan_id", "fingerprint"], unique=False)
    op.create_index("ix_assets_company_ownership", "assets",
                    ["company_id", "ownership_status"], unique=False)


def downgrade() -> None:
    from app.models import Base

    if _is_postgres():
        op.execute("DROP TRIGGER IF EXISTS audit_logs_no_delete ON audit_logs")
        op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs")
        op.execute("DROP FUNCTION IF EXISTS defenix_audit_append_only()")
        for table in TENANT_TABLES:
            op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    Base.metadata.drop_all(bind=op.get_bind())
