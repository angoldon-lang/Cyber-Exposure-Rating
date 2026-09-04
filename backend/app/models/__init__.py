"""Registro dei modelli: importare da qui garantisce che tutte le tabelle
siano registrate su `Base.metadata` (necessario per Alembic e per i test)."""
from app.models.audit import AuditLog
from app.models.base import Base, GUID, utcnow
from app.models.organization import (
    TenantBranding,
    APIKeyReference,
    Company,
    Connector,
    RetentionPolicy,
    Role,
    Tenant,
    User,
    user_roles,
)
from app.models.reporting import Report, ReportVersion
from app.models.scanning import (
    Evidence,
    Finding,
    Remediation,
    Scan,
    ScanProfile,
    ToolRun,
    Vulnerability,
)
from app.models.scope import (
    Asset,
    AssetRelationship,
    Authorization,
    Brand,
    Domain,
    EmailDomain,
    IPAddress,
    NetworkRange,
    Scope,
)
from app.models.scoring import ConfidenceScore, Score, ScoreCategory

__all__ = [
    "APIKeyReference", "Asset", "AssetRelationship", "AuditLog", "Authorization", "Base",
    "Brand", "Company", "ConfidenceScore", "Connector", "Domain", "EmailDomain", "Evidence",
    "Finding", "GUID", "IPAddress", "NetworkRange", "Remediation", "Report", "ReportVersion",
    "RetentionPolicy", "Role", "Scan", "ScanProfile", "Scope", "Score", "ScoreCategory",
    "Tenant",
    "TenantBranding", "ToolRun", "User", "Vulnerability", "user_roles", "utcnow",
]
