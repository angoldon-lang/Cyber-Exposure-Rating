"""Matrice dei permessi RBAC (sezione 5 e 19)."""
from __future__ import annotations

from app.models.enums import RoleName


class Permission:
    # Tenant e piattaforma
    PLATFORM_MANAGE = "platform:manage"
    TENANT_MANAGE = "tenant:manage"
    TENANT_READ = "tenant:read"
    # Aziende e perimetro
    COMPANY_READ = "company:read"
    COMPANY_WRITE = "company:write"
    DOMAIN_READ = "domain:read"
    DOMAIN_WRITE = "domain:write"
    DOMAIN_VERIFY = "domain:verify"
    AUTHORIZATION_READ = "authorization:read"
    AUTHORIZATION_WRITE = "authorization:write"
    # Scansioni
    SCAN_READ = "scan:read"
    SCAN_START_PASSIVE = "scan:start_passive"
    SCAN_START_STANDARD = "scan:start_standard"
    SCAN_START_EXTENDED = "scan:start_extended"
    SCAN_CANCEL = "scan:cancel"
    # Finding e revisione
    FINDING_READ = "finding:read"
    FINDING_REVIEW = "finding:review"
    FINDING_APPROVE = "finding:approve"
    # Evidenze raw e dati sensibili
    EVIDENCE_RAW_READ = "evidence:raw_read"
    PII_UNMASK = "pii:unmask"
    # Report
    REPORT_READ = "report:read"
    REPORT_GENERATE = "report:generate"
    REPORT_APPROVE = "report:approve"
    # Audit
    AUDIT_READ = "audit:read"
    # Connettori
    CONNECTOR_READ = "connector:read"
    CONNECTOR_WRITE = "connector:write"


_ANALYST_BASE = {
    Permission.TENANT_READ, Permission.COMPANY_READ, Permission.COMPANY_WRITE,
    Permission.DOMAIN_READ, Permission.DOMAIN_WRITE, Permission.DOMAIN_VERIFY,
    Permission.AUTHORIZATION_READ,
    Permission.SCAN_READ, Permission.SCAN_START_PASSIVE, Permission.SCAN_START_STANDARD,
    Permission.SCAN_CANCEL,
    Permission.FINDING_READ, Permission.FINDING_REVIEW,
    Permission.EVIDENCE_RAW_READ, Permission.PII_UNMASK,
    Permission.REPORT_READ, Permission.REPORT_GENERATE,
    Permission.CONNECTOR_READ,
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    RoleName.PLATFORM_ADMIN.value: {
        value for name, value in vars(Permission).items() if not name.startswith("_")
    },
    RoleName.TENANT_ADMIN.value: _ANALYST_BASE | {
        Permission.TENANT_MANAGE, Permission.AUTHORIZATION_WRITE,
        Permission.SCAN_START_EXTENDED, Permission.FINDING_APPROVE,
        Permission.REPORT_APPROVE, Permission.AUDIT_READ, Permission.CONNECTOR_WRITE,
    },
    RoleName.SECURITY_ANALYST.value: set(_ANALYST_BASE),
    RoleName.REVIEWER.value: {
        Permission.TENANT_READ, Permission.COMPANY_READ, Permission.DOMAIN_READ,
        Permission.AUTHORIZATION_READ, Permission.SCAN_READ,
        Permission.FINDING_READ, Permission.FINDING_REVIEW, Permission.FINDING_APPROVE,
        Permission.EVIDENCE_RAW_READ,
        Permission.REPORT_READ, Permission.REPORT_GENERATE, Permission.REPORT_APPROVE,
        Permission.AUDIT_READ,
    },
    RoleName.SALES.value: {
        Permission.TENANT_READ, Permission.COMPANY_READ, Permission.COMPANY_WRITE,
        Permission.DOMAIN_READ, Permission.DOMAIN_WRITE,
        Permission.SCAN_READ, Permission.SCAN_START_PASSIVE,
        Permission.FINDING_READ, Permission.REPORT_READ,
    },
    RoleName.CUSTOMER_VIEWER.value: {
        Permission.COMPANY_READ, Permission.DOMAIN_READ, Permission.SCAN_READ,
        Permission.FINDING_READ, Permission.REPORT_READ,
    },
    RoleName.READ_ONLY_AUDITOR.value: {
        Permission.TENANT_READ, Permission.COMPANY_READ, Permission.DOMAIN_READ,
        Permission.AUTHORIZATION_READ, Permission.SCAN_READ, Permission.FINDING_READ,
        Permission.REPORT_READ, Permission.AUDIT_READ, Permission.CONNECTOR_READ,
    },
}

# Profilo di scansione -> permesso necessario per avviarlo.
PROFILE_PERMISSION: dict[str, str] = {
    "public_passive": Permission.SCAN_START_PASSIVE,
    "verified_standard": Permission.SCAN_START_STANDARD,
    "verified_extended": Permission.SCAN_START_EXTENDED,
}


def permissions_for_roles(role_names: list[str]) -> set[str]:
    permissions: set[str] = set()
    for role in role_names:
        permissions |= ROLE_PERMISSIONS.get(role, set())
    return permissions


def has_permission(role_names: list[str], permission: str) -> bool:
    return permission in permissions_for_roles(role_names)
