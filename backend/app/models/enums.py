"""Enumerazioni del dominio Defenix Exposure Rating."""
from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - comodita' di logging
        return self.value


class ScanProfileType(StrEnum):
    PUBLIC_PASSIVE = "public_passive"
    VERIFIED_STANDARD = "verified_standard"
    VERIFIED_EXTENDED = "verified_extended"


class ScanStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    NORMALIZING = "normalizing"
    SCORING = "scoring"
    AWAITING_REVIEW = "awaiting_review"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class OwnershipStatus(StrEnum):
    """Classificazione della proprieta' di un asset. Solo VERIFIED_OWNED e
    (con moltiplicatore ridotto) LIKELY_OWNED influenzano il rating."""
    VERIFIED_OWNED = "verified_owned"
    LIKELY_OWNED = "likely_owned"
    UNVERIFIED = "unverified"
    THIRD_PARTY = "third_party"
    EXCLUDED = "excluded"


OWNERSHIP_RANK: dict[str, int] = {
    OwnershipStatus.EXCLUDED.value: 0,
    OwnershipStatus.THIRD_PARTY.value: 1,
    OwnershipStatus.UNVERIFIED.value: 2,
    OwnershipStatus.LIKELY_OWNED.value: 3,
    OwnershipStatus.VERIFIED_OWNED.value: 4,
}


class ConfidenceClass(StrEnum):
    """Classificazione dell'evidenza (sezione 11 della specifica)."""
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INFERRED = "inferred"
    INFORMATIONAL = "informational"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


CONFIDENCE_RANK: dict[str, int] = {
    ConfidenceClass.RESOLVED.value: 0,
    ConfidenceClass.ACCEPTED_RISK.value: 0,
    ConfidenceClass.FALSE_POSITIVE.value: 0,
    ConfidenceClass.INFORMATIONAL.value: 1,
    ConfidenceClass.INFERRED.value: 2,
    ConfidenceClass.PROBABLE.value: 3,
    ConfidenceClass.CONFIRMED.value: 4,
}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


class ScoreCategoryKey(StrEnum):
    ATTACK_SURFACE = "attack_surface"
    TECHNICAL_VULNERABILITIES = "technical_vulnerabilities"
    WEB_SECURITY = "web_security"
    EMAIL_DNS_SECURITY = "email_dns_security"
    DARKWEB_BREACH = "darkweb_breach"


class FindingWorkflowState(StrEnum):
    """Workflow di sezione 17."""
    DETECTED = "detected"
    NORMALIZED = "normalized"
    CORRELATED = "correlated"
    SCORED = "scored"
    ANALYST_REVIEW = "analyst_review"
    APPROVED = "approved"
    REPORTED = "reported"
    RESOLVED = "resolved"


class AnalystValidation(StrEnum):
    NOT_REVIEWED = "not_reviewed"
    VALIDATED = "validated"
    REJECTED_FALSE_POSITIVE = "rejected_false_positive"
    ACCEPTED_RISK = "accepted_risk"
    EXCLUDED_FROM_RATING = "excluded_from_rating"
    RETEST_REQUESTED = "retest_requested"


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    NETWORK_RANGE = "network_range"
    WEB_SERVICE = "web_service"
    MAIL_SERVICE = "mail_service"
    NETWORK_SERVICE = "network_service"
    ASN = "asn"
    EMAIL_ADDRESS = "email_address"
    BRAND = "brand"
    CERTIFICATE = "certificate"


class AssetRelationshipType(StrEnum):
    RESOLVES_TO = "resolves_to"
    CNAME_TO = "cname_to"
    SUBDOMAIN_OF = "subdomain_of"
    MX_OF = "mx_of"
    HOSTED_ON = "hosted_on"
    ANNOUNCED_BY = "announced_by"
    SIMILAR_TO = "similar_to"
    CERTIFICATE_FOR = "certificate_for"
    SERVICE_ON = "service_on"


class VerificationMethod(StrEnum):
    DNS_TXT = "dns_txt"
    HTTP_FILE = "http_file"
    ADMIN_EMAIL = "admin_email"
    MANUAL_APPROVAL = "manual_approval"
    SIGNED_DOCUMENT = "signed_document"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuthorizationStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ScopeEntryType(StrEnum):
    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    URL = "url"
    EMAIL_DOMAIN = "email_domain"
    # Indirizzo singolo da verificare sulle fonti di violazione. Non allarga
    # il perimetro degli host: `_host_matches` ignora i tipi che non conosce.
    EMAIL_ADDRESS = "email_address"


class ScopeAction(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class RoleName(StrEnum):
    PLATFORM_ADMIN = "platform_administrator"
    TENANT_ADMIN = "tenant_administrator"
    SECURITY_ANALYST = "security_analyst"
    REVIEWER = "reviewer"
    SALES = "sales_account_manager"
    CUSTOMER_VIEWER = "customer_viewer"
    READ_ONLY_AUDITOR = "read_only_auditor"


class ReportType(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMBINED = "combined"


class ReportFormat(StrEnum):
    PDF = "pdf"
    DOCX = "docx"
    JSON = "json"
    CSV = "csv"
    HTML = "html"


class ReportStatus(StrEnum):
    DRAFT = "draft"
    GENERATING = "generating"
    READY = "ready"
    APPROVED = "approved"
    FAILED = "failed"


class ConnectorStatus(StrEnum):
    DISABLED = "disabled"
    CONFIGURED = "configured"
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class AuditAction(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    READ_SENSITIVE = "read_sensitive"
    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    SCAN_BLOCKED = "scan_blocked"
    FINDING_REVIEW = "finding_review"
    REPORT_GENERATE = "report_generate"
    REPORT_APPROVE = "report_approve"
    AUTHORIZATION_GRANT = "authorization_grant"
    AUTHORIZATION_REVOKE = "authorization_revoke"
    VERIFICATION_ATTEMPT = "verification_attempt"
    SCOPE_VIOLATION = "scope_violation"
