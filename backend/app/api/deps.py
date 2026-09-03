"""Dipendenze FastAPI: autenticazione, RBAC e isolamento multi-tenant."""
from __future__ import annotations

import uuid
from collections.abc import Generator
from typing import Annotated, Any, Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db, set_tenant_context
from app.core.logging import get_logger
from app.core.rbac import Permission, permissions_for_roles
from app.core.security import decode_token, extract_roles
from app.models.organization import Company, Tenant, User

logger = get_logger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser:
    """Identita' della richiesta corrente, con permessi risolti."""

    def __init__(self, user: User, roles: list[str]) -> None:
        self.user = user
        self.roles = roles
        self.permissions = permissions_for_roles(roles)

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.user.tenant_id

    @property
    def email(self) -> str:
        return self.user.email

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    def company_allowed(self, company_id: uuid.UUID) -> bool:
        """I ruoli con perimetro ristretto vedono solo le aziende assegnate."""
        scope = self.user.company_scope_json or []
        return not scope or str(company_id) in {str(item) for item in scope}


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> CurrentUser:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Autenticazione richiesta",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = decode_token(credentials.credentials)
    except JWTError as exc:
        logger.warning("token_rejected", error=str(exc))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token non valido o scaduto",
                            headers={"WWW-Authenticate": "Bearer"}) from exc

    subject = str(payload.get("sub", ""))
    user: User | None = None
    if settings.auth_mode == "oidc":
        user = db.execute(select(User).where(User.external_subject == subject)).scalar_one_or_none()
        if user is None and payload.get("email"):
            user = db.execute(
                select(User).where(User.email == str(payload["email"]))).scalar_one_or_none()
    else:
        try:
            user = db.get(User, uuid.UUID(subject))
        except (ValueError, TypeError):
            user = None

    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Utente non riconosciuto o disattivato")

    roles = extract_roles(payload) if settings.auth_mode == "oidc" else user.role_names
    if not roles:
        roles = user.role_names

    # Row Level Security: il contesto tenant vale per l'intera transazione.
    set_tenant_context(db, str(user.tenant_id))
    request.state.user_id = str(user.id)
    request.state.tenant_id = str(user.tenant_id)
    return CurrentUser(user, roles)


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]
DbDep = Annotated[Session, Depends(get_db)]


def require_permission(permission: str) -> Callable[..., CurrentUser]:
    """Dependency factory: nega la richiesta se manca il permesso."""

    def dependency(current: CurrentUserDep) -> CurrentUser:
        if not current.has(permission):
            logger.warning("permission_denied", user=current.email,
                           permission=permission, roles=current.roles)
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"Permesso mancante: {permission}")
        return current

    return dependency


def get_tenant(current: CurrentUserDep, db: DbDep) -> Tenant:
    tenant = db.get(Tenant, current.tenant_id)
    if tenant is None or not tenant.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Tenant non attivo")
    return tenant


def get_company(company_id: uuid.UUID, current: CurrentUserDep, db: DbDep) -> Company:
    """Recupera un'azienda applicando SEMPRE il filtro sul tenant.

    Un id valido di un altro tenant produce 404, non 403: non si rivela
    l'esistenza di risorse appartenenti ad altri tenant.
    """
    company = db.execute(
        select(Company).where(Company.id == company_id, Company.tenant_id == current.tenant_id)
    ).scalar_one_or_none()
    if company is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Azienda non trovata")
    if not current.company_allowed(company.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Azienda non trovata")
    return company


CompanyDep = Annotated[Company, Depends(get_company)]


def tenant_scoped(db: Session, model: Any, current: CurrentUser):  # noqa: ANN201
    """Query di base con filtro tenant obbligatorio."""
    return select(model).where(model.tenant_id == current.tenant_id)


def request_context(request: Request) -> dict[str, str | None]:
    """Metadati della richiesta per l'audit log."""
    return {
        "actor_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }


RequestContextDep = Annotated[dict, Depends(request_context)]


def can_unmask_pii(current: CurrentUser) -> bool:
    return current.has(Permission.PII_UNMASK)


def db_session() -> Generator[Session, None, None]:
    yield from get_db()
