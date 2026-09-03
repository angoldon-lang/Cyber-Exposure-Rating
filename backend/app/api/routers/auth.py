"""Autenticazione locale (sviluppo e installazioni minime) e profilo utente.

In produzione si usa `AUTH_MODE=oidc` con Keycloak: l'endpoint di login
locale viene disabilitato e i token sono emessi dall'identity provider.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.api.deps import CurrentUserDep, DbDep, RequestContextDep
from app.core.config import settings
from app.core.rbac import permissions_for_roles
from app.core.security import create_access_token, verify_password
from app.models.enums import AuditAction
from app.models.organization import User
from app.schemas.organization import LoginRequest, TokenResponse, UserProfile
from app.services.audit import record_audit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: DbDep,
          context: RequestContextDep) -> TokenResponse:
    if settings.auth_mode != "local":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "L'autenticazione locale e' disabilitata: usare l'identity provider OIDC configurato")

    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(payload.password, user.hashed_password):
        record_audit(db, action=AuditAction.LOGIN_FAILED.value,
                     tenant_id=user.tenant_id if user else None,
                     actor_email=payload.email, outcome="failure",
                     message="credenziali non valide", **context)
        db.commit()
        # Messaggio volutamente generico: non rivela se l'utente esiste.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenziali non valide")

    roles = user.role_names
    token = create_access_token(str(user.id), {
        "tenant_id": str(user.tenant_id), "email": user.email, "roles": roles})
    user.last_login_at = datetime.now(UTC)
    record_audit(db, action=AuditAction.LOGIN.value, tenant_id=user.tenant_id,
                 actor_user_id=user.id, actor_email=user.email, actor_roles=roles, **context)
    db.commit()

    return TokenResponse(
        access_token=token, expires_in=settings.access_token_expire_minutes * 60,
        profile=UserProfile(id=user.id, tenant_id=user.tenant_id, email=user.email,
                            full_name=user.full_name, roles=roles,
                            permissions=sorted(permissions_for_roles(roles))))


@router.get("/me", response_model=UserProfile)
def me(current: CurrentUserDep) -> UserProfile:
    return UserProfile(id=current.id, tenant_id=current.tenant_id, email=current.email,
                       full_name=current.user.full_name, roles=current.roles,
                       permissions=sorted(current.permissions))
