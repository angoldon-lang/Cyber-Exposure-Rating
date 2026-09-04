"""Autenticazione: modalita' locale (JWT interno) e OIDC (Keycloak)."""
from __future__ import annotations

import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import Any

import base64
import bcrypt
import hashlib

import httpx
from jose import JWTError, jwt

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# bcrypt tronca silenziosamente oltre 72 byte. Si pre-calcola un digest
# SHA-256 in base64 (44 byte) cosi' l'intera password contribuisce sempre
# all'hash, senza troncamenti impliciti.
BCRYPT_ROUNDS = 12

_jwks_cache: dict[str, Any] = {"keys": None, "fetched_at": None}
_JWKS_TTL_SECONDS = 3600


def _prepare(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prepare(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(plain: str, hashed: str | None) -> bool:
    """Confronto a tempo costante; un hash assente o malformato non solleva."""
    if not hashed:
        # Confronto fittizio: il tempo di risposta non rivela se l'utente esiste.
        bcrypt.checkpw(_prepare(plain), bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=4)))
        return False
    try:
        return bcrypt.checkpw(_prepare(plain), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def generate_secure_password(length: int = 20) -> str:
    """Password demo generate casualmente: nessuna credenziale statica nel repo."""
    alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in candidate) and any(c.isupper() for c in candidate)
                and any(c.isdigit() for c in candidate)
                and any(c in "!@#%^*-_=+" for c in candidate)):
            return candidate


def generate_verification_token(prefix: str = "defenix-verify") -> str:
    return f"{prefix}={secrets.token_urlsafe(32)}"


def create_access_token(subject: str, claims: dict[str, Any], expires_minutes: int | None = None) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=expires_minutes or settings.access_token_expire_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(UTC),
        "iss": "defenix-exposure-rating",
        **claims,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_local_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm],
                      options={"verify_aud": False})


def _fetch_jwks() -> dict[str, Any]:
    now = datetime.now(UTC)
    cached_at = _jwks_cache.get("fetched_at")
    if _jwks_cache.get("keys") and cached_at and (now - cached_at).total_seconds() < _JWKS_TTL_SECONDS:
        return _jwks_cache["keys"]
    if not settings.oidc_jwks_url:
        raise RuntimeError("oidc_jwks_url non configurato")
    response = httpx.get(settings.oidc_jwks_url, timeout=10.0)
    response.raise_for_status()
    _jwks_cache["keys"] = response.json()
    _jwks_cache["fetched_at"] = now
    return _jwks_cache["keys"]


def decode_oidc_token(token: str) -> dict[str, Any]:
    jwks = _fetch_jwks()
    header = jwt.get_unverified_header(token)
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise JWTError("Chiave JWKS non trovata per il kid indicato")
    return jwt.decode(
        token,
        key,
        algorithms=[key.get("alg", "RS256")],
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer,
        options={"verify_aud": settings.oidc_audience is not None},
    )


def decode_token(token: str) -> dict[str, Any]:
    if settings.auth_mode == "oidc":
        return decode_oidc_token(token)
    return decode_local_token(token)


def extract_roles(payload: dict[str, Any]) -> list[str]:
    """Estrae i ruoli dal claim configurato (supporta path annidati tipo
    `realm_access.roles` usato da Keycloak)."""
    if "roles" in payload and isinstance(payload["roles"], list):
        return [str(r) for r in payload["roles"]]
    node: Any = payload
    for part in settings.oidc_roles_claim.split("."):
        if not isinstance(node, dict) or part not in node:
            return []
        node = node[part]
    return [str(r) for r in node] if isinstance(node, list) else []
