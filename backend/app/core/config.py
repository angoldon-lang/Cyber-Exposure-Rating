"""Configurazione applicativa centralizzata (12-factor, via variabili d'ambiente)."""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG_DIR = REPO_ROOT / "config"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Applicazione ---
    app_name: str = "Defenix Exposure Rating"
    app_version: str = "0.1.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    api_prefix: str = "/api/v1"
    default_language: Literal["it", "en"] = "it"

    # --- Database ---
    database_url: str = "postgresql+psycopg://defenix:defenix@postgres:5432/defenix"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False
    enable_row_level_security: bool = True

    # --- Redis / Celery ---
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"
    celery_task_time_limit: int = 3600
    celery_task_soft_time_limit: int = 3300

    # --- Autenticazione ---
    # `local` = issuer JWT interno (solo sviluppo/installazioni minime)
    # `oidc`  = Keycloak o altro identity provider OIDC (raccomandato)
    auth_mode: Literal["local", "oidc"] = "local"
    jwt_secret_key: str = Field(default="CHANGE-ME-INSECURE-DEV-ONLY", min_length=8)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_client_id: str | None = None
    oidc_roles_claim: str = "realm_access.roles"

    # --- Sicurezza ---
    # `NoDecode`: senza questa annotazione pydantic-settings tenta di decodificare
    # il valore letto da `.env` come JSON e fallisce prima del validatore, che e'
    # quello che accetta la forma "origine1,origine2" documentata in .env.example.
    cors_origins: Annotated[list[str], NoDecode] = [
        "http://localhost:5173", "http://localhost:8080"]
    rate_limit_per_minute: int = 120
    secure_cookies: bool = True
    evidence_encryption_key: str | None = None  # Fernet key per evidenze raw

    # --- Storage evidenze ---
    evidence_storage_path: Path = Path("/var/lib/defenix/evidence")
    report_storage_path: Path = Path("/var/lib/defenix/reports")
    max_evidence_bytes: int = 52_428_800

    # --- Scansioni ---
    config_dir: Path = DEFAULT_CONFIG_DIR
    scan_mock_mode: bool = True  # In dev: nessun contatto con Internet reale
    scan_max_concurrent_tools: int = 4
    scan_max_targets: int = 500
    scan_default_timeout: int = 600
    allow_private_ip_scanning: bool = False

    # --- Connettori opzionali ---
    hibp_api_key: str | None = None
    spiderfoot_url: str | None = None
    ransomware_live_url: str = "https://api.ransomware.live"
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss_api_url: str = "https://api.first.org/data/v1/epss"

    # --- Report ---
    report_brand_name: str = "Defenix"
    report_brand_owner: str = "AD Consulting"
    report_logo_path: Path | None = None

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


# --------------------------------------------------------------------------
# Caricamento dei file YAML di configurazione (scoring, profili, remediation).
# I file sono versionati nel repository e trattati come sola lettura.
# --------------------------------------------------------------------------
@functools.lru_cache(maxsize=32)
def load_yaml_config(name: str) -> dict[str, Any]:
    """Carica `config/<name>.yaml` con validazione del percorso (no path traversal)."""
    if not name.replace("_", "").isalnum():
        raise ValueError(f"Nome configurazione non valido: {name!r}")
    path = (settings.config_dir / f"{name}.yaml").resolve()
    config_dir = settings.config_dir.resolve()
    if not str(path).startswith(str(config_dir)):
        raise ValueError(f"Percorso configurazione fuori da config_dir: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"Configurazione mancante: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"La configurazione {name} deve essere un mapping YAML")
    return data


def reset_config_cache() -> None:
    """Usato dai test per ricaricare configurazioni modificate."""
    load_yaml_config.cache_clear()
