"""CLI di amministrazione Defenix.

Uso:
    python -m app.cli init-db          crea lo schema (equivalente a `alembic upgrade head`)
    python -m app.cli seed             crea tenant, ruoli, utenti demo e azienda di esempio
    python -m app.cli demo-scan        esegue una scansione dimostrativa su dati sintetici
    python -m app.cli show-credentials ristampa le credenziali demo generate
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from app.core.config import settings
from app.core.db import engine, session_scope
from app.core.logging import configure_logging, get_logger
from app.core.rbac import ROLE_PERMISSIONS
from app.core.security import generate_secure_password, hash_password
from app.models import Base
from app.models.enums import (
    AuthorizationStatus,
    ConnectorStatus,
    RoleName,
    ScanProfileType,
    ScanStatus,
    VerificationMethod,
    VerificationStatus,
)
from app.models.organization import Company, Connector, RetentionPolicy, Role, Tenant, User
from app.models.scanning import Scan, ScanProfile
from app.models.scope import Authorization, Brand, Domain, IPAddress, NetworkRange, Scope

configure_logging()
logger = get_logger(__name__)

# Percorso configurabile: nel container l'immagine gira con filesystem in sola
# lettura, quindi il file va su un volume dedicato (DEMO_CREDENTIALS_PATH).
CREDENTIALS_FILE = Path(os.environ.get("DEMO_CREDENTIALS_PATH", "./.demo-credentials.json"))

DEMO_TENANT = {"name": "AD Consulting - Defenix", "slug": "defenix"}
DEMO_COMPANIES = [
    {"legal_name": "ACME Demo S.p.A.", "slug": "acme-demo", "domain": "acme-demo.it",
     "vat_number": "IT01234567890", "sector": "Manifatturiero", "severity_bias": 0.45,
     "verified": True},
    {"legal_name": "Brescia Logistica S.r.l.", "slug": "brescia-logistica",
     "domain": "brescia-logistica.example", "vat_number": "IT09876543210",
     "sector": "Trasporti e logistica", "severity_bias": 0.75, "verified": True},
    {"legal_name": "Studio Tecnico Rossi", "slug": "studio-rossi",
     "domain": "studio-rossi.example", "vat_number": "IT05555555550",
     "sector": "Servizi professionali", "severity_bias": 0.20, "verified": False},
]

DEMO_USERS = [
    ("admin@defenix.example", "Amministratore Piattaforma", RoleName.PLATFORM_ADMIN),
    ("tenant.admin@defenix.example", "Amministratore Tenant", RoleName.TENANT_ADMIN),
    ("analyst@defenix.example", "Security Analyst", RoleName.SECURITY_ANALYST),
    ("reviewer@defenix.example", "Reviewer", RoleName.REVIEWER),
    ("sales@defenix.example", "Account Manager", RoleName.SALES),
    ("cliente@defenix.example", "Referente Cliente", RoleName.CUSTOMER_VIEWER),
    ("auditor@defenix.example", "Auditor Read-Only", RoleName.READ_ONLY_AUDITOR),
]

CONNECTORS = [
    ("dns", "DNS pubblico", True, False, ConnectorStatus.AVAILABLE, None),
    ("rdap", "RDAP", True, False, ConnectorStatus.AVAILABLE, None),
    ("certificate_transparency", "Certificate Transparency (crt.sh)", True, False,
     ConnectorStatus.AVAILABLE, None),
    ("subfinder", "Subfinder", True, False, ConnectorStatus.CONFIGURED, "MIT"),
    ("spiderfoot", "SpiderFoot", True, False, ConnectorStatus.DISABLED,
     "MIT - alcune fonti richiedono API key a pagamento"),
    ("checkdmarc", "checkdmarc", True, False, ConnectorStatus.AVAILABLE, "Apache-2.0"),
    ("httpx", "HTTPX", True, False, ConnectorStatus.CONFIGURED, "MIT"),
    ("testssl", "testssl.sh", True, False, ConnectorStatus.CONFIGURED,
     "GPL-2.0 - invocato come processo esterno, non linkato"),
    ("ransomware_live", "Ransomware.live", True, False, ConnectorStatus.AVAILABLE,
     "AGPL-3.0 (progetto) - usata l'API pubblica"),
    ("hibp", "Have I Been Pwned", False, True, ConnectorStatus.DISABLED,
     "Sorgente commerciale: richiede subscription a pagamento"),
    ("kev", "CISA Known Exploited Vulnerabilities", True, False, ConnectorStatus.AVAILABLE,
     "Public domain (US Government)"),
    ("epss", "FIRST EPSS", True, False, ConnectorStatus.AVAILABLE,
     "Uso gratuito - verificare i termini FIRST"),
]


def init_db() -> None:
    """Crea lo schema. In produzione usare `alembic upgrade head`."""
    Base.metadata.create_all(bind=engine)
    print(f"Schema creato su {settings.database_url.split('@')[-1]}")


def _ensure_roles(db) -> dict[str, Role]:  # noqa: ANN001
    roles: dict[str, Role] = {}
    for role_name in RoleName:
        row = db.execute(select(Role).where(Role.name == role_name.value)).scalar_one_or_none()
        if row is None:
            row = Role(name=role_name.value,
                       description=f"Ruolo {role_name.value}",
                       permissions_json=sorted(ROLE_PERMISSIONS.get(role_name.value, set())))
            db.add(row)
            db.flush()
        roles[role_name.value] = row
    return roles


def _ensure_scan_profiles(db) -> None:  # noqa: ANN001
    from app.core.config import load_yaml_config

    profiles = load_yaml_config("tool_profiles").get("profiles", {})
    for key, definition in profiles.items():
        row = db.execute(
            select(ScanProfile).where(ScanProfile.key == key)).scalar_one_or_none()
        if row is None:
            row = ScanProfile(key=key)
            db.add(row)
        row.label_it = definition.get("label_it", key)
        row.label_en = definition.get("label_en", key)
        row.requires_verification = bool(definition.get("requires_verification", True))
        row.requires_authorization = bool(definition.get("requires_authorization", True))
        row.requires_explicit_scope_whitelist = bool(
            definition.get("requires_explicit_scope_whitelist", False))
        row.allowed_tools_json = definition.get("tools", [])
        row.forbidden_actions_json = definition.get("forbidden_actions", [])
        row.description_it = definition.get("description_it")
    db.flush()


def seed() -> dict:
    """Crea i dati dimostrativi. Le password sono generate casualmente."""
    from app.services.persistence import sync_remediation_catalog

    created: dict[str, object] = {"users": [], "companies": []}
    with session_scope() as db:
        _ensure_scan_profiles(db)
        sync_remediation_catalog(db)
        roles = _ensure_roles(db)

        tenant = db.execute(
            select(Tenant).where(Tenant.slug == DEMO_TENANT["slug"])).scalar_one_or_none()
        if tenant is None:
            tenant = Tenant(**DEMO_TENANT, contact_email="security@defenix.example")
            db.add(tenant)
            db.flush()
        created["tenant"] = {"id": str(tenant.id), "slug": tenant.slug, "name": tenant.name}

        for email, full_name, role in DEMO_USERS:
            existing = db.execute(
                select(User).where(User.tenant_id == tenant.id,
                                   User.email == email)).scalar_one_or_none()
            if existing is not None:
                continue
            password = generate_secure_password()
            user = User(tenant_id=tenant.id, email=email, full_name=full_name,
                        hashed_password=hash_password(password), is_active=True)
            user.roles.append(roles[role.value])
            db.add(user)
            created["users"].append({"email": email, "password": password,
                                     "role": role.value, "full_name": full_name})
        db.flush()

        for key, name, open_source, commercial, connector_status, license_note in CONNECTORS:
            existing = db.execute(
                select(Connector).where(Connector.tenant_id == tenant.id,
                                        Connector.key == key)).scalar_one_or_none()
            if existing is None:
                db.add(Connector(tenant_id=tenant.id, key=key, display_name=name,
                                 status=connector_status.value, is_open_source=open_source,
                                 is_commercial=commercial, requires_api_key=commercial,
                                 license_note=license_note))

        for category, days in (("evidence", 730), ("raw_output", 180), ("report", 1825),
                               ("audit", 3650)):
            existing = db.execute(
                select(RetentionPolicy).where(
                    RetentionPolicy.tenant_id == tenant.id,
                    RetentionPolicy.data_category == category)).scalar_one_or_none()
            if existing is None:
                db.add(RetentionPolicy(tenant_id=tenant.id, data_category=category,
                                       retention_days=days, hard_delete=True,
                                       legal_basis="Interesse legittimo - sicurezza informatica"))
        db.flush()

        now = datetime.now(UTC)
        for spec in DEMO_COMPANIES:
            company = db.execute(
                select(Company).where(Company.tenant_id == tenant.id,
                                      Company.slug == spec["slug"])).scalar_one_or_none()
            if company is None:
                company = Company(
                    tenant_id=tenant.id, legal_name=spec["legal_name"], slug=spec["slug"],
                    vat_number=spec["vat_number"], country="IT", sector=spec["sector"],
                    size_band="50-249", next_scan_due_at=now + timedelta(days=90))
                db.add(company)
                db.flush()

            domain = db.execute(
                select(Domain).where(Domain.company_id == company.id,
                                     Domain.name == spec["domain"])).scalar_one_or_none()
            if domain is None:
                domain = Domain(tenant_id=tenant.id, company_id=company.id, name=spec["domain"],
                                is_primary=True)
                db.add(domain)
                db.flush()
            if spec["verified"]:
                domain.verification_status = VerificationStatus.VERIFIED.value
                domain.verification_method = VerificationMethod.MANUAL_APPROVAL.value
                domain.verified_at = now
                domain.dnssec_enabled = False

            db.add(Brand(tenant_id=tenant.id, company_id=company.id,
                         name=spec["legal_name"].split()[0],
                         keywords_json=[spec["slug"]], monitor_lookalikes=True))

            if spec["verified"]:
                # Autorizzazione esplicita: senza di questa i profili verificati
                # non partono (gate di sezione 4).
                authorization = db.execute(
                    select(Authorization).where(
                        Authorization.company_id == company.id)).scalar_one_or_none()
                if authorization is None:
                    authorization = Authorization(
                        tenant_id=tenant.id, company_id=company.id,
                        status=AuthorizationStatus.ACTIVE.value,
                        granting_subject_name="Mario Bianchi",
                        granting_subject_role="IT Manager",
                        granting_subject_email=f"it@{spec['domain']}",
                        granted_at=now, valid_from=now - timedelta(days=1),
                        expires_at=now + timedelta(days=180),
                        allowed_profiles_json=[ScanProfileType.PUBLIC_PASSIVE.value,
                                               ScanProfileType.VERIFIED_STANDARD.value,
                                               ScanProfileType.VERIFIED_EXTENDED.value],
                        document_reference="AUT-2026-001 (documento dimostrativo)",
                        notes="Autorizzazione dimostrativa generata dal seed")
                    db.add(authorization)
                    db.flush()

                    for entry_type, value in (("wildcard_domain", f"*.{spec['domain']}"),
                                              ("domain", spec["domain"]),
                                              ("cidr", "203.0.113.0/24")):
                        db.add(Scope(tenant_id=tenant.id, company_id=company.id,
                                     authorization_id=authorization.id,
                                     entry_type=entry_type, value=value, action="include"))
                    db.add(Scope(tenant_id=tenant.id, company_id=company.id,
                                 authorization_id=authorization.id, entry_type="domain",
                                 value=f"legacy.{spec['domain']}", action="exclude",
                                 note="ambiente dismesso, escluso su richiesta del cliente"))

                    for index in range(2):
                        db.add(IPAddress(tenant_id=tenant.id, company_id=company.id,
                                         address=f"203.0.113.{10 + index}", version=4,
                                         ownership_status="verified_owned",
                                         authorization_id=authorization.id))
                    db.add(NetworkRange(tenant_id=tenant.id, company_id=company.id,
                                        cidr="203.0.113.0/24",
                                        description="Rete pubblica dimostrativa (RFC 5737)",
                                        ownership_status="verified_owned",
                                        authorization_id=authorization.id))

            created["companies"].append({
                "id": str(company.id), "name": company.legal_name, "slug": company.slug,
                "domain": spec["domain"], "verified": spec["verified"],
                "severity_bias": spec["severity_bias"]})

    return created


def salva_credenziali(created: dict) -> Path | None:
    """Salva le credenziali su file, se possibile.

    E' una comodita', non un passaggio obbligatorio: le password sono gia' state
    stampate su stdout, che resta il canale autorevole. Se la destinazione non e'
    scrivibile (filesystem in sola lettura del container, permessi, disco pieno)
    si avvisa e si prosegue: far fallire qui il comando distruggerebbe l'unica
    copia in chiaro di credenziali gia' scritte nel database.
    """
    if not created.get("users"):
        return None
    try:
        CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
        CREDENTIALS_FILE.write_text(json.dumps(created, indent=2), encoding="utf-8")
        CREDENTIALS_FILE.chmod(0o600)
    except OSError as errore:
        print(f"\nATTENZIONE: impossibile salvare {CREDENTIALS_FILE}: {errore}",
              file=sys.stderr)
        print("Le credenziali sono solo qui sopra: copiarle adesso, nel database "
              "sono memorizzate unicamente come hash.", file=sys.stderr)
        return None
    return CREDENTIALS_FILE


def demo_scan(company_slug: str | None = None, profile: str = "verified_standard") -> dict:
    """Esegue una scansione dimostrativa completa su dati sintetici."""
    from app.services.persistence import persist_outcome
    from app.workers.pipeline import ScanPipeline, ScanRequest

    if not settings.scan_mock_mode:
        print("ATTENZIONE: SCAN_MOCK_MODE e' disattivato. La demo richiede dati sintetici.",
              file=sys.stderr)
        return {"status": "aborted", "reason": "mock mode disattivato"}

    results: list[dict] = []
    with session_scope() as db:
        query = select(Company)
        if company_slug:
            query = query.where(Company.slug == company_slug)
        companies = db.execute(query).scalars().all()
        if not companies:
            print("Nessuna azienda trovata: eseguire prima `python -m app.cli seed`",
                  file=sys.stderr)
            return {"status": "no_companies"}
        targets = [(c.id, c.tenant_id, c.legal_name, c.slug) for c in companies]

    bias_by_slug = {spec["slug"]: spec["severity_bias"] for spec in DEMO_COMPANIES}

    for company_id, tenant_id, legal_name, slug in targets:
        with session_scope() as db:
            domains = db.execute(
                select(Domain).where(Domain.company_id == company_id)).scalars().all()
            verified = [d.name for d in domains
                        if d.verification_status == VerificationStatus.VERIFIED.value]
            ips = db.execute(
                select(IPAddress).where(IPAddress.company_id == company_id)).scalars().all()
            networks = db.execute(
                select(NetworkRange).where(
                    NetworkRange.company_id == company_id)).scalars().all()
            scopes = db.execute(
                select(Scope).where(Scope.company_id == company_id)).scalars().all()

            effective_profile = profile if verified else ScanProfileType.PUBLIC_PASSIVE.value
            previous = db.execute(
                select(Scan).where(Scan.company_id == company_id,
                                   Scan.status.in_([ScanStatus.COMPLETED.value,
                                                    ScanStatus.PARTIAL.value]))
                .order_by(Scan.finished_at.desc()).limit(1)).scalar_one_or_none()

            scan = Scan(
                tenant_id=tenant_id, company_id=company_id, profile_key=effective_profile,
                status=ScanStatus.RUNNING.value, mock_mode=True,
                started_at=datetime.now(UTC),
                previous_scan_id=previous.id if previous else None,
                scope_snapshot_json={
                    "domains": [d.name for d in domains], "verified_domains": verified,
                    "ip_addresses": [i.address for i in ips],
                    "authorized_ips": [i.address for i in ips],
                    "network_ranges": [n.cidr for n in networks],
                    "excluded": [s.value for s in scopes if s.action == "exclude"]})
            db.add(scan)
            db.flush()
            scan_id, snapshot = scan.id, dict(scan.scope_snapshot_json)

        request = ScanRequest(
            scan_id=str(scan_id), tenant_id=str(tenant_id), company_id=str(company_id),
            company_name=legal_name, profile=effective_profile,
            domains=snapshot["domains"], verified_domains=snapshot["verified_domains"],
            ip_addresses=snapshot["ip_addresses"], authorized_ips=snapshot["authorized_ips"],
            network_ranges=snapshot["network_ranges"], excluded_values=snapshot["excluded"],
            mock_mode=True,
            connector_config={"hibp": {"mock_enabled": True},
                              "synthetic": {"severity_bias": bias_by_slug.get(slug, 0.5)}})
        outcome = ScanPipeline(request).run()

        with session_scope() as db:
            score = persist_outcome(db, db.get(Scan, scan_id), outcome)
            results.append({
                "company": legal_name, "profile": effective_profile,
                "scan_id": str(scan_id), "score": score.overall_score,
                "class": score.rating_class, "confidence": round(outcome.confidence.value, 1),
                "provisional": score.is_provisional,
                "findings": len(outcome.normalization.findings),
                "assets": len(outcome.normalization.assets)})

    return {"status": "ok", "scans": results}


def run_queued(scan_id: str | None = None) -> dict:
    """Esegue subito le scansioni in coda, senza passare da Celery.

    Serve quando il worker non e' disponibile: la scansione resterebbe
    accodata a tempo indeterminato e non c'e' modo di sbloccarla
    dall'interfaccia. Riusa esattamente la stessa pipeline del worker, quindi
    il risultato e' identico.

    Consentito solo in modalita' simulata: con `SCAN_MOCK_MODE=false` i tool
    verrebbero eseguiti nel processo che lancia il comando, mentre devono
    girare esclusivamente nei worker isolati. In quel caso il comando si
    rifiuta di procedere e indica di avviare il servizio worker.
    """
    from app.models.enums import ScanStatus
    from app.services.persistence import persist_outcome
    from app.workers.pipeline import ScanPipeline, ScanRequest

    if not settings.scan_mock_mode:
        raise SystemExit(
            "Rifiutato: con SCAN_MOCK_MODE=false gli strumenti devono girare nei "
            "worker isolati, non qui.\n"
            "Avviare il servizio worker:  docker compose up -d worker")

    eseguibili = {ScanStatus.QUEUED.value, ScanStatus.PENDING.value}
    esiti: list[dict] = []

    with session_scope() as db:
        if scan_id:
            # Indicata esplicitamente: si esegue qualunque sia lo stato. Serve a
            # riprendere una scansione rimasta in `running` dopo un'interruzione,
            # che altrimenti nessuno raccoglierebbe piu'.
            query = select(Scan).where(Scan.id == uuid.UUID(scan_id))
        else:
            query = select(Scan).where(Scan.status.in_(eseguibili))
        da_eseguire = [str(s.id) for s in db.execute(query).scalars().all()]

    if not da_eseguire:
        print("Nessuna scansione in coda.")
        return {"status": "ok", "scans": []}

    for identificativo in da_eseguire:
        with session_scope() as db:
            scan = db.get(Scan, uuid.UUID(identificativo))
            snapshot = scan.scope_snapshot_json or {}
            richiesta = ScanRequest(
                scan_id=str(scan.id), tenant_id=str(scan.tenant_id),
                company_id=str(scan.company_id), company_name=scan.company.legal_name,
                profile=scan.profile_key,
                domains=list(snapshot.get("domains", [])),
                verified_domains=list(snapshot.get("verified_domains", [])),
                ip_addresses=list(snapshot.get("ip_addresses", [])),
                authorized_ips=list(snapshot.get("authorized_ips", [])),
                network_ranges=list(snapshot.get("network_ranges", [])),
                excluded_values=list(snapshot.get("excluded", [])),
                dkim_selectors=list(snapshot.get("dkim_selectors", [])),
                mock_mode=True)
            scan.status = ScanStatus.RUNNING.value
            nome = scan.company.legal_name

        print(f"Eseguo {identificativo[:8]} ({nome})…")
        try:
            esito = ScanPipeline(richiesta).run()
        except Exception as errore:  # noqa: BLE001
            with session_scope() as db:
                scan = db.get(Scan, uuid.UUID(identificativo))
                scan.status = ScanStatus.FAILED.value
                scan.error_message = f"{type(errore).__name__}: {errore}"[:2000]
                scan.finished_at = datetime.now(UTC)
            print(f"  fallita: {errore}", file=sys.stderr)
            esiti.append({"scan_id": identificativo, "status": "failed", "error": str(errore)})
            continue

        with session_scope() as db:
            scan = db.get(Scan, uuid.UUID(identificativo))
            punteggio = persist_outcome(db, scan, esito)
            esiti.append({
                "scan_id": identificativo, "company": nome,
                "status": scan.status,
                "score": round(float(punteggio.overall_score), 2) if punteggio else None,
                "class": punteggio.rating_class if punteggio else None,
                "findings": len(esito.normalization.findings)})
        print(f"  completata: rating {esiti[-1]['score']} classe {esiti[-1]['class']} "
              f"({esiti[-1]['findings']} rilievi)")

    return {"status": "ok", "scans": esiti}


def show_credentials() -> None:
    if not CREDENTIALS_FILE.is_file():
        print("Nessun file di credenziali: eseguire prima `python -m app.cli seed`",
              file=sys.stderr)
        return
    print(CREDENTIALS_FILE.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(prog="defenix", description="CLI Defenix Exposure Rating")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="crea lo schema del database")
    subparsers.add_parser("seed", help="crea tenant, ruoli, utenti e aziende dimostrative")
    scan_parser = subparsers.add_parser("demo-scan", help="esegue una scansione dimostrativa")
    scan_parser.add_argument("--company", default=None, help="slug dell'azienda")
    scan_parser.add_argument("--profile", default="verified_standard",
                             choices=[p.value for p in ScanProfileType])
    subparsers.add_parser("show-credentials", help="ristampa le credenziali demo generate")
    run_parser = subparsers.add_parser(
        "run-queued", help="esegue subito le scansioni in coda, senza Celery")
    run_parser.add_argument("--scan-id", default=None, help="una sola scansione")

    args = parser.parse_args()
    if args.command == "init-db":
        init_db()
    elif args.command == "seed":
        result = seed()
        # Stampa prima di qualsiasi scrittura su disco: e' l'unica occasione in
        # cui le password compaiono in chiaro.
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if result.get("users"):
            percorso = salva_credenziali(result)
            if percorso is not None:
                print(f"\nCredenziali salvate in {percorso.resolve()} (permessi 0600).")
            print("Cambiare le password al primo accesso e non usarle in produzione.")
    elif args.command == "demo-scan":
        print(json.dumps(demo_scan(args.company, args.profile), indent=2, ensure_ascii=False))
    elif args.command == "run-queued":
        print(json.dumps(run_queued(args.scan_id), indent=2, ensure_ascii=False))
    elif args.command == "show-credentials":
        show_credentials()


if __name__ == "__main__":
    main()
