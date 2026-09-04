# ---------------------------------------------------------------------------
# Defenix Exposure Rating
# ---------------------------------------------------------------------------
.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE ?= docker compose
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip
export PYTHONPATH := backend:.

.PHONY: help
help: ## Mostra questo elenco
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --------------------------- sviluppo locale -------------------------------
.PHONY: venv
venv: ## Crea l'ambiente virtuale e installa le dipendenze
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements-dev.txt

.PHONY: install
install: venv ## Installa backend e frontend
	cd frontend && npm install

.PHONY: init-db
init-db: ## Crea lo schema del database
	$(PY) -m app.cli init-db

.PHONY: migrate
migrate: ## Applica le migrazioni Alembic
	cd backend && ../.venv/bin/alembic upgrade head

.PHONY: seed
seed: ## Crea tenant, ruoli, utenti e aziende dimostrative
	$(PY) -m app.cli seed

.PHONY: demo
demo: ## Esegue una scansione dimostrativa su dati sintetici
	$(PY) -m app.cli demo-scan

.PHONY: credentials
credentials: ## Ristampa le credenziali demo generate
	$(PY) -m app.cli show-credentials

.PHONY: api
api: ## Avvia l'API in locale con ricarica automatica
	.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

.PHONY: worker
worker: ## Avvia un worker Celery in locale
	.venv/bin/celery -A app.workers.celery_app.celery_app worker --loglevel=info -Q scans,maintenance

.PHONY: web
web: ## Avvia il frontend in sviluppo
	cd frontend && npm run dev

# ------------------------------- qualita' ----------------------------------
.PHONY: test
test: ## Esegue la suite di test
	.venv/bin/pytest -q

.PHONY: coverage
coverage: ## Test con report di copertura
	.venv/bin/pytest --cov=backend/app --cov=adapters --cov=reporting \
		--cov-report=term-missing --cov-report=html

.PHONY: lint
lint: ## Analisi statica di backend e frontend
	.venv/bin/ruff check backend adapters reporting tests
	cd frontend && npm run typecheck

.PHONY: format
format: ## Formattazione automatica
	.venv/bin/ruff format backend adapters reporting tests

.PHONY: check-config
check-config: ## Valida i file YAML di configurazione
	$(PY) -c "from app.services.scoring import ScoringEngine; \
		from app.services.confidence import ConfidenceEngine; \
		ScoringEngine(); ConfidenceEngine(); print('configurazione valida')"

.PHONY: sbom
sbom: ## Genera la SBOM del prodotto (CycloneDX)
	$(PIP) install --quiet cyclonedx-bom
	.venv/bin/cyclonedx-py environment .venv --output-format json --outfile sbom-backend.json
	cd frontend && npx --yes @cyclonedx/cyclonedx-npm --output-file ../sbom-frontend.json

# ------------------------------- container ---------------------------------
.PHONY: build
build: ## Costruisce le immagini container
	$(COMPOSE) build

.PHONY: up
up: ## Avvia lo stack completo
	$(COMPOSE) up -d
	@echo "Frontend: http://localhost:$${FRONTEND_PORT:-8080}"
	@echo "API docs: http://localhost:$${API_PORT:-8000}/api/v1/docs"

.PHONY: down
down: ## Ferma lo stack
	$(COMPOSE) down

.PHONY: logs
logs: ## Segue i log dello stack
	$(COMPOSE) logs -f --tail=100

.PHONY: compose-migrate
compose-migrate: ## Applica le migrazioni nel container API
	$(COMPOSE) exec api sh -lc 'cd /srv/backend && alembic upgrade head'

.PHONY: compose-seed
compose-seed: ## Crea i dati dimostrativi nel container API
	$(COMPOSE) exec api python -m app.cli seed

.PHONY: harden-db
harden-db: ## Revoca UPDATE/DELETE sull'audit log (dopo le migrazioni)
	$(COMPOSE) exec postgres psql -U $${POSTGRES_USER:-defenix} -d $${POSTGRES_DB:-defenix} \
		-c "REVOKE UPDATE, DELETE ON audit_logs FROM defenix_app;"

# -------------------------------- backup -----------------------------------
.PHONY: backup
backup: ## Backup di database e storage
	@mkdir -p backups
	$(COMPOSE) exec -T postgres pg_dump -U $${POSTGRES_USER:-defenix} \
		-d $${POSTGRES_DB:-defenix} --format=custom \
		> backups/defenix-$$(date +%Y%m%d-%H%M%S).dump
	docker run --rm -v defenix_evidence-data:/data:ro -v "$$PWD/backups":/backup \
		alpine tar czf /backup/evidence-$$(date +%Y%m%d-%H%M%S).tar.gz -C /data .
	@echo "Backup in ./backups (cifrarli prima di archiviarli fuori sede)."

.PHONY: restore
restore: ## Ripristina un dump (DUMP=backups/file.dump)
	@test -n "$(DUMP)" || (echo "Uso: make restore DUMP=backups/file.dump" && exit 1)
	$(COMPOSE) exec -T postgres pg_restore -U $${POSTGRES_USER:-defenix} \
		-d $${POSTGRES_DB:-defenix} --clean --if-exists < $(DUMP)

.PHONY: clean
clean: ## Rimuove artefatti locali
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage frontend/dist

.PHONY: up-oidc
up-oidc: ## Avvia lo stack con Keycloak (profilo oidc)
	@grep -qE '^KEYCLOAK_ADMIN_PASSWORD=.+' .env \
		|| (echo "KEYCLOAK_ADMIN_PASSWORD non impostata in .env: richiesta dal profilo oidc." \
		    && echo "  openssl rand -base64 32" && exit 1)
	$(COMPOSE) --profile oidc up -d
