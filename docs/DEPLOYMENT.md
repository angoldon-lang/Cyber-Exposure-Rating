# Installazione e deployment

## 1. Requisiti

| Componente | Versione minima | Nota |
|---|---|---|
| Docker Engine | 24.0 | con il plugin Compose v2 |
| CPU | 4 core | 8 consigliati con il profilo esteso |
| RAM | 8 GB | 16 con ZAP e Keycloak |
| Disco | 50 GB | cresce con evidenze e report |

Per lo sviluppo senza container servono Python 3.11+, Node.js 22+,
PostgreSQL 16 e Redis 7.

## 2. Avvio rapido (dati sintetici)

```bash
git clone <repository> defenix && cd defenix
cp .env.example .env

# Generare i segreti obbligatori
echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)" >> .env
echo "JWT_SECRET_KEY=$(openssl rand -base64 48)" >> .env

make build && make up
make compose-migrate
make compose-seed        # stampa le credenziali demo generate
```

- Frontend: <http://localhost:8080>
- API e documentazione: <http://localhost:8000/api/v1/docs>

Con `SCAN_MOCK_MODE=true` (predefinito) le scansioni usano dati sintetici
deterministici e **non contattano alcun sistema reale**: e' la modalita'
corretta per dimostrazioni e formazione.

## 3. Sviluppo locale senza container

```bash
make venv && make install
export DATABASE_URL="sqlite:///./defenix.db"
export JWT_SECRET_KEY="chiave-di-sviluppo-almeno-8-caratteri"
export SCAN_MOCK_MODE=true ENABLE_ROW_LEVEL_SECURITY=false

make init-db && make seed && make demo
make api      # in un terminale
make web      # in un altro
```

SQLite e' adeguato allo sviluppo; non supporta Row Level Security, quindi
in questa modalita' l'isolamento resta garantito dai soli filtri applicativi.

## 4. Passaggio in produzione

### 4.1 Elenco di controllo

- [ ] `ENVIRONMENT=production`
- [ ] `JWT_SECRET_KEY` generata casualmente (l'avvio fallisce con il default)
- [ ] `AUTH_MODE=oidc` con Keycloak e MFA attiva
- [ ] `ENABLE_ROW_LEVEL_SECURITY=true` con PostgreSQL
- [ ] `SCAN_MOCK_MODE=false` **solo** dopo aver verificato le autorizzazioni
- [ ] `ALLOW_PRIVATE_IP_SCANNING=false` (deve restare false)
- [ ] `CORS_ORIGINS` limitato ai domini effettivi
- [ ] TLS terminato da un reverse proxy davanti al frontend
- [ ] `make harden-db` eseguito dopo le migrazioni
- [ ] backup automatici configurati e **verificati con un ripristino**
- [ ] rate limiting sul reverse proxy
- [ ] rotazione dei log e conservazione centralizzata

### 4.2 Autenticazione OIDC

```bash
docker compose --profile oidc up -d keycloak
```

In Keycloak: creare il realm `defenix`, un client `defenix-api` (public,
PKCE), i sette ruoli di realm con gli stessi nomi usati dalla piattaforma
(`platform_administrator`, `tenant_administrator`, `security_analyst`,
`reviewer`, `sales_account_manager`, `customer_viewer`,
`read_only_auditor`), e imporre l'MFA.

Poi in `.env`:

```bash
AUTH_MODE=oidc
OIDC_ISSUER=https://keycloak.esempio.it/realms/defenix
OIDC_JWKS_URL=https://keycloak.esempio.it/realms/defenix/protocol/openid-connect/certs
OIDC_AUDIENCE=defenix-api
OIDC_CLIENT_ID=defenix-api
```

Con `AUTH_MODE=oidc` l'endpoint di login locale viene disabilitato.

### 4.3 Irrobustimento del database

```bash
make compose-migrate    # crea schema, policy RLS e trigger sull'audit
make harden-db          # revoca UPDATE/DELETE su audit_logs
```

Il ruolo applicativo deve essere `NOSUPERUSER NOBYPASSRLS`: le policy RLS non
si applicano a chi puo' aggirarle.

## 5. Attivazione delle scansioni reali

`SCAN_MOCK_MODE=false` abilita il contatto con sistemi reali. Prima di
procedere:

1. verificare che ogni azienda abbia domini verificati;
2. verificare che le autorizzazioni siano registrate, firmate e valide;
3. confermare che il perimetro non includa asset di terzi;
4. controllare che gli IP di uscita dei worker siano noti al cliente;
5. verificare i limiti di rate rispetto agli accordi.

`ALLOW_PRIVATE_IP_SCANNING` deve restare `false`: abilitarlo permetterebbe di
scansionare reti interne e trasformerebbe la piattaforma in uno strumento di
movimento laterale.

## 6. Connettori esterni

| Connettore | Configurazione | Costo |
|---|---|---|
| CISA KEV, EPSS | attivi per impostazione predefinita | gratuiti |
| Certificate Transparency, RDAP | attivi | gratuiti |
| theHarvester | profilo `osint` + `THEHARVESTER_URL` | gratuito, alcune fonti a pagamento |
| SpiderFoot | istanza propria + `SPIDERFOOT_URL` (vedere 6.3) | gratuito, alcune fonti a pagamento |
| OWASP ZAP | profilo `zap` + `ZAP_URL` e `ZAP_API_KEY` | gratuito |
| Have I Been Pwned | `HIBP_API_KEY` | **a pagamento** |
| Fonte su credenziali esposte | `CREDENTIAL_EXPOSURE_URL` e `..._API_KEY` | **a pagamento** |
| Ransomware.live | attivo | API pubblica |

Le chiavi non vanno mai inserite nel codice: `APIKeyReference` conserva solo
metadati per rotazione e audit, il valore vive nel secret manager.

### 6.1 I profili compose: due passi, non uno

Un servizio dichiarato sotto un profilo **non esiste** se il profilo non e'
attivo, e Compose non emette alcun avviso: `docker compose up -d` avvia lo
stack e tace. theHarvester non viene creato, il suo adapter trova un
indirizzo che non risponde, e il motivo vero -- «il contenitore non e' mai
stato avviato» -- non compare da nessuna parte: in scansione si legge soltanto
`Connection refused`, e la copertura cala.

Compose legge `COMPOSE_PROFILES` da `.env`, e quello e' il posto giusto:

```
COMPOSE_PROFILES=osint          # predefinito in .env.example
COMPOSE_PROFILES=osint,zap      # anche il demone ZAP
```

Da li' in avanti `make up` avvia tutto. Chi ha installato prima che la riga
comparisse in `.env.example` ha un `.env` che non la contiene: `make up` lo
segnala, e `make up-osint` avvia i due servizi senza modificare nulla.

`osint` e' attivo per impostazione predefinita perche' theHarvester e'
gratuito, locale e non richiede chiavi. `zap` e `oidc` no: senza la loro
chiave il contenitore parte e rifiuta ogni richiesta, e avviarlo per default
sposterebbe il guasto senza risolverlo. Si avviano con `make up-zap` e
`make up-oidc`, che la chiave la controllano prima.

### 6.2 Verificare che tutto sia a posto

```bash
make strumenti
```

Dice, strumento per strumento, se e' utilizzabile e cosa gli manca: binario
assente, variabile non impostata, servizio che non risponde, abbonamento
mancante, oppure niente da fare. E' il controllo da eseguire dopo
l'installazione e dopo ogni `make aggiorna`, prima di dedurre dalla matrice di
copertura di una scansione che qualcosa sia rotto. Il dettaglio degli esiti e'
in `docs/OPERATIONS_RUNBOOK.md`, sezione 3.

### 6.3 SpiderFoot non fa piu' parte dello stack

Il progetto non pubblica un'immagine container utilizzabile:
`ghcr.io/smicallef/spiderfoot` non esiste (il registro risponde `denied`), su
Docker Hub non c'e' nulla, e la sola immagine raggiungibile e' un fork di terzi
pubblicato solo per amd64 e solo con tag mobili. Non e' qualcosa su cui fondare
un'installazione, tanto meno di una piattaforma che fissa ogni immagine per
digest, e su arm64 non partirebbe nemmeno.

Lo stack percio' non lo avvia. Le sue due aree -- superficie d'attacco e dark
web -- le copre **theHarvester**, che e' pinnato per digest e gira su entrambe
le architetture: il catalogo lo dichiara (`replaced_by: theharvester`), e
l'assenza di SpiderFoot non costa copertura finche' theHarvester riesce.

Lo strumento resta integrato. Chi ospita una propria istanza raggiungibile dal
worker ne indica l'indirizzo in `SPIDERFOOT_URL` (o da Personalizzazione ->
Strumenti) e torna a funzionare, senza altre modifiche.

## 7. Backup e ripristino

```bash
make backup                          # database + storage evidenze
make restore DUMP=backups/file.dump  # ripristino
```

I backup contengono dati sensibili: vanno cifrati prima di essere archiviati
fuori sede. Un backup mai ripristinato non e' un backup: verificarlo
periodicamente su un ambiente separato.

## 8. Osservabilita'

Health check: `/api/v1/health` (completo), `/health/live` (liveness),
`/health/ready` (readiness).

I log sono JSON strutturati con redazione automatica dei segreti. Ogni
richiesta porta un `X-Request-ID` propagato nella risposta.

Segnali da monitorare: percentuale di `ToolRun` falliti (copertura in calo),
scansioni in stato `queued` da troppo tempo (worker fermi), confidence media
in discesa (fonti degradate), `scan_blocked` frequenti (autorizzazioni
scadute).

## 9. Prospettiva Kubernetes

La struttura e' predisposta: servizi separati e senza stato locale (tranne i
volumi dichiarati), configurazione via variabili d'ambiente, health check
distinti per liveness e readiness, immagini con versioni bloccate.

Per il passaggio servirebbero: Deployment per API, worker e beat; StatefulSet
o servizi gestiti per PostgreSQL e Redis; PersistentVolumeClaim per evidenze e
report; NetworkPolicy che riproduca la separazione delle reti del compose;
`SecurityContext` con `runAsNonRoot` e `readOnlyRootFilesystem`; secret
gestiti da un secret manager esterno.

## 10. Aggiornamenti

```bash
git pull
make build
make down && make up
make compose-migrate
```

Le migrazioni Alembic sono progressive. Prima di aggiornare in produzione:
eseguire un backup, verificare le note di rilascio e provare l'aggiornamento
su un ambiente di staging.
