# Defenix Exposure Rating

Piattaforma multi-tenant per la produzione di un **External Cyber Exposure Rating**:
raccoglie evidenze OSINT sul perimetro esterno di un'azienda, le normalizza, le
correla e le trasforma in un rating deterministico 0-100 con classe A-E, cinque
rating tematici, un indice di confidenza separato, un report esecutivo, un
allegato tecnico e un piano di rimedio prioritizzato.

> **Che cosa NON e'.** Il rating e' una valutazione dell'esposizione esterna
> osservabile da fonti pubbliche. **Non e' un penetration test, non e' un
> vulnerability assessment completo e non e' una certificazione di sicurezza.**
> L'assenza di risultati non e' prova di sicurezza. La limitazione e' riportata
> nell'interfaccia e in ogni report generato. Dettagli in
> [`docs/LEGAL_AND_SCOPE.md`](docs/LEGAL_AND_SCOPE.md).

---

## Principio architetturale non negoziabile

```
I tool raccolgono evidenze.  Il motore deterministico calcola il rating.  L'AI interpreta e spiega.
```

Le tre responsabilita' sono separate anche a livello di codice: il pacchetto di
scoring (`backend/app/services/scoring.py`) non importa nulla di collegato a un
modello linguistico, e il livello di interpretazione riceve esclusivamente dati
normalizzati, sanificati e conformi a uno schema JSON predefinito.

L'AI non puo': inventare asset, vulnerabilita' o evidenze; assegnare punteggi;
modificare il risultato del motore; considerare vulnerabile una tecnologia senza
un match sufficientemente affidabile; interpretare l'assenza di risultati come
prova di sicurezza; eseguire comandi di sistema; seguire istruzioni contenute
nelle pagine web analizzate.

**Tutto cio' che arriva da Internet e' trattato come dato non fidato e
potenzialmente contenente prompt injection** (`backend/app/core/redaction.py`).

---

## Componenti

| Livello | Tecnologia | Contenuto |
|---|---|---|
| API | Python 3.11, FastAPI, Pydantic v2 | 8 router: auth, companies, scans, findings, reports, dashboard, admin, health |
| Persistenza | PostgreSQL 16, SQLAlchemy 2.0, Alembic | 28 entita', `tenant_id` su ogni record, Row Level Security |
| Orchestrazione | Celery 5 + Redis 7 | code `scans` e `maintenance`, worker separati dall'API |
| Adapter | `adapters/` | DNS, RDAP, Certificate Transparency, Subfinder, Amass, HTTPX, checkdmarc, testssl.sh, ZAP Baseline, Nuclei (allowlist), Naabu, DNSTwist, SpiderFoot, Ransomware.live, HIBP, vuln-intel (KEV + EPSS + NVD), stub fase 2 |
| Motore rating | `backend/app/services/scoring.py` | 57 regole YAML, 5 categorie, cap, gruppi esclusivi, decadimento temporale |
| Confidenza | `backend/app/services/confidence.py` | indice 0-100 indipendente dal rating |
| Sicurezza scansione | `scope_guard.py`, `adapters/runner.py` | anti-SSRF, default deny, esecuzione `shell=False` con argomenti ad array |
| Reporting | Jinja2 + WeasyPrint + python-docx | PDF, DOCX, JSON, CSV in italiano (inglese opzionale) |
| Frontend | React 18, TypeScript, Vite, Recharts | Login, Portfolio, Company Dashboard, Gestione azienda, **Personalizzazione**, Findings, Remediation, Reports, Scans |
| Deploy | Docker Compose, struttura K8s-ready | container non-root, tmpfs, limiti CPU/memoria, health check |

---

## Requisiti

* Docker 24+ e Docker Compose v2 (percorso consigliato), **oppure**
* Python 3.11+, Node.js 20+, PostgreSQL 16, Redis 7 per l'esecuzione locale.

I tool esterni (Subfinder, testssl.sh, Nuclei, ...) non sono necessari per
avviare la piattaforma: ogni adapter dichiara la propria disponibilita' e, se
assente, restituisce `skipped` riducendo la confidenza senza bloccare la
scansione. In `SCAN_MOCK_MODE=true` gli adapter usano generatori sintetici
deterministici.

---

## Installazione

### 1. Con Docker Compose

```bash
git clone <repo> && cd Cyber-Exposure-Rating
# Crea `.env` dai valori di esempio generando i segreti obbligatori
# (password Postgres, chiave JWT, chiave Fernet per le evidenze raw).
# Senza di essi `docker compose` si rifiuta di partire.
make env                    # aggiungere KEYCLOAK=1 se si usera' il profilo oidc

make build
make up
make compose-migrate
make compose-seed
make harden-db        # revoca UPDATE/DELETE sull'audit log
```

Se l'avvio fallisce con `port is already allocated`, un altro programma occupa
una delle porte: `make check-ports` dice quali e quale variabile di `.env`
cambiare. Il frontend raggiunge l'API attraverso il proxy interno di nginx,
quindi cambiare porta non richiede di toccare `CORS_ORIGINS`.

* Frontend: <http://localhost:8080>
* API + OpenAPI: <http://localhost:8000/api/v1/docs>
* Health: <http://localhost:8000/api/v1/health/ready>

### 2. In locale, senza container

```bash
make install          # venv + dipendenze backend, npm install frontend
make init-db          # schema su SQLite di sviluppo (o DATABASE_URL PostgreSQL)
make seed             # tenant, ruoli, utenti e tre aziende dimostrative
make demo             # scansione dimostrativa su dati sintetici
make api              # http://127.0.0.1:8000
make worker           # in un secondo terminale
make web              # http://127.0.0.1:5173
```

---

## Comandi di avvio

| Comando | Effetto |
|---|---|
| `make env` | crea `.env` generando i segreti (`FORCE=1` rigenera, `KEYCLOAK=1` include OIDC) |
| `make up` / `make down` | avvia / ferma lo stack completo |
| `make up-oidc` | avvia lo stack con Keycloak (profilo `oidc`) |
| `make api` | API FastAPI con ricarica automatica |
| `make worker` | worker Celery sulle code `scans` e `maintenance` |
| `make web` | frontend Vite in sviluppo |
| `make demo` | scansione dimostrativa end-to-end su dati sintetici |
| `make credentials` | ristampa le credenziali demo generate |
| `make compose-credentials` | ristampa le credenziali demo dal container API |
| `make test` / `make lint` | suite di test / analisi statica |
| `make check-config` | valida i YAML di scoring e confidenza |
| `make check-versions` | verifica che le versioni fissate nei Dockerfile esistano ancora |
| `make check-ports` | verifica che le porte pubblicate dallo stack siano libere |
| `make doctor` | raccoglie stato, porte e log dello stack per la diagnosi |
| `make fix-evidence-perms` | corregge i permessi del volume delle evidenze creato prima della correzione |
| `make worker-start` | costruisce, avvia e verifica il worker: serve per le scansioni reali |
| `make scan-now` | esegue subito le scansioni in coda senza attendere il worker (solo in modalita' simulata) |
| `make sbom` | genera la SBOM CycloneDX di backend e frontend |
| `make backup` / `make restore DUMP=...` | backup e ripristino |

---

## Credenziali demo

Le password compaiono in chiaro **solo nell'output del comando**: nel database
sono memorizzate unicamente come hash bcrypt, e un nuovo `seed` non le rigenera
per utenti gia' esistenti. Conviene quindi salvarle subito:
`make compose-seed | tee credenziali-demo.txt`.

`make seed` genera password casuali con `secrets.token_urlsafe`, le stampa una
sola volta e le salva in `.demo-credentials.json` (permessi `0600`, escluso da
git). **Non esistono credenziali predefinite nel codice.** Per rileggerle:

```bash
make credentials
```

Gli utenti creati coprono i sette ruoli previsti: `platform_administrator`,
`tenant_administrator`, `security_analyst`, `reviewer`, `sales_account_manager`,
`customer_viewer`, `read_only_auditor`.

---

## Verifica del dominio

Nessuna scansione oltre il profilo passivo e' eseguibile su un perimetro non
verificato. I metodi supportati sono quattro:

1. **DNS TXT** – record TXT `_defenix-verification.<dominio>` con il token.
2. **File HTTP** – `https://<dominio>/.well-known/defenix-verification.txt`
   contenente il token.
3. **Email amministrativa** – link inviato a un indirizzo del dominio stesso.
4. **Approvazione manuale** – caricamento del documento di autorizzazione,
   convalidato da un `tenant_admin`.

L'autorizzazione registra soggetto autorizzante, azienda, data e ora, perimetro
autorizzato, profilo di scansione, scadenza, esclusioni e riferimento del
documento. Il perimetro **non** viene mai esteso automaticamente verso CDN,
cloud provider, hosting condiviso, domini di fornitori, SaaS o IP condivisi.
Gli asset sono classificati come *Verified Owned*, *Likely Owned*, *Unverified*,
*Third Party*, *Excluded*: solo i primi due influenzano il rating, i secondi con
regole piu' restrittive.

### Se una scansione resta «in corso»

Una scansione viene chiusa dal processo che la esegue. Se quel processo se ne
va — container riavviato, macchina sospesa, limite di tempo raggiunto — la
riga resta in corso e **blocca l'azienda**: non se ne puo' avviare un'altra.

Il recupero e' automatico oltre la soglia di abbandono (limite del task Celery
piu' dieci minuti): il primo avvio successivo chiude l'orfana e procede. Per
non aspettare:

```bash
make scan-stato       # cosa e' rimasto aperto, da quanto, e se e' orfano
make scan-sblocca     # chiude tutto cio' che non e' concluso
```

Gli strumenti gia' partiti proseguono nel worker fino al proprio tempo
massimo. Per fermarli subito: `docker compose restart worker`.

### Dati dimostrativi

Con `SCAN_MOCK_MODE=true` le scansioni producono dati sintetici, e gli asset
restano nel database fra una scansione e l'altra. Sono marcati come
dimostrativi ed **esclusi dai report delle scansioni reali**: senza la
marcatura un indirizzo e-mail inventato comparirebbe in un report vero come
«proprieta' verificata». Un asset osservato anche da una scansione reale perde
la marcatura; la sezione *Asset* permette di rimuovere quelli rimasti.

### Inventario degli asset

Ogni asset attribuito all'azienda e' consultabile in *Asset* (sotto la scheda
dell'azienda), con il tipo, lo stato di proprieta', le tecnologie rilevate e
**lo strumento che lo ha individuato**: la provenienza e' la prima cosa da
controllare per stabilire se ci si possa fidare di un asset. Lo stesso elenco
compare nell'allegato tecnico del report.

Gli asset non piu' osservati non vengono cancellati ma marcati: un asset
scomparso puo' essere un servizio dismesso oppure un servizio che non ha
risposto durante la rilevazione, e sono due situazioni diverse.

Gli indirizzi e-mail sono mostrati mascherati; l'indirizzo completo e'
visibile solo ai ruoli con il permesso `pii:unmask`, e la ricerca opera sul
nome mascherato per non permettere di confermare un indirizzo per tentativi.

### Perimetro di rete

Gli indirizzi IP raggiunti dai domini in perimetro vengono classificati a ogni
scansione (reverse DNS e rete RDAP) e registrati come inventario in *Gestione
azienda → Perimetro di rete*. Il port scanning del profilo Extended agisce solo
su quelli **autorizzati**: l'autorizzazione e' un atto esplicito dell'analista,
registrato nel log di audit. Gli indirizzi di CDN e reverse proxy non sono
autorizzabili, e il rifiuto e' applicato dal server: rispondono per molti
clienti insieme, e sondarli significherebbe sondare l'infrastruttura del
fornitore. Il dettaglio della regola e' in `docs/SCAN_PROFILES.md`.

---

## Profili di scansione

| Profilo | Verifica richiesta | Cosa fa | Cosa non fa mai |
|---|---|---|---|
| Public Passive Check | nessuna | solo fonti pubbliche e passive | port scan, vulnerability scan, brute force, crawling aggressivo, autenticazione, exploit, fuzzing |
| Verified Standard Check | dominio verificato | interrogazioni attive non intrusive | exploit, modifica dati |
| Verified Extended Check | verifica + autorizzazione scritta | controlli estesi non distruttivi | credential stuffing, password spraying, brute force, tentativi di login, SQL injection attiva, DoS, upload, esecuzione payload, modifica/cancellazione dati, exploit distruttivi, scansione di infrastrutture terze |

Dettaglio in [`docs/SCAN_PROFILES.md`](docs/SCAN_PROFILES.md).

---

## Rating e confidenza

Il punteggio parte da 100 e sottrae le detrazioni previste dalle regole in
`config/scoring.yaml`, per cinque aree pesate:

| Area | Peso |
|---|---|
| Superficie esposta | 20% |
| Vulnerabilita' note | 25% |
| Sicurezza email | 20% |
| Esposizione dati e credenziali | 20% |
| Reputazione e minacce | 15% |

Classi: **A** 85-100, **B** 70-84, **C** 55-69, **D** 40-54, **E** 0-39.

Ogni evidenza pesa in base alla classificazione (Confirmed 100%, Probable 50%,
Inferred e Informational 0%) e alla proprieta' dell'asset. I gruppi esclusivi
impediscono che una stessa CVE sia penalizzata da piu' regole sovrapposte; i cap
per causa radice limitano il totale sottratto da un unico problema.

**Un controllo non eseguito riduce la confidenza, non il rating.** L'indice di
confidenza 0-100 e' calcolato separatamente (`config/evidence_confidence.yaml`);
sotto 50 il rating e' marcato *"Valutazione provvisoria – evidenze insufficienti
per un rating attendibile."*

I cap di rating (ransomware ≤39, KEV internet-facing ≤49, stealer log recenti
≤59, vulnerabilita' critiche sfruttabili ≤54) si applicano **esclusivamente** a
evidenze confermate, su asset verificati e con esito validato da un analista.

Dettaglio in [`docs/SCORING_MODEL.md`](docs/SCORING_MODEL.md).

---

## Struttura del progetto

```
├── README.md                  ├── config/                 YAML versionati del modello
├── docker-compose.yml         │   ├── scoring.yaml            57 regole, 5 categorie
├── .env.example               │   ├── tool_profiles.yaml      22 tool, 3 profili
├── Makefile                   │   ├── remediation_catalog.yaml
├── backend/                   │   ├── rating_caps.yaml
│   ├── app/                   │   ├── evidence_confidence.yaml
│   │   ├── api/routers/       │   └── nuclei_allowlist.yaml
│   │   ├── core/              ├── reporting/              Jinja2, PDF, DOCX, JSON, CSV
│   │   ├── models/            ├── frontend/               React + TypeScript + Vite
│   │   ├── schemas/           ├── workers/                immagini e wrapper dei tool
│   │   ├── services/          ├── deploy/                 configurazioni di runtime
│   │   └── workers/           ├── tests/                  373 test
│   └── alembic/               ├── docs/                   ARCHITECTURE, SCORING_MODEL,
├── adapters/                  │                           SCAN_PROFILES, SECURITY_MODEL,
│   ├── runner.py              │                           LEGAL_AND_SCOPE, DEPLOYMENT,
│   └── <un file per tool>     │                           OPERATIONS_RUNBOOK
                               └── THIRD_PARTY_NOTICES.md
```

---

## Sicurezza

* I tool **non** vengono eseguiti nel container API: girano in worker dedicati,
  con utente non-root, tmpfs, limiti CPU/memoria, timeout e rate limiting.
* Nessuna interpolazione di input utente nella shell: `shell=False` e argomenti
  passati **come array**, con validazione per espressione regolare e allowlist
  di opzioni per ogni tool (`adapters/runner.py`).
* `ScopeGuard` e' l'unico punto di autorizzazione dei target: default deny,
  blocco di localhost, reti private e link-local, endpoint di metadata cloud,
  URL con credenziali, difesa da DNS rebinding e rivalutazione dei redirect.
* Isolamento multi-tenant con RLS e risposte `404` (non `403`) sulle risorse di
  altri tenant, audit log append-only con catena di hash, MFA, retention e
  cancellazione sicura.
* I report **non** contengono password, token, cookie, dati personali non
  necessari, contenuto integrale dei leak, documenti illeciti, istruzioni di
  exploit o payload offensivi. Le password non vengono mai memorizzate; gli
  indirizzi email sono mascherati salvo per i ruoli autorizzati.

Dettaglio in [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

---

## Test

```bash
make test        # 373 test
make coverage    # con report di copertura
make lint        # ruff + tsc --noEmit
```

La suite copre motore di scoring e confidenza, parser, adapter su fixture,
deduplica, segregazione multi-tenant, RBAC, command injection, SSRF, limiti di
perimetro, cap di rating, generazione PDF e DOCX e workflow di revisione.
**Nessun test contatta sistemi reali su Internet:** si usano esclusivamente
fixture, output registrati e sanificati e dati completamente sintetici.

---

## Licenze

Il catalogo completo dei componenti con versione, licenza, modalita' d'uso,
obblighi di attribuzione, diritti di ridistribuzione e rischio commerciale e' in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Attenzione particolare a
Nmap (NPSL), AIL (AGPL-3.0), alle licenze dei template Nuclei, alle immagini
Docker e alle condizioni delle API: **una fonte dati non e' gratuita solo perche'
il connettore e' open source.**

---

## Documentazione

| Documento | Contenuto |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | componenti, flussi, diagrammi Mermaid, modello dati |
| [`docs/SCORING_MODEL.md`](docs/SCORING_MODEL.md) | regole, pesi, cap, decadimento, confidenza |
| [`docs/SCAN_PROFILES.md`](docs/SCAN_PROFILES.md) | profili, tool ammessi, azioni vietate |
| [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) | minacce, contromisure, isolamento, audit |
| [`docs/LEGAL_AND_SCOPE.md`](docs/LEGAL_AND_SCOPE.md) | limiti del servizio, autorizzazioni, privacy |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | installazione, configurazione, hardening |
| [`docs/OPERATIONS_RUNBOOK.md`](docs/OPERATIONS_RUNBOOK.md) | esercizio, backup, incidenti, manutenzione |

---

© Defenix / AD Consulting. Uso interno e per clienti autorizzati.
