# Architettura

## 1. Principio fondante

> Gli strumenti tecnici raccolgono le evidenze.
> Il motore deterministico calcola il rating.
> L'intelligenza artificiale interpreta e spiega i risultati.

Questa separazione non e' una linea guida: e' vincolata dal codice.
Il motore di scoring (`backend/app/services/scoring.py`) non importa alcun
client di modelli linguistici e legge esclusivamente file YAML versionati.
Un modello AI, quando verra' integrato, ricevera' il risultato gia' calcolato
e potra' soltanto descriverlo.

Cio' che l'AI non puo' fare, e perche' e' strutturalmente impossibile:

| Divieto | Come e' impedito |
|---|---|
| inventare asset o evidenze | le evidenze nascono solo dagli adapter, con `fingerprint` e riferimento all'output grezzo |
| assegnare il punteggio | il punteggio e' prodotto da `ScoringEngine`, che non ha dipendenze AI |
| modificare il risultato | `Score` e' scritto dalla pipeline e non e' esposto ad alcun endpoint di modifica |
| dedurre vulnerabilita' senza prove | `adapters/vulnintel/matcher.py` richiede prodotto **e** versione compatibili |
| trattare l'assenza di risultati come sicurezza | un tool non eseguito abbassa la *confidence*, non alza il rating |
| eseguire comandi | l'esecuzione passa solo da `adapters/runner.py`, con argv validato e allowlist |
| seguire istruzioni dalle pagine analizzate | `app/core/redaction.py` neutralizza i pattern di prompt injection |

## 2. Vista d'insieme

```mermaid
flowchart TB
    subgraph client["Interfaccia"]
        UI["Frontend React/TypeScript<br/>dashboard, revisione, report"]
    end

    subgraph api["Container API (nessuno strumento di scansione)"]
        REST["FastAPI + OpenAPI"]
        AUTHZ["Gate di autorizzazione<br/>verifica dominio + autorizzazione + profilo"]
        RBAC["RBAC · 7 ruoli"]
        AUDIT["Audit log append-only"]
    end

    subgraph queue["Coda"]
        REDIS[("Redis<br/>broker Celery")]
    end

    subgraph worker["Worker isolati (utente non root, limiti di risorse)"]
        PIPE["ScanPipeline"]
        GUARD["ScopeGuard<br/>anti-SSRF e perimetro"]
        RUNNER["ToolRunner<br/>argv validato, no shell"]
        ADAPT["Adapter<br/>DNS · RDAP · CT · Subfinder · SpiderFoot<br/>checkdmarc · HTTPX · testssl · Ransomware.live<br/>HIBP · KEV/EPSS · DNSTwist · ZAP · Nuclei · Naabu"]
    end

    subgraph engine["Motore deterministico"]
        NORM["Normalizzazione<br/>correlazione e deduplicazione"]
        OWN["Ownership<br/>verified / likely / third party"]
        SCORE["ScoringEngine<br/>YAML versionati"]
        CONF["ConfidenceEngine"]
    end

    subgraph store["Persistenza"]
        PG[("PostgreSQL<br/>RLS per tenant")]
        FS[("Storage evidenze<br/>e report")]
    end

    subgraph out["Uscite"]
        REP["Report PDF · Word · JSON · CSV"]
        AI["Interpretazione AI<br/>(riceve solo dati normalizzati)"]
    end

    UI --> REST
    REST --> AUTHZ --> RBAC
    REST --> AUDIT
    AUTHZ -->|scansione autorizzata| REDIS
    REDIS --> PIPE
    PIPE --> GUARD --> RUNNER --> ADAPT
    ADAPT --> NORM --> OWN --> SCORE --> CONF
    CONF --> PG
    ADAPT -.output grezzo.-> FS
    PG --> REST
    PG --> REP
    SCORE -.risultato immutabile.-> AI
```

## 3. Decisioni tecniche principali

### 3.1 Il motore di scoring e' configurazione, non codice

Pesi, regole, detrazioni, tetti e soglie vivono in `config/*.yaml` con un
numero di versione. Ogni `Score` registra la versione usata: un rating di sei
mesi fa resta spiegabile anche dopo l'evoluzione del modello. Cambiare il
modello significa modificare uno YAML ed eseguire i test di regressione, non
riscrivere Python.

### 3.2 Il fallimento di un tool non e' il fallimento della scansione

`BaseAdapter.run()` cattura ogni eccezione e la converte in un
`AdapterResult` con stato `failed` e un `coverage_impact`. La scansione
prosegue; la copertura ridotta si riflette nel confidence score. Un tool
rotto quindi **abbassa l'affidabilita' dichiarata**, non migliora il rating.

### 3.3 Un solo punto di autorizzazione dei target

Nessun adapter costruisce da se' l'elenco dei target: passa da
`ScopeGuard`, che applica in ordine formato → esclusioni → indirizzi non
pubblici → inclusioni → *default deny*. Anche i redirect vengono rivalutati
hop per hop, perche' un redirect non estende il perimetro.

### 3.4 Gli argomenti dei comandi sono dati, mai stringhe

`adapters/runner.py` non usa mai la shell. Ogni argomento e' validato contro
una regex restrittiva e ogni opzione deve comparire in un'allowlist per quel
tool: cosi' e' bloccata anche l'*argument injection* (un hostname che inizia
con `--` non puo' diventare un'opzione).

### 3.5 Il perimetro non si espande da solo

Un sottodominio che punta a CloudFront non rende CloudFront un asset del
cliente. `app/services/ownership.py` classifica CDN, cloud, hosting condivisi
e SaaS come `third_party`, con moltiplicatore 0 nello scoring.

### 3.6 La confidence e' separata dal rating

Sono due numeri con significati diversi: *quanto sei esposto* e *quanto e'
solida questa misura*. Tenerli separati evita il difetto tipico dei rating
esterni, in cui una scansione superficiale produce un buon voto.

## 4. Flusso di una scansione

```mermaid
sequenceDiagram
    participant U as Utente
    participant A as API
    participant G as Gate autorizzazione
    participant Q as Celery
    participant P as Pipeline
    participant S as ScopeGuard
    participant T as Adapter
    participant E as Motore
    participant D as PostgreSQL

    U->>A: POST /companies/{id}/scans {profile}
    A->>A: RBAC: permesso per il profilo?
    A->>G: dominio verificato? autorizzazione attiva? whitelist?
    alt requisiti non soddisfatti
        G-->>A: rifiuto con i motivi
        A->>D: audit `scan_blocked`
        A-->>U: 403 con l'elenco di cio' che manca
    else autorizzata
        A->>D: Scan(queued) + snapshot immutabile del perimetro
        A->>Q: accoda
        Q->>P: esegue
        P->>S: costruisce il perimetro autorizzato
        P->>T: fase 1 discovery (DNS, RDAP, CT, Subfinder, SpiderFoot)
        T->>S: ogni target e' verificato
        P->>T: fase 2 analisi (checkdmarc, HTTPX, testssl, dark web)
        P->>E: normalizza, correla, deduplica
        P->>T: fase 3 vulnerability intelligence sulle tecnologie osservate
        E->>E: scoring deterministico + confidence
        P->>D: asset, evidenze, finding, punteggi, tool run
        U->>A: revisione dei finding critici
        U->>A: generazione del report
    end
```

## 5. Struttura del repository

```
config/           modello di scoring, profili, remediation, cap, allowlist Nuclei
backend/
  app/
    core/         configurazione, database, sicurezza, RBAC, logging, redazione
    models/       30 tabelle SQLAlchemy, tutte con tenant_id
    schemas/      contratti Pydantic dell'API
    api/          dipendenze e router REST
    services/     scope guard, ownership, normalizzazione, scoring, confidence,
                  autorizzazione, verifica dominio, revisione, remediation, diff
    workers/      Celery e orchestratore della pipeline
  alembic/        migrazioni (RLS, trigger di immutabilita' dell'audit)
adapters/         un modulo per strumento, piu' runner sicuro e registro
reporting/        contesto, template Jinja2, generatori PDF/Word/JSON/CSV
frontend/         React + TypeScript + Vite
tests/            373 test: scoring, sicurezza, adapter, API, report, pipeline
docs/             questa documentazione
```

## 6. Modello dati

```mermaid
erDiagram
    TENANT ||--o{ COMPANY : contiene
    TENANT ||--o{ USER : contiene
    USER }o--o{ ROLE : ha
    COMPANY ||--o{ DOMAIN : dichiara
    COMPANY ||--o{ IP_ADDRESS : dichiara
    COMPANY ||--o{ NETWORK_RANGE : dichiara
    COMPANY ||--o{ BRAND : dichiara
    COMPANY ||--o{ AUTHORIZATION : concede
    AUTHORIZATION ||--o{ SCOPE : delimita
    COMPANY ||--o{ ASSET : possiede
    ASSET ||--o{ ASSET_RELATIONSHIP : collega
    COMPANY ||--o{ SCAN : sottoposta_a
    SCAN ||--o{ TOOL_RUN : esegue
    TOOL_RUN ||--o{ EVIDENCE : produce
    EVIDENCE }o--|| ASSET : riferisce
    SCAN ||--o{ FINDING : correla
    FINDING }o--o| REMEDIATION : rimediato_da
    FINDING }o--o| VULNERABILITY : riferisce
    SCAN ||--|| SCORE : valutata
    SCORE ||--o{ SCORE_CATEGORY : dettaglia
    SCORE ||--|| CONFIDENCE_SCORE : accompagnata
    SCAN ||--o{ REPORT : documentata
    REPORT ||--o{ REPORT_VERSION : versionata
    TENANT ||--o{ CONNECTOR : configura
    TENANT ||--o{ API_KEY_REFERENCE : referenzia
    TENANT ||--o{ RETENTION_POLICY : applica
    TENANT ||--o{ AUDIT_LOG : registra
```

Note sul modello:

- **`tenant_id` ovunque.** Ogni tabella del dominio lo porta, con policy
  PostgreSQL RLS oltre ai filtri applicativi.
- **`APIKeyReference` non contiene chiavi.** Solo metadati per rotazione e
  audit; il valore vive nel secret manager.
- **`Evidence` e' immutabile,** `Finding` no: il finding e' l'unita' che
  l'analista rivede, l'evidenza e' il fatto osservato.
- **`AuditLog` e' append-only** con hash a catena, e in PostgreSQL con
  trigger che rifiuta UPDATE e DELETE.

## 7. Perche' i worker sono separati dall'API

Gli strumenti di scansione elaborano contenuti non attendibili provenienti da
Internet. Tenerli nel container API significherebbe che una vulnerabilita' in
un parser esporrebbe direttamente credenziali del database, segreti JWT e
storage delle evidenze.

Il container API non contiene alcun binario di scansione. Il worker gira come
utente non root, con `cap_drop: ALL`, filesystem temporaneo dedicato e limiti
espliciti di CPU e memoria. La sola capability aggiunta e' `NET_RAW`, e serve
unicamente al SYN scan di Naabu nel profilo esteso: chi non usa quel profilo
puo' rimuoverla.

## 8. Evoluzione prevista

| Fase | Contenuto | Stato |
|---|---|---|
| 1 – MVP | passivo, scoring, confidence, report, revisione | completata |
| 2 – Extended | Amass, ZAP, Naabu/Nuclei, DNSTwist, header e-mail, trend, retest, webhook | adapter e gate presenti, integrazione da completare |
| 3 – Threat Intelligence | AIL, OpenCTI/MISP, monitoraggio continuo, SIEM e ticketing | interfacce predisposte |

L'interpretazione AI si innesta a valle del motore: riceve il JSON gia'
normalizzato e sanitizzato e produce testo descrittivo. Non ha accesso agli
output grezzi ne' alla possibilita' di modificare punteggi.
