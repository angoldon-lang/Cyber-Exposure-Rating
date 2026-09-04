# Componenti di terze parti

Elenco dei componenti usati da Defenix Exposure Rating, con licenza, modalita'
d'uso, obblighi e rischi per un servizio commerciale.

**Principio applicato:** gli strumenti con licenza copyleft sono invocati come
**processi esterni** o **servizi di rete separati**, mai linkati nel codice
del prodotto e mai ridistribuiti in forma modificata.

Ultimo aggiornamento: settembre 2026. Verificare le licenze prima di ogni
rilascio: possono cambiare fra versioni.

---

## 1. Strumenti di scansione

### Subfinder
- **Versione:** 2.6.6 · **Licenza:** MIT
- **Repository:** <https://github.com/projectdiscovery/subfinder>
- **Uso:** binario invocato via subprocess nel worker
- **Obblighi:** conservare copyright e licenza
- **Redistribuzione:** consentita · **Rischio commerciale:** nessuno
- **Nota:** alcune fonti configurabili richiedono API key proprie

### HTTPX
- **Versione:** 1.6.9 · **Licenza:** MIT
- **Repository:** <https://github.com/projectdiscovery/httpx>
- **Uso:** binario invocato via subprocess · **Rischio:** nessuno

### Naabu
- **Versione:** 2.3.1 · **Licenza:** MIT
- **Repository:** <https://github.com/projectdiscovery/naabu>
- **Uso:** binario invocato via subprocess, solo nel profilo esteso
- **Rischio:** nessuno sul piano della licenza. Richiede `NET_RAW` per il SYN
  scan: rimuovibile se il profilo esteso non viene usato

### Nuclei
- **Versione:** 3.3.7 · **Licenza:** MIT (motore)
- **Repository:** <https://github.com/projectdiscovery/nuclei>
- **Uso:** binario invocato via subprocess, solo nel profilo esteso
- **Rischio: ATTENZIONE.** I **template** hanno licenza distinta dal motore.
  Alcuni sono soggetti a termini propri. Il prodotto usa un'allowlist di
  template esplicitamente approvati (`config/nuclei_allowlist.yaml`):
  **verificare la licenza di ogni template prima di aggiungerlo**

### testssl.sh
- **Versione:** v3.2.4 · **Licenza:** **GPL-2.0**
- **Repository:** <https://github.com/testssl/testssl.sh>
- **Uso:** script shell invocato come **processo esterno** via subprocess.
  Nessun linking, nessuna incorporazione nel codice Defenix
- **Obblighi:** conservare licenza e copyright; se lo script viene
  **modificato e ridistribuito**, le modifiche vanno rilasciate sotto GPL-2.0
- **Rischio commerciale: BASSO con l'uso attuale.** L'invocazione come
  processo separato non estende la GPL al prodotto (*mere aggregation*).
  Il rischio diventa **ALTO** se si modificasse lo script e lo si
  ridistribuisse senza rilasciare le modifiche
- **Regola operativa:** non modificare `testssl.sh`; se serve un
  comportamento diverso, adattare l'adapter Defenix

### OWASP Amass
- **Versione:** 4.2 · **Licenza:** Apache-2.0
- **Repository:** <https://github.com/owasp-amass/amass>
- **Uso:** binario invocato via subprocess, modalita' passiva
- **Obblighi:** conservare NOTICE e attribuzioni · **Rischio:** nessuno

### Nmap
- **Licenza:** **NPSL (Nmap Public Source License)**
- **Uso:** adapter previsto ma **non attivo per impostazione predefinita**
- **Rischio commerciale: ALTO.** La NPSL **non** e' una licenza open source
  approvata OSI e limita la ridistribuzione in prodotti commerciali; l'uso in
  un servizio a pagamento puo' richiedere una licenza OEM da Nmap Software LLC
- **Mitigazione adottata:** il prodotto usa **Naabu (MIT)**. L'alias di
  configurazione `nmap` punta a Naabu. L'adapter Nmap resta disponibile per
  installazioni con licenza propria

### OWASP ZAP
- **Versione:** 2.15 stable · **Licenza:** Apache-2.0
- **Uso:** immagine container ufficiale, solo modalita' **Baseline**
- **Rischio:** nessuno

### SpiderFoot
- **Versione:** 4.0 · **Licenza:** MIT
- **Repository:** <https://github.com/smicallef/spiderfoot>
- **Uso:** servizio esterno interrogato via API HTTP
- **Rischio: MEDIO sul piano dei costi, non della licenza.** Molte fonti
  usate dai moduli SpiderFoot **non sono gratuite**: richiedono API key con
  abbonamento e hanno limiti d'uso propri. Ogni modulo va valutato
  singolarmente; l'allowlist per profilo e' in `config/tool_profiles.yaml`

### DNSTwist
- **Versione:** 20240812 · **Licenza:** Apache-2.0
- **Uso:** libreria Python nel worker · **Rischio:** nessuno

### checkdmarc
- **Versione:** 5.7.4 · **Licenza:** Apache-2.0
- **Repository:** <https://github.com/domainaware/checkdmarc>
- **Uso:** libreria Python (con fallback nativo su dnspython)
- **Rischio:** nessuno

### AIL Framework (fase 3)
- **Licenza:** **AGPL-3.0**
- **Repository:** <https://github.com/ail-project/ail-framework>
- **Uso previsto:** **servizio esterno separato**, interrogato via API di rete
- **Rischio commerciale: ALTO se integrato male.** L'AGPL estende gli obblighi
  di rilascio del codice anche all'uso via rete **del software AGPL stesso**.
  Mantenere AIL come servizio distinto, con la propria interfaccia, non
  contamina il codice Defenix; **incorporarne il codice lo renderebbe soggetto
  ad AGPL**
- **Regola operativa:** nessun codice AIL nel prodotto; solo chiamate HTTP a
  un'istanza separata, dichiarata al cliente

---

## 2. Fonti di dati

| Fonte | Licenza / termini | Costo | Rischio |
|---|---|---|---|
| CISA KEV | pubblico dominio (governo USA) | gratuito | nessuno |
| FIRST EPSS | uso gratuito, termini FIRST | gratuito | **verificare i termini per l'uso commerciale** |
| NVD / CVE | pubblico dominio | gratuito | limiti di rate sulle API |
| Certificate Transparency (crt.sh) | log pubblici | gratuito | limiti di rate |
| RDAP | protocollo standard | gratuito | politiche per registro |
| Ransomware.live | progetto AGPL-3.0, API pubblica | gratuito | **uso dell'API, non del codice**; verificare i termini per l'uso commerciale |
| **Have I Been Pwned** | **servizio commerciale** | **a pagamento** | **NON open source.** Richiede abbonamento; i termini limitano la ridistribuzione dei dati |

> Un connettore open source **non** implica che la fonte sia gratuita.
> La matrice di copertura (`GET /api/v1/coverage-matrix`) distingue le fonti
> gratuite da quelle commerciali, ed e' riportata nei report.

---

## 3. Dipendenze del backend

| Componente | Versione | Licenza | Rischio |
|---|---|---|---|
| Python | 3.11 | PSF | nessuno |
| FastAPI | 0.115.6 | MIT | nessuno |
| Pydantic | 2.10.4 | MIT | nessuno |
| SQLAlchemy | 2.0.36 | MIT | nessuno |
| Alembic | 1.14.0 | MIT | nessuno |
| Celery | 5.4.0 | BSD-3 | nessuno |
| Redis (client) | 5.2.1 | MIT | nessuno |
| psycopg | 3.2.3 | LGPL-3.0 | **basso**: uso come libreria dinamica, nessuna modifica |
| httpx | 0.28.1 | BSD-3 | nessuno |
| dnspython | 2.7.0 | ISC | nessuno |
| PyYAML | 6.0.2 | MIT | nessuno |
| python-jose | 3.3.0 | MIT | nessuno |
| bcrypt | 4.2.1 | Apache-2.0 | nessuno |
| Jinja2 | 3.1.5 | BSD-3 | nessuno |
| **WeasyPrint** | 63.1 | **BSD-3** | nessuno (dalla 53 non e' piu' AGPL) |
| python-docx | 1.1.2 | MIT | nessuno |
| structlog | 24.4.0 | Apache-2.0 / MIT | nessuno |

## 4. Dipendenze del frontend

| Componente | Versione | Licenza | Rischio |
|---|---|---|---|
| React | 18.3.1 | MIT | nessuno |
| React Router | 6.28.0 | MIT | nessuno |
| **Recharts** | 2.13.3 | MIT | nessuno |
| TypeScript | 5.6.3 | Apache-2.0 | nessuno |
| Vite | 5.4.11 | MIT | nessuno |

## 5. Immagini container

| Immagine | Licenza | Nota |
|---|---|---|
| `python:3.11-slim-bookworm` | PSF + licenze Debian | base Debian, componenti GPL usati come sistema operativo |
| `postgres:16.6-alpine` | PostgreSQL License (BSD-like) | nessun rischio |
| `redis:7.4.1-alpine` | **RSALv2 / SSPLv1** dalla 7.4 | **verificare:** la licenza limita l'offerta di Redis *come servizio gestito a terzi*. L'uso interno come coda non e' interessato. Valutare Valkey (BSD) per eliminare il dubbio |
| `nginxinc/nginx-unprivileged` | BSD-2 | nessuno |
| `ghcr.io/zaproxy/zaproxy:stable` | Apache-2.0 | nessuno |
| `quay.io/keycloak/keycloak:26.0.7` | Apache-2.0 | nessuno |
| `golang:1.23.4-bookworm` | BSD-3 | solo build stage |

---

## 6. Sintesi dei rischi

| Rischio | Livello | Mitigazione adottata |
|---|---|---|
| Nmap NPSL in prodotto commerciale | **alto** | si usa Naabu (MIT); adapter Nmap non attivo |
| AIL AGPL-3.0 | **alto se incorporato** | servizio esterno separato, solo chiamate di rete |
| Licenze dei template Nuclei | **medio** | allowlist con approvazione esplicita per template |
| Costi delle fonti SpiderFoot | **medio** | allowlist per profilo; costi dichiarati nella matrice |
| HIBP a pagamento | **medio** | connettore opzionale, disattivato per impostazione predefinita |
| Licenza Redis 7.4 | **basso** | uso interno; Valkey come alternativa |
| testssl.sh GPL-2.0 | **basso** | processo esterno, mai modificato |
| psycopg LGPL-3.0 | **basso** | libreria dinamica non modificata |

## 7. SBOM

```bash
make sbom    # genera sbom-backend.json e sbom-frontend.json (CycloneDX)
```

Da rigenerare a ogni rilascio e conservare insieme all'artefatto distribuito.

## 8. Manutenzione di questo documento

Va aggiornato quando si aggiunge una dipendenza, si cambia versione di un
componente con licenza a rischio, si aggiunge un template Nuclei o una fonte
dati. Le licenze cambiano: Redis e WeasyPrint ne sono esempi recenti.
