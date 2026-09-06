# Profili di scansione

Tre profili, con requisiti e limiti crescenti. Il profilo determina quali
strumenti possono essere eseguiti: un tool non elencato nel profilo non viene
istanziato, nemmeno se richiesto esplicitamente.

## Sintesi

| | Public Passive | Verified Standard | Verified Extended |
|---|---|---|---|
| Verifica del dominio | non richiesta | **richiesta** | **richiesta** |
| Autorizzazione formale | non richiesta | **richiesta** | **richiesta** |
| Whitelist esplicita | non richiesta | non richiesta | **richiesta** |
| Contatto diretto col target | no | HTTP/HTTPS e TLS | + porte e Nuclei |
| Strumenti disponibili | 10 | 15 | 17 |
| Uso tipico | pre-sales, prima analisi | valutazione periodica | verifica approfondita |

## 1. Public Passive Check

Utilizzabile senza alcuna autorizzazione perche' consulta esclusivamente
fonti pubbliche: non tocca l'infrastruttura del target.

**Fonti:** DNS pubblico, RDAP, Certificate Transparency, enumerazione passiva
dei sottodomini, classificazione degli indirizzi IP pubblici (reverse DNS e
rete RDAP), OSINT via SpiderFoot (solo moduli passivi), configurazione
e-mail pubblicata in DNS, leak site ransomware, fonti di data breach,
indirizzi e-mail esposti in violazioni (XposedOrNot), domini simili,
CISA KEV ed EPSS.

**Vietato:** port scanning, vulnerability scanning, brute force, crawling
aggressivo, tentativi di autenticazione, exploit, fuzzing, verifiche
intrusive.

Sull'assenza di risultati: un profilo passivo che non trova nulla produce una
confidence bassa (profondita' 0.45) e quindi, spesso, un rating provvisorio.
E' il comportamento voluto: non aver guardato non e' la stessa cosa che non
aver trovato.

## 2. Verified Standard Check

Richiede la verifica della proprieta' del dominio **e** un'autorizzazione
formale registrata che includa questo profilo.

**Aggiunge:** richieste HTTP/HTTPS normali, analisi degli header,
fingerprinting delle tecnologie, verifica dei certificati e della
configurazione TLS, OWASP ZAP Baseline, controllo STARTTLS, verifica dei
redirect, screenshot, validazione dei servizi web.

**Vietato:** port scanning, exploit, brute force, modifica di dati, fuzzing.

Su ZAP: e' ammesso **esclusivamente** ZAP Baseline. Full Scan e Active Scan
non sono attivabili da configurazione (`forbidden_modes` in
`config/tool_profiles.yaml`).

## 3. Verified Extended Check

Richiede verifica, autorizzazione **e** una whitelist esplicita di IP, domini
o URL approvati. Senza almeno una voce di perimetro attiva la scansione non
parte.

**Aggiunge:** port scanning controllato (Naabu, lista di porte predefinita,
rate limit prudenti), service discovery, Nuclei con template approvati,
validazione non invasiva delle vulnerabilita'.

**Vietato:** credential stuffing, password spraying, brute force, tentativi di
login, SQL injection attiva, denial of service, upload di file, esecuzione di
payload, modifica o cancellazione di dati, exploit distruttivi, scansione di
infrastrutture di terzi.

### Allowlist Nuclei

Nessun template viene eseguito se non e' in `config/nuclei_allowlist.yaml` con
`approved: true`. Ogni voce dichiara identificativo, versione, descrizione,
severita', tipo di richiesta, classificazione, timeout, numero massimo di
richieste e approvatore.

Sono esclusi per costruzione i template `network-raw`, `headless`, `code`,
`javascript`, `file` e `websocket`, e i tag `dos`, `fuzz`, `brute-force`,
`intrusive`, `rce`, `sqli`, `file-upload`, `default-login`, `exploit`,
`deserialization`.

### Nmap e la licenza

Naabu (MIT) e' preferito a Nmap: la Nmap Public Source License limita la
redistribuzione in prodotti commerciali. L'adapter Nmap resta previsto per
installazioni che dispongano di una licenza propria; l'alias di default punta
a Naabu.

## Il perimetro degli indirizzi IP

I domini in perimetro risolvono su indirizzi IP, e quegli indirizzi espongono
servizi. Non tutti sono pero' sondabili.

A ogni scansione, in **tutti** i profili, gli indirizzi raggiunti vengono
arricchiti con il reverse DNS e con la rete RDAP e classificati:

| Classificazione | Significato | Scansione attiva |
|---|---|---|
| Rete condivisa | edge di CDN o reverse proxy (Cloudflare, Akamai, Fastly...): risponde per molti clienti insieme | **mai**, in nessun profilo |
| Hosting | l'istanza e' del cliente, la rete e' del fornitore (AWS, Azure, OVH, Aruba...) | ammessa se autorizzata |
| Rete propria | assegnazione diretta o hosting dedicato | ammessa se autorizzata |

Gli indirizzi entrano nel perimetro come **inventario**, mai come autorizzati:
una scansione non puo' autorizzare se stessa. L'autorizzazione e' un atto
esplicito dell'analista, in *Gestione azienda → Perimetro di rete*, registrato
nel log di audit con l'identita' di chi l'ha compiuto. Il motivo non e'
formale: sondare porte su un indirizzo che non appartiene al cliente e' un
fatto di cui qualcuno deve rispondere.

Il rifiuto di autorizzare un indirizzo di CDN e' applicato dal server, non
dall'interfaccia: l'API risponde 409 anche a una richiesta costruita a mano.

Conseguenza pratica: nel profilo Extended il port scanning non parte finche'
nessun indirizzo e' autorizzato, e lo dichiara — «N indirizzi IP pubblici
individuati, nessuno coperto da un'autorizzazione esplicita» — invece di
risultare semplicemente senza rilievi.

### Naabu e le architetture arm64

Naabu non pubblica binari per linux/arm64 (usa libpcap tramite CGO): sulle
macchine Apple Silicon il binario non e' nel worker e il port scanning non
partiva mai, pur risultando il profilo completo.

`port_scan` fa la stessa cosa senza dipendenze native: una connessione TCP
completa verso ciascuna coppia indirizzo/porta, nessun raw socket, nessun
privilegio. Gira **solo quando Naabu non e' presente**, perche' i due
strumenti fanno lo stesso lavoro e le loro evidenze convergono sulla stessa
impronta: eseguirli entrambi raddoppierebbe le connessioni verso il cliente
per ottenere gli stessi rilievi.

## Da dove vengono gli indirizzi e-mail

La verifica sulle violazioni ha bisogno di indirizzi da cercare. Le fonti,
in ordine di affidabilita':

1. **Dichiarati nel perimetro** — voci di tipo «Indirizzo e-mail» in
   *Gestione azienda → Perimetro*. Non allargano il perimetro degli host.
2. **DMARC** — i tag `rua` e `ruf` del record `_dmarc`, quando puntano a una
   casella del dominio stesso.
3. **SOA** — il campo RNAME, dove la chiocciola e' scritta come punto.
4. **SpiderFoot** — i moduli di raccolta, se un'istanza e' configurata.

Le prime tre non richiedono nulla oltre al DNS pubblico. Gli indirizzi su
domini diversi da quelli in perimetro non vengono raccolti: un `rua` che punta
a un elaboratore DMARC di terzi e' un indirizzo del fornitore, non del cliente.

## Quanto puo' durare una scansione

`global_limits.max_wall_clock_seconds` in `config/tool_profiles.yaml` e' il
tetto complessivo. Superato, gli strumenti **non ancora avviati** non partono
piu': diventano lacune di copertura dichiarate, con il motivo scritto, e la
scansione si chiude. Uno strumento gia' in esecuzione non viene interrotto —
ha il proprio timeout — ma riceve al massimo il tempo che resta.

E' l'esito corretto: una copertura parziale e dichiarata vale piu' di una
completa che non arriva mai, e il confidence score tiene gia' conto delle
lacune.

Alcuni strumenti hanno anche un tetto proprio (`total_budget_seconds`), perche'
da soli consumerebbero tutto il tempo disponibile. testssl.sh e' il caso
tipico: prova centinaia di combinazioni di cifrari e protocolli, un host alla
volta, e su venticinque host supera le quattro ore.

### Scansioni rimaste aperte

Il tetto di tempo garantisce che la *pipeline* finisca, non che finisca il
processo che la ospita. Se il worker viene riavviato a meta' scansione, la
riga resta in uno stato non terminale e nessuno la chiude piu': l'azienda
resta bloccata e il messaggio riaccodato dal broker si ferma trovando lo
stato «in corso».

Una scansione e' considerata abbandonata quando la sua riga non cambia da
piu' del limite di tempo del task Celery, con un margine di dieci minuti.
Oltre quel limite Celery avrebbe comunque terminato il processo: se la riga
non e' cambiata, nessuno la sta eseguendo. Il margine evita di dichiarare
morta una scansione viva ma lenta, che aggiorna la riga solo al termine di
ogni strumento.

Viene chiusa come **fallita**, non annullata: nessuno l'ha interrotta, e' il
processo che se n'e' andato, e la distinzione conta nello storico.

## Gate di autorizzazione

```mermaid
flowchart TD
    START["Richiesta di scansione"] --> PERM{"L'utente ha il permesso<br/>per questo profilo?"}
    PERM -->|no| DENY1["403 · permesso mancante"]
    PERM -->|si| PASSIVE{"profilo passivo?"}
    PASSIVE -->|si| DOM{"almeno un dominio?"}
    DOM -->|no| DENY2["403 · perimetro assente"]
    DOM -->|si| OK["Scansione accodata"]
    PASSIVE -->|no| VER{"dominio verificato?"}
    VER -->|no| DENY3["403 · verifica richiesta"]
    VER -->|si| AUTH{"autorizzazione attiva,<br/>non scaduta, non revocata,<br/>che include il profilo?"}
    AUTH -->|no| DENY4["403 · autorizzazione mancante"]
    AUTH -->|si| EXT{"profilo esteso?"}
    EXT -->|no| OK
    EXT -->|si| WL{"whitelist esplicita?"}
    WL -->|no| DENY5["403 · whitelist richiesta"]
    WL -->|si| OK
```

Ogni rifiuto e' registrato nell'audit log come `scan_blocked`, con i motivi.
L'endpoint `GET /companies/{id}/scans/authorization-preview?profile=...`
restituisce lo stesso esito senza avviare nulla, cosi' l'interfaccia puo'
spiegare in anticipo cosa manca.

## Verifica della proprieta' del dominio

Quattro metodi, tutti tracciati:

| Metodo | Come funziona |
|---|---|
| `dns_txt` | record TXT temporaneo su `_defenix-verification.<dominio>` |
| `http_file` | file su `/.well-known/defenix-verification.txt`, senza seguire i redirect |
| `admin_email` | codice inviato a un indirizzo amministrativo del dominio (RFC 2142) |
| `manual_approval` | approvazione di un Platform Administrator, con riferimento del documento |

La sfida scade dopo 14 giorni e il numero di tentativi e' limitato. La
verifica HTTP non segue i redirect di proposito: un redirect potrebbe
spostare la prova su un host non controllato dall'organizzazione.

## Autorizzazione: cosa viene registrato

Come richiesto dalla sezione 4 della specifica: soggetto autorizzante e suo
ruolo, azienda, data e ora, perimetro autorizzato, profili concessi, data di
scadenza, esclusioni, riferimento al documento di autorizzazione e utente
della piattaforma che ha registrato la concessione.

Le autorizzazioni sono revocabili con motivazione obbligatoria; la revoca ha
effetto immediato sul gate.

## Limiti globali

Validi per qualunque strumento, indipendentemente dal profilo
(`global_limits` in `config/tool_profiles.yaml`):

| Limite | Valore |
|---|---|
| Target per esecuzione | 500 |
| Output massimo per tool | 50 MB |
| Durata massima | 3600 s |
| Esecuzioni concorrenti | 4 |
| Memoria per processo | 2048 MB |
| CPU per processo | 3000 s |
| Quota della directory temporanea | 512 MB |
