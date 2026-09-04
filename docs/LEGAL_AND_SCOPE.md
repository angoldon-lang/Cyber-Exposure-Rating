# Ambito, limiti e aspetti legali

## 1. Che cosa e' Defenix Exposure Rating

> **External Cyber Exposure Rating**: valutazione della sicurezza osservabile
> dall'esterno e dei rischi a cui l'organizzazione potrebbe essere esposta.

Questa formulazione va usata in ogni contesto commerciale e contrattuale.
Compare nell'interfaccia, in ogni report e nell'endpoint
`GET /api/v1/meta/disclaimer`.

## 2. Che cosa NON e'

Il prodotto **non** e', e non deve essere presentato come:

- un **penetration test** — non tenta di sfruttare le vulnerabilita' rilevate;
- un **vulnerability assessment completo** — non ha visibilita' interna e non
  esegue scansioni autenticate;
- una **certificazione di sicurezza** — non attesta conformita' a standard;
- una **garanzia** — un rating alto non garantisce l'assenza di compromissioni.

Dichiararlo diversamente in una proposta commerciale espone a responsabilita'
contrattuale.

## 3. Limiti della valutazione

Riportati in ogni report:

1. l'analisi si basa su informazioni osservabili dall'esterno e non sostituisce
   una verifica interna dei sistemi;
2. l'assenza di rilievi non costituisce prova di sicurezza: puo' dipendere
   dalla copertura degli strumenti impiegati;
3. i rilievi non confermati sono indicati come tali e non incidono sul punteggio;
4. le fonti pubbliche e i cataloghi di vulnerabilita' possono essere incompleti
   o aggiornati con ritardo;
5. gli asset di terzi (CDN, cloud, hosting condivisi, fornitori, SaaS) sono
   esclusi dal calcolo del rating;
6. la valutazione fotografa lo stato osservato alla data della rilevazione.

Il confidence score quantifica quanto questi limiti abbiano inciso sulla
singola valutazione. Sotto il 50% il rating e' dichiarato provvisorio.

## 4. Base giuridica delle attivita'

### 4.1 Public Passive Check

Consulta esclusivamente fonti pubbliche (DNS, RDAP, Certificate Transparency,
indici pubblici) senza contatto intrusivo con l'infrastruttura del target.
Nella maggior parte degli ordinamenti europei non richiede autorizzazione,
ma **e' buona prassi informare comunque l'organizzazione valutata**, sia per
correttezza sia perche' la valutazione risulta piu' utile se condivisa.

### 4.2 Verified Standard e Verified Extended

Comportano contatto diretto con i sistemi del target. In Italia l'accesso non
autorizzato a un sistema informatico e' sanzionato dall'**art. 615-ter c.p.**;
a livello europeo si applica la **Direttiva 2013/40/UE**.

Prima di eseguirli e' necessaria un'autorizzazione scritta che indichi:

- soggetto autorizzante, ruolo e legittimazione a impegnare l'organizzazione;
- perimetro autorizzato (domini, IP, reti, URL);
- profilo di scansione concesso;
- validita' temporale;
- esclusioni;
- riferimento del documento di autorizzazione.

La piattaforma registra tutti questi elementi e impedisce l'avvio della
scansione se manca anche uno solo dei requisiti.

### 4.3 Il caso dei fornitori

Un'autorizzazione del cliente **non** copre i sistemi dei suoi fornitori.
Se il cliente ospita servizi presso terzi, serve un'autorizzazione anche di
quei soggetti — oppure quegli asset restano `third_party` ed esclusi dal
rating. Il classificatore di ownership riconosce automaticamente i principali
provider CDN, cloud, hosting e SaaS.

## 5. Protezione dei dati personali

### 5.1 Ruoli GDPR

Nell'uso tipico AD Consulting/Defenix agisce come **responsabile del
trattamento** (art. 28 GDPR) per conto del cliente, che e' titolare. Serve un
accordo sul trattamento dei dati (DPA) che copra: indirizzi e-mail aziendali
rinvenuti in fonti pubbliche, riferimenti a data breach, metadati di
pubblicazioni ransomware, header e-mail forniti dal cliente.

### 5.2 Minimizzazione applicata

| Dato | Trattamento |
|---|---|
| Password da breach | **mai** memorizzate |
| Indirizzi e-mail | mascherati per default, in chiaro solo per ruoli autorizzati |
| Contenuti di leak | mai memorizzati: solo metadati |
| Header e-mail | conservati solo i campi di autenticazione |

### 5.3 Conservazione

Configurabile per categoria (`RetentionPolicy`). Valori predefiniti: evidenze
730 giorni, output grezzi 180, report 1825, audit log 3650. La cancellazione
e' applicata da un task periodico.

### 5.4 Dati di terzi

Le evidenze possono riguardare persone fisiche (indirizzi e-mail in un
breach). Il trattamento si fonda sull'interesse legittimo alla sicurezza
informatica, ma richiede minimizzazione, conservazione limitata e accesso
ristretto — tutte misure implementate.

## 6. Fonti dei dati: aspetti legali

| Fonte | Nota |
|---|---|
| Ransomware.live | espone metadati di pubblicazioni criminali; non si scaricano ne' conservano i contenuti dei leak |
| Have I Been Pwned | servizio commerciale con termini d'uso propri: verificare la licenza per uso commerciale |
| CISA KEV | pubblico dominio (governo USA) |
| FIRST EPSS | uso gratuito, verificare i termini FIRST per l'uso commerciale |
| Certificate Transparency | log pubblici |
| Fonti dark web | consultazione di indici pubblici; nessun accesso a servizi criminali, nessun acquisto di dati |

**La piattaforma non acquista dati rubati e non accede a servizi criminali.**
Consulta indici pubblici e API legittime.

## 7. Uso commerciale e licenze open source

`THIRD_PARTY_NOTICES.md` elenca ogni componente con licenza, modalita' d'uso e
rischi. I punti di attenzione:

- **testssl.sh (GPL-2.0):** invocato come processo esterno, non linkato, non
  ridistribuito in forma modificata. Uso conforme.
- **AIL Framework (AGPL-3.0):** previsto come servizio esterno separato,
  interrogato via rete. Nessun codice AIL incorporato.
- **Nmap (NPSL):** la licenza limita la redistribuzione commerciale. Il
  prodotto usa Naabu (MIT); l'adapter Nmap resta per chi abbia licenza propria.
- **Template Nuclei:** licenza distinta dal motore. Verificare i termini dei
  template distribuiti.

Un connettore open source non implica che la fonte sia gratuita: HIBP e
alcune fonti usate da SpiderFoot richiedono abbonamenti. La matrice di
copertura (`GET /api/v1/coverage-matrix`) distingue le fonti gratuite da
quelle commerciali.

## 8. Responsabilita' nella proposta commerciale

Da includere nei contratti:

1. la valutazione riflette lo stato osservato alla data indicata;
2. un rating alto non garantisce l'assenza di compromissioni;
3. la valutazione non sostituisce penetration test, vulnerability assessment
   ne' certificazioni;
4. il cliente e' responsabile dell'accuratezza del perimetro dichiarato;
5. il cliente garantisce di essere legittimato ad autorizzare i controlli sui
   sistemi indicati.

## 9. Separazione fra tecnica e commerciale

Le raccomandazioni tecniche e le proposte commerciali sono tenute distinte:
il catalogo delle remediation contiene entrambe in campi separati, e nel
report i servizi professionali compaiono in una sezione dedicata, dichiarata
come proposta commerciale.

Un rilievo tecnico non deve mai essere formulato per giustificare una
vendita: e' un requisito di correttezza professionale, oltre che la ragione
per cui il motore di scoring e' deterministico e ispezionabile.
