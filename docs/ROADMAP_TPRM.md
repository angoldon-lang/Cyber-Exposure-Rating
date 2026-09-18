# Dal Security Rating al TPRM

Questo documento misura la distanza fra cio' che la piattaforma fa oggi e un
**TPRM** (Third-Party Risk Management) vendibile a clienti paganti, e stima
il costo di percorrerla.

I numeri dell'inventario sono misurati sul repository, non ricordati. Le
stime di dimensione sono tarate sul codice esistente; la stima in token e'
la parte piu' debole e il § 6 dice perche'.

## 1. Che cosa c'e' oggi

| | |
|---|---|
| Codice Python (senza test) | 18.553 righe |
| Test | 8.335 righe, 774 test in 45 file |
| Frontend | 3.919 righe, 10 pagine |
| Configurazione versionata | 2.862 righe YAML |
| API | 71 endpoint, 8 router |
| Modello dati | 24 tabelle, 6 migrazioni |
| Motore di rating | 61 regole, 5 aree, 5 classi, 4 cap, 27 remediation |
| Raccolta | 28 strumenti, 3 profili, 20 servizi in compose |

In termini di mercato: e' un **motore di security rating esterno**, cioe' la
fetta che BitSight e SecurityScorecard vendono come «security ratings». E' il
pezzo piu' difficile da costruire ed e' fatto. Non e' il pezzo che il
compratore chiama «TPRM».

## 2. I blocchi di un TPRM, e dove siamo

| # | Blocco | Stato | Nota |
|---|---|---|---|
| 1 | Rating esterno continuo | **fatto** | l'asset della piattaforma |
| 2 | Anagrafica fornitori e ciclo di vita | assente | `Company` e' piatta: manca «fornitore *di chi*», criticita', referente interno, contratto, scadenze, on/offboarding |
| 3 | Questionari e assessment | assente | e' il cuore del TPRM: senza, e' uno scanner |
| 4 | Portale fornitore | assente | il fornitore deve rispondere e caricare evidenze da solo |
| 5 | Registro rischi e trattamento | parziale | il piano di rimedio si genera ma non si traccia: niente owner, scadenza, SLA, accettazione, riverifica |
| 6 | Monitoraggio ricorrente e allerta | quasi | `next_scan_due_at` si mostra ma nessuno lo aggiorna e niente lo fa scattare; nessun canale di notifica |
| 7 | Quarta parte e concentrazione | assente | ricavabile in gran parte dai dati gia' raccolti (ASN, hosting, CDN) |
| 8 | Mappatura normativa NIS2/DORA/GDPR/ISO | assente | e' la ragione per cui in Italia oggi si compra |
| 9 | Dati non-cyber sul fornitore | assente | salute finanziaria, visura, sanzioni, adverse media |
| 10 | Workflow, task, collaborazione | assente | assegnazioni, approvazioni, escalation, solleciti |
| 11 | Integrazioni | parziale | OIDC c'e'; mancano API pubblica, webhook, ticketing, SAML/SCIM |
| 12 | Commerciale multi-tenant | parziale | branding c'e'; mancano piani, quote, metering, self-service, gerarchia MSP |
| 13 | Maturita' di prodotto | debole | solo italiano, nessuna metrica/tracing, DR non provato, nessun pen test della piattaforma |

Un dato che pesa piu' di quanto sembri: in una scansione reale di settembre
2026, **7 strumenti su 28 risultavano «non attivo»** e l'affidabilita'
dichiarata era 61%. Sono connettori a pagamento o non configurati. Un cliente
che paga non accetta a lungo un voto con quella copertura — ed e' un gap di
approvvigionamento dati, non di codice.

## 3. Due traguardi distinti

### A — MVP vendibile come TPRM

Il minimo per firmare contratti ricorrenti invece di consulenze una tantum.

| Cosa | Righe stimate |
|---|---:|
| Anagrafica fornitori minima: criticita', referente, contratto, dati trattati | 1.200 |
| Motore questionari + portale fornitore (NIS2 art.21, GDPR art.28, custom, evidenze con scadenza) | 4.000 |
| Scansione ricorrente + notifiche (SMTP, digest, allerta su variazione) | 1.500 |
| Registro rischi: owner, scadenza, accettazione, riverifica | 1.500 |
| Cruscotto di portafoglio TPRM + report per fornitore | 1.000 |
| Piani e quote minime, onboarding | 800 |
| **Totale** | **≈ 10.000** |

### B — TPRM completo

| Cosa | Righe stimate |
|---|---:|
| Quarta parte e concentrazione | 1.500 |
| Framework normativi e mappatura controlli | 3.000 |
| Connettori dati non-cyber | 2.000 |
| Workflow, task, approvazioni | 2.500 |
| API pubblica, webhook, SAML/SCIM, ticketing | 2.500 |
| Multi-tenant commerciale, MSP, metering | 3.000 |
| i18n, osservabilita', DR, hardening, performance | 3.000 |
| Questionari avanzati (SIG, CAIQ, logica condizionale, benchmark) | 4.000 |
| **Totale** | **≈ 21.500** |

Insieme: **≈ 31.500 righe**, cioe' il raddoppio della base di codice attuale.

## 4. Ordine di esecuzione consigliato

Non l'ordine della tabella: l'ordine del rapporto valore/costo.

1. **Scansione ricorrente e notifiche** (1.500 righe). Oggi si vende una
   fotografia; con questo si vende un abbonamento. E' il cambiamento che
   trasforma il modello di ricavo, ed e' il piu' economico della lista.
2. **Criticita' del fornitore e referente interno** (600 righe). Piccolo, e
   senza di esso il portafoglio non si sa ordinare.
3. **Questionario e portale fornitore** (4.000 righe). Il pezzo grosso, ma e'
   quello che fa dire «e' un TPRM».
4. **Registro rischi con scadenze**. Chiude il cerchio: rilevo, chiedo,
   assegno, verifico.

Il blocco normativo (NIS2, DORA) va dopo il punto 3, non prima: senza
questionari non c'e' dove agganciare le evidenze di conformita'.

## 5. Quello che non si risolve scrivendo codice

- **Le fonti dati a pagamento** (HIBP, threat intelligence sulle credenziali,
  visure, sanzioni, adverse media): costo ricorrente. Sono 7 dei 28 strumenti
  oggi spenti.
- **Il pen test della piattaforma** e la strada verso ISO 27001: si vende
  sicurezza, verra' chiesto al primo cliente strutturato.
- **Legale**: DPA, elenco dei sub-responsabili, contratti, SLA.
- **Il contenuto dei questionari**: qualcuno deve scrivere e mantenere le
  domande NIS2/DORA e le mappature. E' lavoro di dominio, non di codice, ed e'
  meta' del valore percepito.

## 6. Stima in token, e quanto fidarsene

Il metodo non e' un parametro di listino: e' il consumo misurato su questo
stesso progetto.

- Riscrittura del rapporto esecutivo (≈1.500 righe nette: un YAML da 700, un
  modulo da 280, modello, CSS, test, piu' una dozzina di cicli di render e
  verifica) → ≈ 300k token.
- Copertina e quadrante del punteggio (≈400 righe nette con test e render) →
  ≈ 80k token.

Entrambi danno **≈ 200 token per riga consegnata**. L'intervallo di lavoro e'
150–400, perche' il contenuto (YAML, questionari, mappature) costa meno per
riga del codice, i sottosistemi nuovi costano di piu', e la caccia ai guasti
costa moltissimo per riga — la collisione dei binari `httpx` e il parser di
`testssl` sono costati centinaia di migliaia di token per poche decine di
righe.

| | Righe | Token (centrale) | Intervallo |
|---|---:|---:|---|
| A — MVP vendibile | 10.000 | 2,5 M | 1,5 – 4 M |
| B — completamento | 21.500 | 5,4 M | 3,2 – 8,6 M |
| Sovraccarico (analisi, revisione, rifacimenti) +30% | | 2,4 M | 1,4 – 3,8 M |
| **Totale** | ≈ 31.500 | **≈ 10 M** | **6 – 16 M** |

**Il limite di questa stima.** Il moltiplicatore e' tarato su un contatore di
sessione di cui non conosciamo la contabilita' esatta — se conti i soli token
nuovi o anche il contesto rimandato a ogni turno, e come tratti la cache. Il
rapporto fra i due blocchi misurati era coerente, quindi l'ordine di
grandezza regge; la cifra assoluta no. Va riverificata misurando il consumo
reale del primo blocco consegnato, e a quel punto smette di essere una
proiezione.

La voce piu' incerta resta il rifacimento. Sul rapporto per la direzione
abbiamo cambiato impostazione due volte — giustamente, perche' il documento
stampato si giudica solo stampato — e ogni giro e' costato. Su un motore di
questionari, dove l'interfaccia conta molto, i giri saranno di piu', non di
meno.
