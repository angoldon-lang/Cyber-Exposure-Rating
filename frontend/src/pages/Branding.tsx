/** Personalizzazione: marchio, logo, colore e testi inseriti nei report. */
import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, api, auth } from '../api/client';
import type { Branding, ToolRequirement, ToolStatusResponse } from '../api/types';
import { Banner, Chip, ConfirmButton, Field, Spinner } from '../components/ui';

function messaggio(errore: unknown): string {
  if (errore instanceof ApiError) return errore.message;
  return String((errore as Error)?.message ?? errore);
}

/** Cosa manca a ciascuno strumento per funzionare.
 *
 *  Il motivo per cui uno strumento resta saltato compariva solo nel log del
 *  worker. Chi deve porvi rimedio ha bisogno di sapere quale variabile
 *  impostare, se la fonte costi qualcosa e dove procurarsi la chiave: tre
 *  cose che non erano scritte da nessuna parte.
 */
/** Un requisito, con il campo per soddisfarlo.
 *
 *  La versione precedente descriveva soltanto cosa serviva: per impostarlo
 *  bisognava comunque accedere al server e modificare `.env`. Chi usa la
 *  piattaforma non ha necessariamente quell'accesso.
 */
function CampoRequisito({ requisito, salvabile, onFatto }: {
  requisito: ToolRequirement;
  salvabile: boolean;
  onFatto: () => void;
}) {
  const [valore, setValore] = useState('');
  const [inCorso, setInCorso] = useState(false);
  const [errore, setErrore] = useState<string | null>(null);

  async function esegui(azione: () => Promise<unknown>) {
    setInCorso(true); setErrore(null);
    try { await azione(); setValore(''); onFatto(); }
    catch (e) { setErrore(messaggio(e)); }
    finally { setInCorso(false); }
  }

  return (
    <div style={{ marginBottom: 12 }}>
      <label className="small" style={{ display: 'block', marginBottom: 3 }}>
        {requisito.label ?? requisito.variable}
        {!requisito.free && <> <Chip tone="medium">a pagamento</Chip></>}
        {requisito.present && (
          <> <Chip tone="low">
            {requisito.source === 'ambiente' ? 'impostata nel file .env' : 'impostata'}
          </Chip></>
        )}
      </label>
      {requisito.note && <p className="muted small" style={{ margin: '0 0 5px' }}>
        {requisito.note}
        {requisito.where && (
          <> <a href={requisito.where} target="_blank" rel="noreferrer">
            {requisito.free ? 'documentazione' : 'come ottenere la chiave'}
          </a></>
        )}
      </p>}
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <input
          type={requisito.secret ? 'password' : 'text'}
          value={valore}
          onChange={(e) => setValore(e.target.value)}
          autoComplete="off"
          placeholder={requisito.present
            ? (requisito.secret ? 'valore conservato — scriverne uno nuovo per sostituirlo'
                                : 'valore conservato — scriverne uno nuovo per sostituirlo')
            : requisito.variable}
          style={{ minWidth: 320, flex: 1 }} />
        <button className="btn" disabled={!valore.trim() || inCorso || !salvabile}
                onClick={() => esegui(() => api.setToolSetting(requisito.variable, valore.trim()))}>
          Salva
        </button>
        {requisito.present && requisito.source === 'interfaccia' && (
          <ConfirmButton label="Rimuovi" confirmLabel="Rimuovo"
                         onConfirm={() => esegui(() => api.clearToolSetting(requisito.variable))} />
        )}
      </div>
      {errore && <p className="small" style={{ color: 'var(--danger, #b42318)', margin: '4px 0 0' }}>
        {errore}
      </p>}
      {requisito.secret && (
        <p className="muted small" style={{ margin: '4px 0 0' }}>
          Il valore viene cifrato e non e&rsquo; piu&rsquo; leggibile
          dall&rsquo;interfaccia: per cambiarlo si sostituisce.
        </p>
      )}
    </div>
  );
}

/** Cosa manca a ciascuno strumento, e il modo di fornirlo. */
function SchedaStrumenti() {
  const [stato, setStato] = useState<ToolStatusResponse | null>(null);
  const [errore, setErrore] = useState<string | null>(null);

  const carica = useCallback(() => {
    api.toolStatus().then(setStato).catch((e) => setErrore(messaggio(e)));
  }, []);
  useEffect(carica, [carica]);

  if (errore) return <Banner kind="danger">{errore}</Banner>;
  if (!stato) return <div className="card"><Spinner /></div>;

  const strumenti = stato.tools;
  const daSistemare = strumenti.filter((s) => !s.configured);
  const inAttesaDiUnDato = strumenti.filter((s) => s.configured && s.kind === 'uso');

  return (
    <div className="card">
      <div className="section-head">
        <h2>Strumenti</h2>
        <Chip tone={daSistemare.length ? 'medium' : 'low'}>
          {strumenti.length - daSistemare.length} su {strumenti.length} pronti
        </Chip>
      </div>
      <p className="muted small">
        Uno strumento non configurato non falsa il rating: riduce
        l&rsquo;affidabilita&rsquo; dichiarata della rilevazione, e l&rsquo;area che
        copriva risulta non verificata.
      </p>

      {!stato.can_store && (
        <Banner kind="danger">
          {stato.storage_reason ?? 'I valori non possono essere conservati.'}
        </Banner>
      )}

      {daSistemare.length === 0 ? (
        <p className="muted small" style={{ marginBottom: 0 }}>
          Tutti gli strumenti disponibili sono configurati.
        </p>
      ) : (
        daSistemare.map((strumento) => (
          <div key={strumento.key} style={{ borderTop: '1px solid var(--line)', paddingTop: 12,
                                            marginTop: 12 }}>
            <h3 style={{ margin: '0 0 4px', fontSize: 14 }}>{strumento.label}</h3>
            {strumento.kind === 'immagine' ? (
              <p className="muted small" style={{ margin: 0 }}>{strumento.reason}</p>
            ) : strumento.requirements.length === 0 ? (
              <p className="muted small" style={{ margin: 0 }}>{strumento.reason}</p>
            ) : (
              strumento.requirements.map((requisito) => (
                <CampoRequisito key={requisito.variable} requisito={requisito}
                                salvabile={stato.can_store} onFatto={carica} />
              ))
            )}
          </div>
        ))
      )}

      <p className="muted small" style={{ marginBottom: 0, marginTop: 12 }}>
        I valori salvati qui hanno la precedenza su quelli del file
        <code> .env</code> e valgono dalla scansione successiva, senza riavviare
        nulla. Quelli marcati «impostata nel file .env» si cambiano sul server.
      </p>

      {inAttesaDiUnDato.length > 0 && (
        <>
          <div className="section-head" style={{ marginTop: 18 }}>
            <h3 style={{ margin: 0 }}>Pronti, in attesa di un dato</h3>
          </div>
          <p className="muted small">
            Installati e senza configurazione: restano inattivi finche&rsquo; non
            ricevono qualcosa dalla scansione. Se compaiono come «saltati» nel
            registro, la causa e&rsquo; qui, non nel file <code>.env</code>.
          </p>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {inAttesaDiUnDato.map((strumento) => (
              <li key={strumento.key} style={{ marginBottom: 6 }}>
                <strong>{strumento.label}</strong> — {strumento.reason}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}


export default function BrandingPage() {
  const [valori, setValori] = useState<Branding | null>(null);
  const [errore, setErrore] = useState<string | null>(null);
  const [esito, setEsito] = useState<string | null>(null);
  const [inCorso, setInCorso] = useState(false);
  const [logoSrc, setLogoSrc] = useState<string | null>(null);
  const inputFile = useRef<HTMLInputElement>(null);

  /** Il logo e' protetto da autenticazione: va scaricato con il token e
   *  mostrato da un oggetto blob, non da un `src` diretto. */
  async function caricaAnteprima() {
    try {
      const headers = new Headers();
      if (auth.token) headers.set('Authorization', `Bearer ${auth.token}`);
      const risposta = await fetch(api.logoUrl(), { headers });
      if (!risposta.ok) { setLogoSrc(null); return; }
      setLogoSrc(URL.createObjectURL(await risposta.blob()));
    } catch { setLogoSrc(null); }
  }

  useEffect(() => {
    api.branding()
      .then((b) => { setValori(b); if (b.has_logo) caricaAnteprima(); })
      .catch((e) => setErrore(messaggio(e)));
  }, []);

  // L'URL dell'oggetto blob va revocato, altrimenti resta allocato.
  useEffect(() => () => { if (logoSrc) URL.revokeObjectURL(logoSrc); }, [logoSrc]);

  if (errore && !valori) return <Banner kind="danger">{errore}</Banner>;
  if (!valori) return <Spinner />;

  const aggiorna = (campo: keyof Branding) => (evento: { target: { value: string } }) =>
    setValori((precedenti) => (precedenti ? { ...precedenti, [campo]: evento.target.value } : precedenti));

  const coloreValido = !valori.primary_color
    || /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(valori.primary_color);

  async function salva() {
    setInCorso(true); setErrore(null); setEsito(null);
    try {
      const salvato = await api.updateBranding({
        brand_name: valori!.brand_name || null,
        brand_owner: valori!.brand_owner || null,
        primary_color: valori!.primary_color || null,
        report_intro_it: valori!.report_intro_it || null,
        report_footer_it: valori!.report_footer_it || null,
        contact_block_it: valori!.contact_block_it || null,
        show_context_section: valori!.show_context_section,
      });
      setValori({ ...salvato, has_logo: valori!.has_logo });
      setEsito('Personalizzazione salvata. Vale per i report generati d’ora in poi.');
    } catch (e) { setErrore(messaggio(e)); } finally { setInCorso(false); }
  }

  async function inviaLogo(file: File) {
    setErrore(null); setEsito(null);
    try {
      const salvato = await api.uploadLogo(file);
      setValori(salvato);
      await caricaAnteprima();
      setEsito('Logo caricato.');
    } catch (e) { setErrore(messaggio(e)); }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Personalizzazione</h1>
          <p className="sub">Marchio, logo e testi inseriti nei report</p>
        </div>
      </div>

      {errore && <Banner kind="danger">{errore}</Banner>}
      {esito && <Banner>{esito}</Banner>}

      <div className="card">
        <h2>Marchio</h2>
        <div className="form-grid">
          <Field label="Nome del marchio" hint="compare nella testata e nel titolo del report">
            <input type="text" value={valori.brand_name ?? ''} onChange={aggiorna('brand_name')}
                   placeholder="Defenix" />
          </Field>
          <Field label="Prodotto da" hint="chi emette il documento">
            <input type="text" value={valori.brand_owner ?? ''} onChange={aggiorna('brand_owner')}
                   placeholder="AD Consulting" />
          </Field>
          <Field label="Colore principale" hint="notazione esadecimale, es. #1f4e79"
                 error={coloreValido ? null : 'Formato non valido: usare #rgb o #rrggbb'}>
            <input type="text" value={valori.primary_color ?? ''}
                   onChange={aggiorna('primary_color')} placeholder="#1f4e79" />
          </Field>
        </div>
      </div>

      <div className="card">
        <h2>Logo</h2>
        <p className="muted small">
          PNG o JPEG, fino a 2&nbsp;MB. Gli SVG non sono accettati: sono documenti
          che possono contenere script, e il logo finisce in report distribuiti a terzi.
        </p>
        {logoSrc && (
          <div style={{ margin: '10px 0', padding: 12, background: 'var(--surface-2)',
                        borderRadius: 6, display: 'inline-block' }}>
            <img src={logoSrc} alt="Logo attuale" style={{ maxHeight: 60, maxWidth: 240 }} />
          </div>
        )}
        <div className="toolbar">
          <input ref={inputFile} type="file" accept="image/png,image/jpeg"
                 style={{ display: 'none' }}
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) inviaLogo(f); }} />
          <button className="btn" onClick={() => inputFile.current?.click()}>
            {valori.has_logo ? 'Sostituisci logo' : 'Carica logo'}
          </button>
          {valori.has_logo && (
            <ConfirmButton label="Rimuovi logo" confirmLabel="Rimuovo"
                           onConfirm={async () => {
                             try {
                               await api.deleteLogo();
                               setValori({ ...valori, has_logo: false, logo_filename: null });
                               setLogoSrc(null);
                               setEsito('Logo rimosso.');
                             } catch (e) { setErrore(messaggio(e)); }
                           }} />
          )}
        </div>
      </div>

      <div className="card">
        <h2>Testi dei report</h2>
        <Field label="Introduzione" hint="apre la sintesi per la direzione">
          <textarea value={valori.report_intro_it ?? ''} onChange={aggiorna('report_intro_it')} />
        </Field>
        <Field label="Nota finale" hint="in fondo, nella nota metodologica">
          <textarea value={valori.report_footer_it ?? ''} onChange={aggiorna('report_footer_it')} />
        </Field>
        <Field label="Contatti" hint="sezione «Il passo successivo», in fondo al report">
          <textarea value={valori.contact_block_it ?? ''} onChange={aggiorna('contact_block_it')} />
        </Field>
        <label className="small" style={{ display: 'flex', gap: 8, alignItems: 'flex-start',
                                          margin: '10px 0 4px' }}>
          <input type="checkbox" checked={valori.show_context_section}
                 style={{ marginTop: 3 }}
                 onChange={(e) => setValori((p) => (p ? {
                   ...p, show_context_section: e.target.checked } : p))} />
          <span>
            <strong>Sezione di contesto in apertura</strong>
            <br />
            <span className="muted">
              Due pagine con i dati di settore che spiegano perche&rsquo;
              l&rsquo;esposizione esterna vada misurata, prima della sintesi per la
              direzione. Compare solo nel rapporto esecutivo. Da togliere quando il
              destinatario quel contesto lo ha gia&rsquo;.
            </span>
          </span>
        </label>
        <div className="toolbar">
          <button className="btn" onClick={salva} disabled={inCorso || !coloreValido}>
            Salva personalizzazione
          </button>
        </div>
        <p className="muted small" style={{ marginBottom: 0 }}>
          Il testo inserito viene sanificato e inserito come testo semplice: eventuale
          markup non viene interpretato.
        </p>
      </div>

      <SchedaStrumenti />
    </>
  );
}
