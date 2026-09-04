/** Personalizzazione: marchio, logo, colore e testi inseriti nei report. */
import { useEffect, useRef, useState } from 'react';
import { ApiError, api, auth } from '../api/client';
import type { Branding } from '../api/types';
import { Banner, ConfirmButton, Field, Spinner } from '../components/ui';

function messaggio(errore: unknown): string {
  if (errore instanceof ApiError) return errore.message;
  return String((errore as Error)?.message ?? errore);
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
          <Field label="Nome del marchio" hint="compare in copertina e nell’intestazione">
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
        <Field label="Nota in copertina" hint="sotto la limitazione d’ambito">
          <textarea value={valori.report_footer_it ?? ''} onChange={aggiorna('report_footer_it')} />
        </Field>
        <Field label="Contatti" hint="sezione finale del report">
          <textarea value={valori.contact_block_it ?? ''} onChange={aggiorna('contact_block_it')} />
        </Field>
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
    </>
  );
}
