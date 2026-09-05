/** Gestione completa di un'azienda: anagrafica, domini, autorizzazioni e
 *  perimetro. E' l'unico punto da cui si crea, si modifica e si cancella. */
import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ApiError, api } from '../api/client';
import type {
  Authorization, Company, CompanyInput, Domain, IPAddressEntry, NetworkRangeEntry, ScopeEntry,
} from '../api/types';
import {
  Banner, Chip, ConfirmButton, Empty, Field, Spinner, formatDate, formatDateTime,
} from '../components/ui';

const TIPI_PERIMETRO: Record<string, string> = {
  domain: 'Dominio',
  wildcard_domain: 'Dominio e sottodomini',
  ip_address: 'Indirizzo IP',
  cidr: 'Rete (CIDR)',
  url: 'URL',
  email_domain: 'Dominio e-mail',
};

const PROFILI: Record<string, string> = {
  public_passive: 'Public Passive Check',
  verified_standard: 'Verified Standard Check',
  verified_extended: 'Verified Extended Check',
};

const STATO_VERIFICA: Record<string, string> = {
  unverified: 'Non verificato',
  pending: 'In attesa',
  verified: 'Verificato',
  failed: 'Non riuscita',
  expired: 'Scaduta',
};

function messaggio(errore: unknown): string {
  if (errore instanceof ApiError) return errore.message;
  return String((errore as Error)?.message ?? errore);
}

/** Anagrafica: creazione e modifica condividono la stessa form. */
function SchedaAnagrafica({ azienda, onSalvata }: {
  azienda: Company | null;
  onSalvata: (azienda: Company) => void;
}) {
  const navigate = useNavigate();
  const [valori, setValori] = useState<CompanyInput>({
    legal_name: azienda?.legal_name ?? '',
    slug: azienda?.slug ?? '',
    vat_number: azienda?.vat_number ?? '',
    country: azienda?.country ?? 'IT',
    sector: azienda?.sector ?? '',
    size_band: azienda?.size_band ?? '',
    notes: azienda?.notes ?? '',
  });
  const [errore, setErrore] = useState<string | null>(null);
  const [esito, setEsito] = useState<string | null>(null);
  const [inCorso, setInCorso] = useState(false);

  const aggiorna = (campo: keyof CompanyInput) =>
    (evento: { target: { value: string } }) =>
      setValori((precedenti) => ({ ...precedenti, [campo]: evento.target.value }));

  async function salva() {
    setInCorso(true); setErrore(null); setEsito(null);
    try {
      const corpo = { ...valori, vat_number: valori.vat_number || null,
                      sector: valori.sector || null, size_band: valori.size_band || null,
                      notes: valori.notes || null };
      if (azienda) {
        // Lo slug identifica l'azienda in modo stabile: non viene inviato.
        const { slug: _ignorato, ...modificabili } = corpo;
        const aggiornata = await api.updateCompany(azienda.id, modificabili);
        onSalvata(aggiornata);
        setEsito('Modifiche salvate.');
      } else {
        const creata = await api.createCompany(corpo);
        navigate(`/aziende/${creata.id}/gestione`, { replace: true });
      }
    } catch (e) {
      setErrore(messaggio(e));
    } finally {
      setInCorso(false);
    }
  }

  const slugValido = /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(valori.slug);

  return (
    <div className="card">
      <div className="section-head">
        <h2>{azienda ? 'Anagrafica' : 'Nuova azienda'}</h2>
        {azienda && (
          <Chip tone={azienda.is_active ? 'low' : 'medium'}>
            {azienda.is_active ? 'Attiva' : 'Archiviata'}
          </Chip>
        )}
      </div>

      {errore && <Banner kind="danger">{errore}</Banner>}
      {esito && <Banner>{esito}</Banner>}

      <div className="form-grid">
        <Field label="Ragione sociale">
          <input type="text" value={valori.legal_name} onChange={aggiorna('legal_name')}
                 placeholder="ACME S.p.A." />
        </Field>
        <Field label="Identificativo breve (slug)"
               hint={azienda ? 'Non modificabile dopo la creazione' : 'minuscole e trattini'}
               error={valori.slug && !slugValido ? 'Ammessi solo minuscole, cifre e trattini' : null}>
          <input type="text" value={valori.slug} onChange={aggiorna('slug')}
                 disabled={Boolean(azienda)} placeholder="acme" />
        </Field>
        <Field label="Partita IVA">
          <input type="text" value={valori.vat_number ?? ''} onChange={aggiorna('vat_number')}
                 placeholder="IT01234567890" />
        </Field>
        <Field label="Paese" hint="codice ISO a due lettere">
          <input type="text" value={valori.country ?? ''} onChange={aggiorna('country')}
                 maxLength={2} placeholder="IT" />
        </Field>
        <Field label="Settore">
          <input type="text" value={valori.sector ?? ''} onChange={aggiorna('sector')}
                 placeholder="Manifatturiero" />
        </Field>
        <Field label="Dimensione">
          <select value={valori.size_band ?? ''} onChange={aggiorna('size_band')}>
            <option value="">—</option>
            <option value="1-9">1-9 addetti</option>
            <option value="10-49">10-49 addetti</option>
            <option value="50-249">50-249 addetti</option>
            <option value="250+">250 addetti o piu’</option>
          </select>
        </Field>
      </div>
      <Field label="Note">
        <textarea value={valori.notes ?? ''}
                  onChange={(e) => setValori((p) => ({ ...p, notes: e.target.value }))} />
      </Field>

      <div className="toolbar">
        <button className="btn" onClick={salva}
                disabled={inCorso || valori.legal_name.length < 2 || !slugValido}>
          {azienda ? 'Salva modifiche' : 'Crea azienda'}
        </button>
        {!azienda && (
          <button className="btn btn--ghost" onClick={() => navigate('/portfolio')}>Annulla</button>
        )}
      </div>
    </div>
  );
}

/** Domini dichiarati e stato della verifica di proprieta'. */
function SchedaDomini({ companyId, onCambio }: { companyId: string; onCambio: () => void }) {
  const [domini, setDomini] = useState<Domain[] | null>(null);
  const [nuovo, setNuovo] = useState('');
  const [errore, setErrore] = useState<string | null>(null);
  const [approvando, setApprovando] = useState<string | null>(null);
  const [approvatore, setApprovatore] = useState('');
  const [documento, setDocumento] = useState('');

  const ricarica = useCallback(() => {
    api.domains(companyId).then(setDomini).catch((e) => setErrore(messaggio(e)));
  }, [companyId]);
  useEffect(ricarica, [ricarica]);

  async function esegui(azione: () => Promise<unknown>) {
    setErrore(null);
    try { await azione(); ricarica(); onCambio(); }
    catch (e) { setErrore(messaggio(e)); }
  }

  return (
    <div className="card">
      <h2>Domini</h2>
      <p className="muted small">
        Nessuna scansione oltre il profilo passivo e’ possibile su un dominio non verificato.
      </p>
      {errore && <Banner kind="danger">{errore}</Banner>}

      <div className="toolbar">
        <input type="text" value={nuovo} onChange={(e) => setNuovo(e.target.value)}
               placeholder="esempio.it" style={{ minWidth: 240 }} />
        <button className="btn" disabled={nuovo.trim().length < 3}
                onClick={() => esegui(async () => {
                  await api.addDomain(companyId, { name: nuovo.trim(), is_primary: !domini?.length });
                  setNuovo('');
                })}>
          Aggiungi dominio
        </button>
      </div>

      {!domini ? <Spinner /> : domini.length === 0 ? (
        <Empty>Nessun dominio dichiarato.</Empty>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data">
            <thead>
              <tr>
                <th>Dominio</th><th>Principale</th><th>Verifica</th><th>Metodo</th>
                <th>Data</th><th />
              </tr>
            </thead>
            <tbody>
              {domini.map((dominio) => (
                <tr key={dominio.id}>
                  <td>{dominio.name}</td>
                  <td>{dominio.is_primary ? 'Si’' : '—'}</td>
                  <td>
                    <Chip tone={dominio.verification_status === 'verified' ? 'low' : 'medium'}>
                      {STATO_VERIFICA[dominio.verification_status] ?? dominio.verification_status}
                    </Chip>
                  </td>
                  <td className="small muted">{dominio.verification_method ?? '—'}</td>
                  <td className="small muted">{formatDate(dominio.verified_at)}</td>
                  <td>
                    <div className="row-actions">
                      {dominio.verification_status !== 'verified' && (
                        <button className="btn btn--ghost btn--sm"
                                onClick={() => setApprovando(
                                  approvando === dominio.id ? null : dominio.id)}>
                          Approva
                        </button>
                      )}
                      <ConfirmButton label="Rimuovi" confirmLabel="Rimuovo"
                                     onConfirm={() => esegui(
                                       () => api.deleteDomain(companyId, dominio.id))} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {approvando && (
        <div className="card" style={{ marginTop: 14 }}>
          <h3 style={{ marginTop: 0 }}>Approvazione manuale</h3>
          <p className="muted small">
            Riservata al Platform Administrator. Approvatore e documento restano
            nel registro di audit.
          </p>
          <div className="form-grid">
            <Field label="Nome dell’approvatore">
              <input type="text" value={approvatore}
                     onChange={(e) => setApprovatore(e.target.value)} />
            </Field>
            <Field label="Riferimento del documento" hint="contratto, ordine, e-mail firmata">
              <input type="text" value={documento}
                     onChange={(e) => setDocumento(e.target.value)} />
            </Field>
          </div>
          <div className="toolbar">
            <button className="btn"
                    disabled={approvatore.length < 2 || documento.length < 2}
                    onClick={() => esegui(async () => {
                      await api.approveDomain(companyId, approvando, {
                        approver_name: approvatore, document_reference: documento });
                      setApprovando(null); setApprovatore(''); setDocumento('');
                    })}>
              Conferma approvazione
            </button>
            <button className="btn btn--ghost" onClick={() => setApprovando(null)}>Annulla</button>
          </div>
        </div>
      )}
    </div>
  );
}

/** Autorizzazioni scritte e perimetro autorizzato. */
function SchedaAutorizzazioni({ companyId }: { companyId: string }) {
  const [elenco, setElenco] = useState<Authorization[] | null>(null);
  const [perimetro, setPerimetro] = useState<ScopeEntry[] | null>(null);
  const [errore, setErrore] = useState<string | null>(null);
  const [apertaForm, setApertaForm] = useState(false);
  const [voce, setVoce] = useState({ entry_type: 'domain', value: '', action: 'include', note: '' });
  const [nuova, setNuova] = useState({
    granting_subject_name: '', granting_subject_role: '', document_reference: '',
    valid_from: new Date().toISOString().slice(0, 10),
    expires_at: new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10),
    profili: ['public_passive', 'verified_standard'] as string[],
  });

  const ricarica = useCallback(() => {
    api.authorizations(companyId).then(setElenco).catch((e) => setErrore(messaggio(e)));
    api.scopes(companyId).then(setPerimetro).catch((e) => setErrore(messaggio(e)));
  }, [companyId]);
  useEffect(ricarica, [ricarica]);

  async function esegui(azione: () => Promise<unknown>) {
    setErrore(null);
    try { await azione(); ricarica(); } catch (e) { setErrore(messaggio(e)); }
  }

  return (
    <div className="card">
      <div className="section-head">
        <h2>Autorizzazioni e perimetro</h2>
        <button className="btn btn--ghost btn--sm" onClick={() => setApertaForm((v) => !v)}>
          {apertaForm ? 'Chiudi' : 'Nuova autorizzazione'}
        </button>
      </div>
      <p className="muted small">
        Il perimetro non viene mai esteso automaticamente verso CDN, cloud provider,
        hosting condiviso o servizi di terzi.
      </p>
      {errore && <Banner kind="danger">{errore}</Banner>}

      {apertaForm && (
        <div className="card" style={{ marginBottom: 14 }}>
          <div className="form-grid">
            <Field label="Soggetto autorizzante">
              <input type="text" value={nuova.granting_subject_name}
                     onChange={(e) => setNuova((p) => ({ ...p, granting_subject_name: e.target.value }))} />
            </Field>
            <Field label="Ruolo">
              <input type="text" value={nuova.granting_subject_role}
                     onChange={(e) => setNuova((p) => ({ ...p, granting_subject_role: e.target.value }))}
                     placeholder="Amministratore delegato" />
            </Field>
            <Field label="Valida dal">
              <input type="date" value={nuova.valid_from}
                     onChange={(e) => setNuova((p) => ({ ...p, valid_from: e.target.value }))} />
            </Field>
            <Field label="Scadenza">
              <input type="date" value={nuova.expires_at}
                     onChange={(e) => setNuova((p) => ({ ...p, expires_at: e.target.value }))} />
            </Field>
            <Field label="Riferimento del documento">
              <input type="text" value={nuova.document_reference}
                     onChange={(e) => setNuova((p) => ({ ...p, document_reference: e.target.value }))} />
            </Field>
          </div>
          <Field label="Profili autorizzati">
            <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
              {Object.entries(PROFILI).map(([chiave, etichetta]) => (
                <label key={chiave} className="small" style={{ fontWeight: 400 }}>
                  <input type="checkbox" checked={nuova.profili.includes(chiave)}
                         onChange={(e) => setNuova((p) => ({
                           ...p,
                           profili: e.target.checked
                             ? [...p.profili, chiave]
                             : p.profili.filter((x) => x !== chiave),
                         }))} />{' '}{etichetta}
                </label>
              ))}
            </div>
          </Field>
          <div className="toolbar">
            <button className="btn"
                    disabled={nuova.granting_subject_name.length < 2 || nuova.profili.length === 0}
                    onClick={() => esegui(async () => {
                      await api.createAuthorization(companyId, {
                        granting_subject_name: nuova.granting_subject_name,
                        granting_subject_role: nuova.granting_subject_role || null,
                        document_reference: nuova.document_reference || null,
                        valid_from: `${nuova.valid_from}T00:00:00Z`,
                        expires_at: `${nuova.expires_at}T00:00:00Z`,
                        allowed_profiles: nuova.profili,
                        scopes: [],
                      });
                      setApertaForm(false);
                    })}>
              Registra autorizzazione
            </button>
          </div>
        </div>
      )}

      {!elenco ? <Spinner /> : elenco.length === 0 ? (
        <Empty>Nessuna autorizzazione registrata.</Empty>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data">
            <thead>
              <tr><th>Soggetto</th><th>Profili</th><th>Validita’</th><th>Stato</th><th /></tr>
            </thead>
            <tbody>
              {elenco.map((autorizzazione) => (
                <tr key={autorizzazione.id}>
                  <td>
                    {autorizzazione.granting_subject_name}
                    {autorizzazione.granting_subject_role && (
                      <div className="small muted">{autorizzazione.granting_subject_role}</div>
                    )}
                  </td>
                  <td className="small">
                    {(autorizzazione.allowed_profiles_json ?? [])
                      .map((p) => PROFILI[p] ?? p).join(', ') || '—'}
                  </td>
                  <td className="small muted">
                    {formatDate(autorizzazione.valid_from)} – {formatDate(autorizzazione.expires_at)}
                  </td>
                  <td>
                    <Chip tone={autorizzazione.status === 'active' ? 'low' : 'medium'}>
                      {autorizzazione.status === 'active' ? 'Attiva' : autorizzazione.status}
                    </Chip>
                  </td>
                  <td>
                    <div className="row-actions">
                      {autorizzazione.status === 'active' && (
                        <ConfirmButton label="Revoca" confirmLabel="Revoco"
                                       onConfirm={() => esegui(() => api.revokeAuthorization(
                                         companyId, autorizzazione.id,
                                         'revoca richiesta dall’operatore'))} />
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3 style={{ marginTop: 20 }}>Perimetro</h3>
      <div className="toolbar">
        <select value={voce.entry_type}
                onChange={(e) => setVoce((p) => ({ ...p, entry_type: e.target.value }))}>
          {Object.entries(TIPI_PERIMETRO).map(([chiave, etichetta]) => (
            <option key={chiave} value={chiave}>{etichetta}</option>
          ))}
        </select>
        <input type="text" value={voce.value} placeholder="esempio.it"
               onChange={(e) => setVoce((p) => ({ ...p, value: e.target.value }))}
               style={{ minWidth: 220 }} />
        <select value={voce.action}
                onChange={(e) => setVoce((p) => ({ ...p, action: e.target.value }))}>
          <option value="include">Includi</option>
          <option value="exclude">Escludi</option>
        </select>
        <button className="btn" disabled={voce.value.trim().length === 0}
                onClick={() => esegui(async () => {
                  await api.addScope(companyId, {
                    entry_type: voce.entry_type, value: voce.value.trim(),
                    action: voce.action, note: voce.note || null });
                  setVoce({ entry_type: 'domain', value: '', action: 'include', note: '' });
                })}>
          Aggiungi
        </button>
      </div>

      {!perimetro ? <Spinner /> : perimetro.length === 0 ? (
        <Empty>Perimetro non ancora definito.</Empty>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data">
            <thead><tr><th>Tipo</th><th>Valore</th><th>Azione</th><th>Nota</th><th /></tr></thead>
            <tbody>
              {perimetro.map((entry) => (
                <tr key={entry.id}>
                  <td className="small">{TIPI_PERIMETRO[entry.entry_type] ?? entry.entry_type}</td>
                  <td className="tabular">{entry.value}</td>
                  <td>
                    <Chip tone={entry.action === 'include' ? 'low' : 'high'}>
                      {entry.action === 'include' ? 'Incluso' : 'Escluso'}
                    </Chip>
                  </td>
                  <td className="small muted">{entry.note ?? '—'}</td>
                  <td>
                    <div className="row-actions">
                      <ConfirmButton label="Rimuovi" confirmLabel="Rimuovo"
                                     onConfirm={() => esegui(
                                       () => api.deleteScope(companyId, entry.id))} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Archiviazione e cancellazione definitiva. */
function SchedaRete({ companyId }: { companyId: string }) {
  const [indirizzi, setIndirizzi] = useState<IPAddressEntry[] | null>(null);
  const [reti, setReti] = useState<NetworkRangeEntry[] | null>(null);
  const [nuovoIp, setNuovoIp] = useState('');
  const [nuovaRete, setNuovaRete] = useState('');
  const [errore, setErrore] = useState<string | null>(null);

  const ricarica = useCallback(() => {
    api.ips(companyId).then(setIndirizzi).catch((e) => setErrore(messaggio(e)));
    api.networks(companyId).then(setReti).catch((e) => setErrore(messaggio(e)));
  }, [companyId]);
  useEffect(ricarica, [ricarica]);

  async function esegui(azione: () => Promise<unknown>) {
    setErrore(null);
    try { await azione(); ricarica(); }
    catch (e) { setErrore(messaggio(e)); }
  }

  const candidati = (indirizzi ?? []).filter((i) => !i.authorized && !i.is_cdn);

  return (
    <div className="card">
      <h2>Perimetro di rete</h2>
      <p className="muted small">
        Gli indirizzi raggiunti dai domini in perimetro vengono scoperti a ogni scansione e
        aggiunti qui come inventario. Il port scanning del profilo Extended agisce solo su
        quelli autorizzati: l’autorizzazione e’ una decisione esplicita, registrata nel log
        di audit. Gli indirizzi di CDN e reverse proxy non sono autorizzabili, perche’
        rispondono per molti clienti insieme.
      </p>
      {errore && <Banner kind="danger">{errore}</Banner>}

      <div className="toolbar">
        <input type="text" value={nuovoIp} onChange={(e) => setNuovoIp(e.target.value)}
               placeholder="203.0.113.10" style={{ minWidth: 200 }} />
        <button className="btn" disabled={nuovoIp.trim().length < 2}
                onClick={() => esegui(async () => {
                  await api.addIp(companyId, { address: nuovoIp.trim() });
                  setNuovoIp('');
                })}>
          Aggiungi indirizzo
        </button>
        {candidati.length > 0 && (
          <button className="btn secondary"
                  onClick={() => esegui(async () => {
                    for (const voce of candidati) {
                      await api.setIpAuthorization(companyId, voce.id, true);
                    }
                  })}>
            Autorizza i {candidati.length} indirizzi non ancora autorizzati
          </button>
        )}
      </div>

      {!indirizzi ? <Spinner /> : indirizzi.length === 0 ? (
        <Empty>
          Nessun indirizzo IP nel perimetro. Vengono aggiunti automaticamente dalla prima
          scansione, oppure inseriti qui a mano.
        </Empty>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data">
            <thead>
              <tr>
                <th>Indirizzo</th><th>Rete</th><th>Reverse DNS</th>
                <th>Scansione attiva</th><th />
              </tr>
            </thead>
            <tbody>
              {indirizzi.map((voce) => (
                <tr key={voce.id}>
                  <td><code>{voce.address}</code></td>
                  <td>
                    {voce.cloud_provider ?? voce.asn_org ?? <span className="muted">n/d</span>}
                    {voce.is_cdn && <> <Chip tone="warn">CDN</Chip></>}
                  </td>
                  <td className="muted small">{voce.reverse_dns ?? '—'}</td>
                  <td>
                    {voce.is_cdn ? (
                      <span className="muted small">non autorizzabile</span>
                    ) : (
                      <label className="small">
                        <input type="checkbox" checked={voce.authorized}
                               onChange={(e) => esegui(() => api.setIpAuthorization(
                                 companyId, voce.id, e.target.checked))} />
                        {' '}{voce.authorized ? 'autorizzata' : 'non autorizzata'}
                      </label>
                    )}
                  </td>
                  <td>
                    <ConfirmButton label="Rimuovi" confirmLabel={`Rimuovere ${voce.address}?`}
                                   onConfirm={() => esegui(() => api.deleteIp(companyId, voce.id))} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3 style={{ marginTop: 20 }}>Reti autorizzate</h3>
      <p className="muted small">
        Una rete autorizzata copre tutti gli indirizzi che contiene, presenti e futuri.
        Il limite e’ /16.
      </p>
      <div className="toolbar">
        <input type="text" value={nuovaRete} onChange={(e) => setNuovaRete(e.target.value)}
               placeholder="203.0.113.0/24" style={{ minWidth: 200 }} />
        <button className="btn" disabled={nuovaRete.trim().length < 4}
                onClick={() => esegui(async () => {
                  await api.addNetwork(companyId, { cidr: nuovaRete.trim() });
                  setNuovaRete('');
                })}>
          Aggiungi rete
        </button>
      </div>
      {!reti ? <Spinner /> : reti.length === 0 ? (
        <Empty>Nessuna rete dichiarata.</Empty>
      ) : (
        <table className="data">
          <thead><tr><th>Rete</th><th>Descrizione</th><th /></tr></thead>
          <tbody>
            {reti.map((rete) => (
              <tr key={rete.id}>
                <td><code>{rete.cidr}</code></td>
                <td className="muted small">{rete.description ?? '—'}</td>
                <td>
                  <ConfirmButton label="Rimuovi" confirmLabel={`Rimuovere ${rete.cidr}?`}
                                 onConfirm={() => esegui(
                                   () => api.deleteNetwork(companyId, rete.id))} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}


function ZonaPericolosa({ azienda, onCambio }: {
  azienda: Company; onCambio: (azienda: Company | null) => void;
}) {
  const navigate = useNavigate();
  const [slug, setSlug] = useState('');
  const [motivo, setMotivo] = useState('');
  const [errore, setErrore] = useState<string | null>(null);
  const [esito, setEsito] = useState<string | null>(null);

  return (
    <div className="card">
      <h2>Ciclo di vita</h2>
      {errore && <Banner kind="danger">{errore}</Banner>}
      {esito && <Banner>{esito}</Banner>}

      <p className="small muted">
        L’archiviazione toglie l’azienda dagli elenchi operativi ma conserva scansioni,
        rilievi e report. E’ l’operazione da preferire a fine contratto.
      </p>
      <div className="toolbar">
        {azienda.is_active ? (
          <ConfirmButton label="Archivia azienda" confirmLabel="Archivio"
                         onConfirm={async () => {
                           try {
                             await api.archiveCompany(azienda.id);
                             onCambio({ ...azienda, is_active: false });
                             setEsito('Azienda archiviata.');
                           } catch (e) { setErrore(messaggio(e)); }
                         }} />
        ) : (
          <button className="btn" onClick={async () => {
            try {
              const riattivata = await api.updateCompany(azienda.id, { is_active: true });
              onCambio(riattivata);
              setEsito('Azienda riattivata.');
            } catch (e) { setErrore(messaggio(e)); }
          }}>
            Riattiva azienda
          </button>
        )}
      </div>

      <div className="danger-zone">
        <h3>Cancellazione definitiva</h3>
        <p className="small muted">
          Rimuove l’azienda e ogni dato collegato: domini, autorizzazioni, scansioni,
          evidenze, rilievi e report. <strong>L’operazione non e’ reversibile.</strong>{' '}
          Nel registro di audit restano la motivazione e il conteggio delle righe
          rimosse. Riservata al Platform Administrator.
        </p>
        <div className="form-grid">
          <Field label={`Digitare “${azienda.slug}” per confermare`}>
            <input type="text" value={slug} onChange={(e) => setSlug(e.target.value)} />
          </Field>
          <Field label="Motivazione" hint="resta nel registro di audit">
            <input type="text" value={motivo} onChange={(e) => setMotivo(e.target.value)}
                   placeholder="richiesta di cancellazione del cliente" />
          </Field>
        </div>
        <button className="btn btn--danger"
                disabled={slug !== azienda.slug || motivo.trim().length < 3}
                onClick={async () => {
                  setErrore(null);
                  try {
                    const esitoPurge = await api.purgeCompany(azienda.id, {
                      confirm_slug: slug, reason: motivo.trim() });
                    onCambio(null);
                    navigate('/portfolio', {
                      replace: true,
                      state: { messaggio: `Azienda cancellata: ${esitoPurge.total_rows} righe rimosse.` },
                    });
                  } catch (e) { setErrore(messaggio(e)); }
                }}>
          Cancella definitivamente
        </button>
      </div>
    </div>
  );
}

export default function CompanyManage() {
  const { companyId } = useParams();
  const nuova = !companyId || companyId === 'nuova';
  const [azienda, setAzienda] = useState<Company | null>(null);
  const [errore, setErrore] = useState<string | null>(null);
  const [versione, setVersione] = useState(0);

  useEffect(() => {
    if (nuova) { setAzienda(null); return; }
    api.company(companyId!).then(setAzienda).catch((e) => setErrore(messaggio(e)));
  }, [companyId, nuova, versione]);

  if (errore) return <Banner kind="danger">{errore}</Banner>;
  if (!nuova && !azienda) return <Spinner />;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>{nuova ? 'Nuova azienda' : azienda!.legal_name}</h1>
          <p className="sub">
            {nuova
              ? 'Anagrafica, poi domini, verifica e autorizzazione'
              : `Creata il ${formatDateTime(azienda!.created_at)}`}
          </p>
        </div>
      </div>

      <SchedaAnagrafica azienda={azienda} onSalvata={setAzienda} />

      {!nuova && azienda && (
        <>
          <SchedaDomini companyId={azienda.id} onCambio={() => setVersione((v) => v + 1)} />
          <SchedaAutorizzazioni companyId={azienda.id} />
          <SchedaRete companyId={azienda.id} />
          <ZonaPericolosa azienda={azienda} onCambio={(a) => a && setAzienda(a)} />
        </>
      )}
    </>
  );
}
