/** Inventario degli asset osservati.
 *
 *  La dashboard ne mostrava soltanto il conteggio. Un numero non e'
 *  verificabile: sapere che gli asset sono 47 non dice quali siano, chi li
 *  abbia trovati ne' se siano davvero dell'azienda. Questa pagina espone
 *  l'elenco con la provenienza, perche' la prima cosa che un analista
 *  controlla di un asset e' da dove salta fuori.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Asset, AssetSummary } from '../api/types';
import {
  Banner, Chip, ConfirmButton, Empty, OWNERSHIP_LABEL, Spinner, formatDate,
} from '../components/ui';

const TIPI: Record<string, string> = {
  domain: 'Dominio',
  subdomain: 'Sottodominio',
  ip_address: 'Indirizzo IP',
  network_range: 'Rete',
  asn: 'Sistema autonomo',
  web_service: 'Servizio web',
  mail_service: 'Servizio di posta',
  network_service: 'Servizio di rete',
  email_address: 'Indirizzo e-mail',
  brand: 'Marchio',
  certificate: 'Certificato',
};

/** Il colore accompagna sempre il testo: la proprieta' e' un ordinale, e i
 *  toni sono quelli gia' definiti nel foglio di stile — un tono inventato
 *  non ha regola CSS e ricadrebbe in silenzio sullo stile neutro. */
const TONO_PROPRIETA: Record<string, string> = {
  verified_owned: 'low', likely_owned: 'medium', unverified: 'info',
  third_party: 'high', excluded: 'info',
};

const PAGINA = 100;

function etichettaTipo(valore: string): string {
  return TIPI[valore] ?? valore;
}

/** Riassunto leggibile degli attributi tecnici, senza dover aprire il dettaglio. */
function sintesi(asset: Asset): string {
  const a = asset.attributes_json ?? {};
  const parti: string[] = [];

  if (typeof a.provider === 'string' && a.provider) parti.push(String(a.provider));
  else if (typeof a.asn_org === 'string' && a.asn_org) parti.push(String(a.asn_org));
  if (a.network_type === 'condivisa') parti.push('infrastruttura condivisa');
  if (typeof a.reverse_dns === 'string' && a.reverse_dns) parti.push(String(a.reverse_dns));
  if (typeof a.port === 'number') parti.push(`porta ${a.port}`);
  if (typeof a.status_code === 'number') parti.push(`HTTP ${a.status_code}`);
  if (typeof a.title === 'string' && a.title) parti.push(`«${a.title}»`);
  if (typeof a.breach_count === 'number' && a.breach_count > 0) {
    parti.push(`${a.breach_count} violazioni`);
  }
  if (Array.isArray(a.from_domains) && a.from_domains.length) {
    parti.push(`da ${(a.from_domains as string[]).join(', ')}`);
  } else if (typeof a.from_domain === 'string') {
    parti.push(`da ${a.from_domain}`);
  }

  const tecnologie = (asset.technologies_json ?? [])
    .map((t) => [t.name, t.version].filter(Boolean).join(' '))
    .filter(Boolean);
  if (tecnologie.length) parti.push(tecnologie.slice(0, 4).join(', '));

  return parti.join(' · ');
}

function Filtro({ etichetta, conteggi, valore, onCambia, etichette }: {
  etichetta: string;
  conteggi: Record<string, number>;
  valore: string;
  onCambia: (v: string) => void;
  etichette?: Record<string, string>;
}) {
  const voci = Object.entries(conteggi);
  if (!voci.length) return null;
  return (
    <label className="small">
      {etichetta}{' '}
      <select value={valore} onChange={(e) => onCambia(e.target.value)}>
        <option value="">tutti</option>
        {voci.map(([chiave, quanti]) => (
          <option key={chiave} value={chiave}>
            {etichette?.[chiave] ?? chiave} ({quanti})
          </option>
        ))}
      </select>
    </label>
  );
}

export default function Assets() {
  const { companyId = '' } = useParams();
  const [riepilogo, setRiepilogo] = useState<AssetSummary | null>(null);
  const [asset, setAsset] = useState<Asset[] | null>(null);
  const [totale, setTotale] = useState(0);
  const [pagina, setPagina] = useState(1);
  const [errore, setErrore] = useState<string | null>(null);

  const [tipo, setTipo] = useState('');
  const [proprieta, setProprieta] = useState('');
  const [strumento, setStrumento] = useState('');
  const [ricerca, setRicerca] = useState('');
  const [mostraScomparsi, setMostraScomparsi] = useState(false);
  const [mostraSintetici, setMostraSintetici] = useState(true);
  const [aperto, setAperto] = useState<string | null>(null);
  const [avviso, setAvviso] = useState<string | null>(null);

  const ricaricaRiepilogo = useCallback(() => {
    api.assetsSummary(companyId).then(setRiepilogo)
      .catch((e) => setErrore(String(e.message ?? e)));
  }, [companyId]);

  useEffect(ricaricaRiepilogo, [ricaricaRiepilogo]);

  const carica = useCallback(() => {
    const parametri: Record<string, string> = {
      page: String(pagina), page_size: String(PAGINA),
      include_disappeared: String(mostraScomparsi),
      include_synthetic: String(mostraSintetici),
    };
    if (tipo) parametri.asset_type = tipo;
    if (proprieta) parametri.ownership_status = proprieta;
    if (strumento) parametri.discovered_by = strumento;
    if (ricerca.trim()) parametri.q = ricerca.trim();
    api.assets(companyId, parametri)
      .then((p) => { setAsset(p.items); setTotale(p.total); })
      .catch((e) => setErrore(String(e.message ?? e)));
  }, [companyId, pagina, tipo, proprieta, strumento, ricerca, mostraScomparsi, mostraSintetici]);

  useEffect(() => {
    const attesa = window.setTimeout(carica, ricerca ? 250 : 0);
    return () => window.clearTimeout(attesa);
  }, [carica, ricerca]);

  // Un filtro nuovo su una pagina alta mostrerebbe una lista vuota anche con
  // risultati presenti: ogni cambio di filtro riporta alla prima pagina.
  useEffect(() => { setPagina(1); },
    [tipo, proprieta, strumento, ricerca, mostraScomparsi, mostraSintetici]);

  const pagine = Math.max(1, Math.ceil(totale / PAGINA));
  const filtrato = useMemo(
    () => Boolean(tipo || proprieta || strumento || ricerca.trim()),
    [tipo, proprieta, strumento, ricerca]);

  if (errore) return <Banner kind="danger">{errore}</Banner>;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Asset osservati</h1>
          <p className="sub">
            Tutto cio' che le scansioni hanno attribuito all'azienda, con la fonte che
            lo ha trovato.
          </p>
        </div>
      </div>

      {avviso && <Banner>{avviso}</Banner>}

      {(riepilogo?.synthetic ?? 0) > 0 && (
        <Banner kind="warning">
          <strong>{riepilogo!.synthetic} asset provengono da scansioni dimostrative.</strong>{' '}
          Sono dati sintetici generati per provare la piattaforma. Restano nell’inventario
          fra una scansione e l’altra, ma sono esclusi dai report delle scansioni reali.
          Un asset osservato anche da una scansione reale perde automaticamente questa
          marcatura.{' '}
          <ConfirmButton label={`Rimuovi i ${riepilogo!.synthetic} asset sintetici`}
                         confirmLabel="Confermi la rimozione?"
                         onConfirm={async () => {
                           const esito = await api.deleteSyntheticAssets(companyId);
                           setAvviso(`${esito.deleted} asset sintetici rimossi.`);
                           ricaricaRiepilogo();
                           carica();
                         }} />
        </Banner>
      )}

      {riepilogo && riepilogo.total > 0 && (
        <div className="card">
          <div className="section-head">
            <h2>Composizione</h2>
            <Chip tone="info">{riepilogo.total} asset</Chip>
          </div>
          <div className="toolbar">
            {Object.entries(riepilogo.by_type).map(([chiave, quanti]) => (
              <button key={chiave} className="btn btn--ghost btn--sm"
                      onClick={() => setTipo(tipo === chiave ? '' : chiave)}
                      aria-pressed={tipo === chiave}>
                {etichettaTipo(chiave)} <strong>{quanti}</strong>
              </button>
            ))}
          </div>
          {riepilogo.disappeared > 0 && (
            <p className="muted small" style={{ marginBottom: 0 }}>
              {riepilogo.disappeared} asset non sono piu' stati osservati nell'ultima
              scansione. Non vengono cancellati: un asset scomparso puo' essere un
              servizio dismesso oppure un servizio che non ha risposto, e sono due
              cose diverse.
            </p>
          )}
        </div>
      )}

      <div className="card">
        <div className="toolbar">
          <input type="search" value={ricerca} onChange={(e) => setRicerca(e.target.value)}
                 placeholder="Cerca per nome" style={{ minWidth: 220 }} />
          <Filtro etichetta="Tipo" conteggi={riepilogo?.by_type ?? {}} etichette={TIPI}
                  valore={tipo} onCambia={setTipo} />
          <Filtro etichetta="Proprieta’" conteggi={riepilogo?.by_ownership ?? {}}
                  etichette={OWNERSHIP_LABEL}
                  valore={proprieta} onCambia={setProprieta} />
          <Filtro etichetta="Trovato da" conteggi={riepilogo?.by_tool ?? {}}
                  valore={strumento} onCambia={setStrumento} />
          <label className="small">
            <input type="checkbox" checked={mostraScomparsi}
                   onChange={(e) => setMostraScomparsi(e.target.checked)} />
            {' '}mostra anche gli asset scomparsi
          </label>
          {(riepilogo?.synthetic ?? 0) > 0 && (
            <label className="small">
              <input type="checkbox" checked={mostraSintetici}
                     onChange={(e) => setMostraSintetici(e.target.checked)} />
              {' '}mostra anche gli asset dimostrativi
            </label>
          )}
        </div>

        {!asset ? <Spinner /> : asset.length === 0 ? (
          <Empty>
            {filtrato
              ? 'Nessun asset corrisponde ai filtri impostati.'
              : 'Nessun asset osservato: avvia una scansione per popolare l’inventario.'}
          </Empty>
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>Asset</th><th>Tipo</th><th>Proprieta’</th>
                    <th>Dettaglio</th><th>Trovato da</th><th>Ultima osservazione</th>
                  </tr>
                </thead>
                <tbody>
                  {asset.map((voce) => (
                    <tr key={voce.id}
                        onClick={() => setAperto(aperto === voce.id ? null : voce.id)}
                        style={{ cursor: 'pointer' }}>
                      <td>
                        <code>{voce.display_name}</code>
                        {voce.disappeared_at && <> <Chip tone="medium">scomparso</Chip></>}
                        {voce.from_mock_scan && <> <Chip tone="medium">dimostrativo</Chip></>}
                        {voce.excluded_from_rating && <> <Chip tone="info">escluso</Chip></>}
                        {aperto === voce.id && (
                          <div className="muted small" style={{ marginTop: 6 }}>
                            <div><strong>Chiave:</strong> <code>{voce.asset_key}</code></div>
                            {voce.ownership_reason && (
                              <div><strong>Proprieta’:</strong> {voce.ownership_reason}</div>
                            )}
                            {voce.exclusion_reason && (
                              <div><strong>Esclusione:</strong> {voce.exclusion_reason}</div>
                            )}
                            <div><strong>Prima osservazione:</strong> {formatDate(voce.first_seen_at)}</div>
                            {voce.attributes_json && Object.keys(voce.attributes_json).length > 0 && (
                              <pre style={{ whiteSpace: 'pre-wrap', marginTop: 6 }}>
                                {JSON.stringify(voce.attributes_json, null, 2)}
                              </pre>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="small">{etichettaTipo(voce.asset_type)}</td>
                      <td>
                        <Chip tone={TONO_PROPRIETA[voce.ownership_status] ?? 'info'}>
                          {OWNERSHIP_LABEL[voce.ownership_status] ?? voce.ownership_status}
                        </Chip>
                      </td>
                      <td className="small muted">{sintesi(voce) || '—'}</td>
                      <td className="small">{(voce.discovered_by_json ?? []).join(', ') || '—'}</td>
                      <td className="small muted">
                        {formatDate(voce.disappeared_at ?? voce.last_seen_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="toolbar" style={{ marginTop: 12, marginBottom: 0 }}>
              <span className="muted small">
                {totale} asset{filtrato ? ' con i filtri impostati' : ''}
                {pagine > 1 && ` · pagina ${pagina} di ${pagine}`}
              </span>
              {pagine > 1 && (
                <>
                  <button className="btn btn--ghost" disabled={pagina <= 1}
                          onClick={() => setPagina((p) => p - 1)}>Precedente</button>
                  <button className="btn btn--ghost" disabled={pagina >= pagine}
                          onClick={() => setPagina((p) => p + 1)}>Successiva</button>
                </>
              )}
            </div>
          </>
        )}
      </div>
    </>
  );
}
