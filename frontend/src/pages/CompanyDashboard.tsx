import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ApiError, api } from '../api/client';
import type { AuthorizationPreview, DashboardOverview, ScanProfile } from '../api/types';
import { CategoryBars, CategoryRadar, RatingGauge, SeverityBars, TrendChart } from '../components/charts';
import { Banner, Chip, Empty, Spinner, StatTile, formatDateTime } from '../components/ui';

const PROFILE_LABEL: Record<ScanProfile, string> = {
  public_passive: 'Public Passive Check',
  verified_standard: 'Verified Standard Check',
  verified_extended: 'Verified Extended Check',
};

export default function CompanyDashboard() {
  const { companyId = '' } = useParams();
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [profile, setProfile] = useState<ScanProfile>('public_passive');
  const [preview, setPreview] = useState<AuthorizationPreview | null>(null);
  const [starting, setStarting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    setData(null);
    api.dashboard(companyId).then(setData).catch((e) => setError(String(e.message ?? e)));
  }, [companyId]);

  useEffect(() => {
    api.authorizationPreview(companyId, profile).then(setPreview).catch(() => setPreview(null));
  }, [companyId, profile]);

  async function startScan() {
    setStarting(true);
    setNotice(null);
    try {
      await api.startScan(companyId, profile);
      setNotice('Scansione accodata. L’avanzamento e’ visibile nella sezione Scansioni.');
    } catch (exc) {
      setNotice(exc instanceof ApiError ? `Avvio rifiutato: ${exc.message}` : 'Avvio non riuscito');
    } finally {
      setStarting(false);
    }
  }

  if (error) return <Banner kind="danger">{error}</Banner>;
  if (!data) return <Spinner />;

  const assets = data.assets ?? {};
  const darkweb = data.darkweb ?? {};
  const review = data.review_progress ?? {};
  const criticalPending = Number(review.critical_high_pending ?? 0);

  return (
    <>
      <div className="topbar">
        <div>
          <h1>{data.company_name}</h1>
          <p className="sub">
            {data.last_scan
              ? <>Ultima scansione: {PROFILE_LABEL[(data.last_scan.profile as ScanProfile)] ?? '—'} ·{' '}
                  {formatDateTime(data.last_scan.finished_at as string)}
                  {data.last_scan.mock_mode ? ' · dati sintetici' : ''}</>
              : 'Nessuna scansione eseguita'}
          </p>
        </div>
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <Link className="btn btn--ghost" to={`/aziende/${companyId}/gestione`}>
            Gestisci azienda
          </Link>
          <select value={profile} aria-label="Profilo di scansione"
                  onChange={(e) => setProfile(e.target.value as ScanProfile)}>
            {(Object.keys(PROFILE_LABEL) as ScanProfile[]).map((key) => (
              <option key={key} value={key}>{PROFILE_LABEL[key]}</option>
            ))}
          </select>
          <button className="btn" onClick={startScan}
                  disabled={starting || (preview ? !preview.allowed : false)}>
            {starting ? 'Avvio…' : 'Avvia scansione'}
          </button>
        </div>
      </div>

      {notice && <Banner kind={notice.startsWith('Avvio rifiutato') ? 'warning' : 'info'}>{notice}</Banner>}

      {preview && !preview.allowed && (
        <Banner kind="warning">
          <strong>Il profilo «{PROFILE_LABEL[profile]}» non e’ avviabile.</strong>
          <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
            {preview.reasons.map((reason) => <li key={reason}>{reason}</li>)}
          </ul>
        </Banner>
      )}

      {data.is_provisional && (
        <Banner kind="warning">
          <strong>{data.provisional_notice}</strong>{' '}
          L’affidabilita’ della rilevazione ({data.confidence?.toFixed(0)}%) e’ sotto la soglia
          minima: i rilievi restano validi, ma il punteggio complessivo non e’ rappresentativo.
        </Banner>
      )}

      {criticalPending > 0 && (
        <Banner kind="warning">
          {criticalPending} rilievi critici o alti attendono la validazione di un analista.
          Il report definitivo non e’ emettibile finche’ la revisione non e’ completa.
        </Banner>
      )}

      <div className="grid cols-3" style={{ marginBottom: 14 }}>
        <div className="card">
          <h2>Rating complessivo</h2>
          <RatingGauge score={data.overall_score} ratingClass={data.rating_class}
                       label={data.rating_label_it} provisional={data.is_provisional} />
        </div>
        <div className="card" style={{ gridColumn: 'span 2' }}>
          <h2>Punteggio per area tematica</h2>
          <CategoryBars categories={data.categories} />
        </div>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 14 }}>
        <StatTile label="Affidabilita’ rilevazione"
                  value={data.confidence !== null ? `${data.confidence.toFixed(0)}%` : '—'}
                  hint={data.confidence_label_it} />
        <StatTile label="Asset osservati" value={assets.total ?? 0}
                  hint={`${assets.verified_owned ?? 0} verificati · ${assets.third_party ?? 0} di terzi (esclusi)`} />
        <StatTile label="Rilievi critici" value={data.severity_counts?.critical ?? 0}
                  tone={(data.severity_counts?.critical ?? 0) > 0 ? 'var(--status-critical)' : undefined}
                  hint={`${data.severity_counts?.high ?? 0} di severita’ alta`} />
        <StatTile label="Remediation aperte" value={data.open_remediations}
                  hint={`revisione al ${Number(review.progress_percent ?? 0).toFixed(0)}%`} />
      </div>

      <div className="grid cols-2" style={{ marginBottom: 14 }}>
        <div className="card">
          <h2>Rilievi per severita’</h2>
          <SeverityBars counts={data.severity_counts as unknown as Record<string, number>} />
        </div>
        <div className="card">
          <h2>Profilo di esposizione</h2>
          <CategoryRadar categories={data.categories} />
        </div>
      </div>

      <div className="grid cols-2" style={{ marginBottom: 14 }}>
        <div className="card">
          <h2>Andamento del rating</h2>
          <TrendChart points={data.trend} />
        </div>
        <div className="card">
          <h2>Superficie esposta e dark web</h2>
          <table className="data">
            <tbody>
              <tr><td>Domini e sottodomini</td>
                  <td className="num tabular">{(assets.domains ?? 0) + (assets.subdomains ?? 0)}</td></tr>
              <tr><td>Servizi web attivi</td><td className="num tabular">{assets.web_services ?? 0}</td></tr>
              <tr><td>Indirizzi IP</td><td className="num tabular">{assets.ip_addresses ?? 0}</td></tr>
              <tr><td>Servizi di rete esposti</td>
                  <td className="num tabular">{assets.network_services ?? 0}</td></tr>
              <tr><td>Nuovi asset (ultima scansione)</td>
                  <td className="num tabular">{assets.new_last_scan ?? 0}</td></tr>
              <tr><td>Asset non piu’ osservati</td>
                  <td className="num tabular">{assets.disappeared ?? 0}</td></tr>
              <tr><td>Pubblicazioni ransomware</td>
                  <td className="num tabular">{darkweb.ransomware_publications ?? 0}</td></tr>
              <tr><td>Stealer log</td><td className="num tabular">{darkweb.stealer_logs ?? 0}</td></tr>
              <tr><td>Data breach</td><td className="num tabular">{darkweb.breaches ?? 0}</td></tr>
              <tr><td>Domini simili registrati</td>
                  <td className="num tabular">{darkweb.lookalike_domains ?? 0}</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      {data.coverage_gaps.length > 0 && (
        <div className="card">
          <div className="section-head">
            <h2>Aree non verificate</h2>
            <Chip tone="medium">{data.coverage_gaps.length} strumenti non eseguiti</Chip>
          </div>
          <p className="muted small">
            Un’area senza rilievi non significa che sia sicura: puo’ non essere stata
            controllata. Queste lacune riducono gia’ l’affidabilita’ della rilevazione,
            non il punteggio.
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table className="data">
              <thead>
                <tr><th>Strumento</th><th>Aree interessate</th><th>Motivo</th><th>Esito</th></tr>
              </thead>
              <tbody>
                {data.coverage_gaps.map((lacuna) => (
                  <tr key={lacuna.tool_key}>
                    <td>{lacuna.tool_label}</td>
                    <td className="small">{lacuna.areas_it.join(', ') || '—'}</td>
                    <td className="small muted">{lacuna.reason}</td>
                    <td>
                      <Chip tone={lacuna.status === 'failed' ? 'high' : 'medium'}>
                        {lacuna.status === 'failed' ? 'non riuscito' : 'non eseguito'}
                      </Chip>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card">
        <h2>Approfondimenti</h2>
        {data.last_scan ? (
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <Link className="btn btn--ghost" to={`/scansioni/${data.last_scan.id}/rilievi`}>Rilievi</Link>
            <Link className="btn btn--ghost" to={`/scansioni/${data.last_scan.id}/remediation`}>
              Piano di remediation
            </Link>
            <Link className="btn btn--ghost" to={`/scansioni/${data.last_scan.id}/report`}>Report</Link>
            <Link className="btn btn--ghost" to={`/aziende/${companyId}/scansioni`}>Storico scansioni</Link>
          </div>
        ) : <Empty>Avviare una scansione per popolare la dashboard.</Empty>}
        <p className="muted small" style={{ marginTop: 12, marginBottom: 0 }}>
          {data.scope_disclaimer_it}
        </p>
      </div>
    </>
  );
}
