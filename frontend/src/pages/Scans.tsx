import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Scan, ScanDetail } from '../api/types';
import { Banner, Empty, Spinner, formatDateTime } from '../components/ui';

const RUNNING = new Set(['pending', 'queued', 'running', 'normalizing', 'scoring']);

const STATUS_LABEL: Record<string, string> = {
  pending: 'in attesa', queued: 'accodata', running: 'in corso',
  normalizing: 'normalizzazione', scoring: 'calcolo del rating',
  awaiting_review: 'in attesa di revisione', completed: 'completata',
  partial: 'completata parzialmente', failed: 'fallita', cancelled: 'annullata',
};

export default function Scans() {
  const { companyId = '' } = useParams();
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const page = await api.scans(companyId);
        if (cancelled) return;
        setScans(page.items);
        const active = page.items.find((s) => RUNNING.has(s.status));
        if (active) {
          const full = await api.scan(active.id);
          if (!cancelled) setDetail(full);
        }
      } catch (exc) {
        if (!cancelled) setError(String((exc as Error).message ?? exc));
      }
    }
    load();
    // Polling leggero: si ferma quando nessuna scansione e' in corso.
    const timer = window.setInterval(() => {
      setScans((current) => {
        if (current?.some((s) => RUNNING.has(s.status))) load();
        return current;
      });
    }, 5000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [companyId]);

  if (error) return <Banner kind="danger">{error}</Banner>;
  if (!scans) return <Spinner />;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Scansioni</h1>
          <p className="sub">Storico delle valutazioni e stato degli strumenti</p>
        </div>
      </div>

      {detail && RUNNING.has(detail.status) && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h2>Scansione in corso</h2>
          <p className="small">
            Fase: <strong>{detail.current_stage ?? '—'}</strong> · avanzamento {detail.progress_percent}%
          </p>
          <div className="bar" style={{ height: 8, background: 'var(--grid)', borderRadius: 4 }}>
            <span style={{ display: 'block', height: '100%', width: `${detail.progress_percent}%`,
                           background: 'var(--series-1)', borderRadius: 4 }} />
          </div>
          {detail.tool_runs.length > 0 && (
            <table className="data" style={{ marginTop: 12 }}>
              <thead><tr><th>Strumento</th><th>Esito</th><th className="num">Evidenze</th><th>Note</th></tr></thead>
              <tbody>
                {detail.tool_runs.map((run) => (
                  <tr key={run.id}>
                    <td>{run.tool_key}{run.was_mocked && <span className="muted small"> (sintetico)</span>}</td>
                    <td>{run.status}</td>
                    <td className="num tabular">{run.evidence_count}</td>
                    <td className="small muted">{run.error_message ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <div className="card">
        {scans.length === 0 ? <Empty>Nessuna scansione eseguita per questa azienda.</Empty> : (
          <table className="data">
            <thead>
              <tr>
                <th>Avvio</th><th>Profilo</th><th>Stato</th><th className="num">Rating</th>
                <th className="num">Affidabilita’</th><th className="num">Rilievi</th><th>Azioni</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const stats = (scan.stats_json ?? {}) as Record<string, number | string | boolean>;
                return (
                  <tr key={scan.id}>
                    <td>{formatDateTime(scan.started_at)}</td>
                    <td className="small">{scan.profile_key}</td>
                    <td>
                      {STATUS_LABEL[scan.status] ?? scan.status}
                      {scan.mock_mode && <span className="muted small"> · dati sintetici</span>}
                    </td>
                    <td className="num tabular">
                      {typeof stats.overall_score === 'number'
                        ? `${stats.overall_score.toFixed(1)} (${stats.rating_class})` : '—'}
                    </td>
                    <td className="num tabular">
                      {typeof stats.confidence === 'number' ? `${stats.confidence}%` : '—'}
                    </td>
                    <td className="num tabular">{String(stats.findings_after_dedup ?? '—')}</td>
                    <td className="small">
                      <Link to={`/scansioni/${scan.id}/rilievi`}>Rilievi</Link>{' · '}
                      <Link to={`/scansioni/${scan.id}/report`}>Report</Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
