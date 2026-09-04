import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { PortfolioView } from '../api/types';
import { Banner, Empty, RATING_TINT, Spinner, StatTile, formatDate, formatDelta } from '../components/ui';

export default function Portfolio() {
  const [data, setData] = useState<PortfolioView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.portfolio().then(setData).catch((e) => setError(String(e.message ?? e)));
  }, []);

  if (error) return <Banner kind="danger">{error}</Banner>;
  if (!data) return <Spinner />;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Portfolio</h1>
          <p className="sub">Tutte le aziende valutate, con rating corrente e variazione</p>
        </div>
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <Link className="btn" to="/aziende/nuova/gestione">Nuova azienda</Link>
        </div>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <StatTile label="Aziende" value={data.total_companies} />
        <StatTile label="Rating medio"
                  value={data.average_score !== null ? data.average_score.toFixed(1) : '—'}
                  hint="media dei rating pubblicati" />
        <StatTile label="In classe D o E" value={data.companies_below_c}
                  tone={data.companies_below_c > 0 ? 'var(--status-serious)' : undefined}
                  hint="richiedono attenzione prioritaria" />
        <StatTile label="Rilievi critici" value={data.total_critical_findings}
                  tone={data.total_critical_findings > 0 ? 'var(--status-critical)' : undefined} />
      </div>

      <div className="card">
        <h2>Aziende</h2>
        {data.companies.length === 0 ? (
          <Empty>Nessuna azienda registrata.</Empty>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Azienda</th>
                  <th className="num">Rating</th>
                  <th>Classe</th>
                  <th className="num">Variazione</th>
                  <th className="num">Affidabilita’</th>
                  <th className="num">Critici</th>
                  <th className="num">Alti</th>
                  <th className="num">Remediation aperte</th>
                  <th>Ultima scansione</th>
                  <th>Prossima verifica</th>
                </tr>
              </thead>
              <tbody>
                {data.companies.map((c) => (
                  <tr key={c.company_id}>
                    <td><Link to={`/aziende/${c.company_id}`}>{c.company_name}</Link></td>
                    <td className="num tabular">
                      {c.is_provisional || c.overall_score === null
                        ? <span className="muted">provvisorio</span>
                        : c.overall_score.toFixed(1)}
                    </td>
                    <td>
                      {c.rating_class ? (
                        <span className="chip">
                          <span className="chip__dot" aria-hidden="true"
                                style={{ background: RATING_TINT[c.rating_class] }} />
                          {c.rating_class}
                        </span>
                      ) : <span className="muted">—</span>}
                    </td>
                    <td className="num tabular"
                        style={{ color: c.score_delta === null ? undefined
                          : c.score_delta > 0 ? 'var(--status-good)'
                          : c.score_delta < 0 ? 'var(--status-critical)' : undefined }}>
                      {formatDelta(c.score_delta)}
                    </td>
                    <td className="num tabular">{c.confidence !== null ? `${c.confidence.toFixed(0)}%` : '—'}</td>
                    <td className="num tabular">{c.critical_findings}</td>
                    <td className="num tabular">{c.high_findings}</td>
                    <td className="num tabular">{c.open_remediations}</td>
                    <td>{formatDate(c.last_scan_at)}</td>
                    <td>{formatDate(c.next_scan_due_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted small" style={{ marginTop: 12, marginBottom: 0 }}>
          Il rating e’ una valutazione dell’esposizione osservabile dall’esterno.
          Non e’ un penetration test ne’ una certificazione di sicurezza.
        </p>
      </div>
    </>
  );
}
