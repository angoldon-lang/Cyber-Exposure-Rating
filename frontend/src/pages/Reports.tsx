import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { ApiError, api, downloadReport } from '../api/client';
import type { Report, ScanComparison } from '../api/types';
import { Banner, Empty, Spinner, formatDateTime } from '../components/ui';

const FORMATS = ['pdf', 'docx', 'json', 'csv'];

export default function Reports() {
  const { scanId = '' } = useParams();
  const [reports, setReports] = useState<Report[] | null>(null);
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [isFinal, setIsFinal] = useState(true);

  async function reload() {
    setReports(await api.reports(scanId));
  }

  useEffect(() => {
    reload().catch((e) => setNotice(String(e.message ?? e)));
    api.comparison(scanId).then(setComparison).catch(() => setComparison(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  async function generate() {
    setBusy(true);
    setNotice(null);
    try {
      await api.generateReport(scanId, {
        report_type: 'combined', language: 'it', formats: FORMATS, is_final: isFinal,
      });
      setNotice('Report generato correttamente.');
      await reload();
    } catch (exc) {
      setNotice(exc instanceof ApiError ? exc.message : 'Generazione del report non riuscita');
    } finally {
      setBusy(false);
    }
  }

  if (!reports) return <Spinner />;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Report</h1>
          <p className="sub">Report esecutivo, allegato tecnico ed esportazioni</p>
        </div>
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <label className="small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input type="checkbox" checked={isFinal} onChange={(e) => setIsFinal(e.target.checked)} />
            Report definitivo
          </label>
          <button className="btn" onClick={generate} disabled={busy}>
            {busy ? 'Generazione…' : 'Genera report'}
          </button>
        </div>
      </div>

      {notice && <Banner kind={notice.includes('correttamente') ? 'info' : 'warning'}>{notice}</Banner>}

      {comparison && comparison.previous_score !== null && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h2>Confronto con la scansione precedente</h2>
          <p style={{ marginTop: 0 }}>{comparison.summary_it}</p>
          <div className="grid cols-4">
            <div><div className="stat__label">Nuovi rilievi</div>
                 <div className="stat__value" style={{ fontSize: 22 }}>{comparison.new_findings.length}</div></div>
            <div><div className="stat__label">Risolti</div>
                 <div className="stat__value" style={{ fontSize: 22 }}>{comparison.resolved_findings.length}</div></div>
            <div><div className="stat__label">In attesa di conferma</div>
                 <div className="stat__value" style={{ fontSize: 22 }}>{comparison.pending_closure.length}</div></div>
            <div><div className="stat__label">Nuovi asset</div>
                 <div className="stat__value" style={{ fontSize: 22 }}>{comparison.new_assets.length}</div></div>
          </div>
          {comparison.pending_closure.length > 0 && (
            <p className="small muted" style={{ marginBottom: 0 }}>
              I rilievi non piu’ osservati non vengono chiusi automaticamente: serve una
              seconda verifica prima di considerarli risolti.
            </p>
          )}
        </div>
      )}

      <div className="card">
        <h2>Report generati</h2>
        {reports.length === 0 ? <Empty>Nessun report generato per questa scansione.</Empty> : (
          <table className="data">
            <thead>
              <tr><th>Titolo</th><th>Tipo</th><th>Stato</th><th>Generato il</th><th>Formati</th></tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id}>
                  <td>{report.title}</td>
                  <td className="small">{report.report_type} · {report.language.toUpperCase()}</td>
                  <td className="small">
                    {report.status}
                    {report.approved_at && <span className="muted"> · approvato {formatDateTime(report.approved_at)}</span>}
                  </td>
                  <td className="small">{formatDateTime(report.created_at)}</td>
                  <td>
                    {report.versions.length === 0 ? <span className="muted small">—</span> :
                      report.versions.map((version) => (
                        <button key={version.id} className="btn btn--ghost"
                                style={{ padding: '2px 8px', fontSize: 12, marginRight: 4 }}
                                onClick={() => downloadReport(
                                  report.id, version.format,
                                  `defenix-report.${version.format}`)}>
                          {version.format.toUpperCase()}
                        </button>
                      ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small" style={{ marginTop: 12, marginBottom: 0 }}>
          Un report definitivo non e’ emettibile finche’ restano rilievi critici o alti
          non validati da un analista. I report non contengono credenziali, token, cookie,
          contenuti integrali di leak ne’ istruzioni di sfruttamento.
        </p>
      </div>
    </>
  );
}
