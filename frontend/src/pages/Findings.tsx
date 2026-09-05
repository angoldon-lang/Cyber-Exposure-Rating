import { useEffect, useMemo, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { ApiError, api } from '../api/client';
import type { Finding, ScoreDetail, Severity } from '../api/types';
import {
  Banner, CATEGORY_LABEL, CONFIDENCE_LABEL, Empty, OWNERSHIP_LABEL, SeverityChip,
  formatDate,
} from '../components/ui';

const REVIEW_ACTIONS: Array<{ value: string; label: string; needsReason: boolean }> = [
  { value: 'confirm', label: 'Conferma il rilievo', needsReason: false },
  { value: 'false_positive', label: 'Dichiara falso positivo', needsReason: true },
  { value: 'accept_risk', label: 'Accetta il rischio', needsReason: true },
  { value: 'exclude_from_rating', label: 'Escludi dal rating', needsReason: true },
  { value: 'request_retest', label: 'Richiedi un retest', needsReason: false },
];

export default function Findings() {
  const { scanId = '' } = useParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [score, setScore] = useState<ScoreDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [severity, setSeverity] = useState<string>('');
  const [category, setCategory] = useState<string>('');
  const [onlyScoring, setOnlyScoring] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  // L'avviso in dashboard rimanda qui gia' filtrato: il criterio di «da
  // validare» vive nell'API, cosi' l'avviso e questo elenco non possono
  // descrivere insiemi diversi.
  const [parametri, setParametri] = useSearchParams();
  const daValidare = parametri.get('daValidare') === '1';

  async function reload() {
    const params: Record<string, string> = {};
    if (severity) params.severity = severity;
    if (category) params.category = category;
    if (onlyScoring) params.only_scoring = 'true';
    if (daValidare) params.pending_review = 'true';
    const page = await api.findings(scanId, params);
    setFindings(page.items);
  }

  useEffect(() => {
    reload().catch((e) => setError(String(e.message ?? e)));
    api.score(scanId).then(setScore).catch(() => setScore(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, severity, category, onlyScoring, daValidare]);

  const categories = useMemo(
    () => Array.from(new Set(findings.map((f) => f.category))).sort(),
    [findings]);

  async function review(finding: Finding, action: string) {
    const definition = REVIEW_ACTIONS.find((a) => a.value === action);
    let reason: string | undefined;
    if (definition?.needsReason) {
      reason = window.prompt('Motivazione (obbligatoria e registrata nell’audit log):') ?? undefined;
      if (!reason) return;
    }
    try {
      await api.reviewFinding(finding.id, { action, reason });
      setNotice(`Rilievo ${finding.reference_code}: azione «${definition?.label}» registrata.`);
      await reload();
    } catch (exc) {
      setNotice(exc instanceof ApiError ? exc.message : 'Azione di revisione non riuscita');
    }
  }

  if (error) return <Banner kind="danger">{error}</Banner>;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Rilievi</h1>
          <p className="sub">
            {score
              ? <>Rating {score.overall_score.toFixed(1)}/100 · classe {score.rating_class} ·
                  modello di scoring v{score.scoring_config_version}</>
              : 'Scansione senza punteggio calcolato'}
          </p>
        </div>
      </div>

      {notice && <Banner>{notice}</Banner>}

      {score?.cap_applied && (
        <Banner kind="danger">
          <strong>Limitazione del punteggio applicata.</strong>
          <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
            {score.applied_caps.map((cap) => (
              <li key={cap.cap_id}>{cap.reason_it} — punteggio massimo {cap.max_score}/100</li>
            ))}
          </ul>
        </Banner>
      )}

      <div className="toolbar">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severita’">
          <option value="">Tutte le severita’</option>
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Area">
          <option value="">Tutte le aree</option>
          {categories.map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c] ?? c}</option>)}
        </select>
        <label className="small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={onlyScoring}
                 onChange={(e) => setOnlyScoring(e.target.checked)} />
          Solo rilievi che incidono sul rating
        </label>
        <label className="small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={daValidare}
                 onChange={(e) => {
                   const successivi = new URLSearchParams(parametri);
                   if (e.target.checked) successivi.set('daValidare', '1');
                   else successivi.delete('daValidare');
                   setParametri(successivi, { replace: true });
                 }} />
          Solo critici e alti da validare
        </label>
        <span className="muted small" style={{ marginLeft: 'auto' }}>{findings.length} rilievi</span>
      </div>

      <div className="card">
        {findings.length === 0 ? <Empty>Nessun rilievo corrisponde ai filtri selezionati.</Empty> : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Rif.</th><th>Severita’</th><th>Rilievo</th><th>Asset interessato</th>
                  <th>Area</th><th>Attendibilita’</th><th className="num">Detrazione</th>
                  <th>Revisione</th><th>Azioni</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <>
                    <tr key={f.id}>
                      <td className="tabular">{f.reference_code}</td>
                      <td><SeverityChip severity={f.severity} /></td>
                      <td>
                        <button className="btn btn--ghost" style={{ padding: '2px 6px', fontSize: 12 }}
                                onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                                aria-expanded={expanded === f.id}>
                          {expanded === f.id ? '−' : '+'}
                        </button>{' '}
                        {f.title}
                        {f.cisa_kev && <> <span className="chip chip--critical">CISA KEV</span></>}
                      </td>
                      <td className="tabular small">{f.asset_display ?? '—'}</td>
                      <td className="small">{CATEGORY_LABEL[f.category] ?? f.category}</td>
                      <td className="small">{CONFIDENCE_LABEL[f.confidence_class] ?? f.confidence_class}</td>
                      <td className="num tabular">
                        {f.applied_deduction > 0 ? `−${f.applied_deduction.toFixed(1)}` : '—'}
                      </td>
                      <td className="small">
                        {f.excluded_from_rating
                          ? <span className="muted">escluso dal rating</span>
                          : f.analyst_validation === 'not_reviewed'
                            ? <span className="muted">da rivedere</span>
                            : f.analyst_validation}
                      </td>
                      <td>
                        <select defaultValue="" aria-label={`Azione su ${f.reference_code}`}
                                onChange={(e) => { if (e.target.value) { review(f, e.target.value); e.target.value = ''; } }}>
                          <option value="">Azione…</option>
                          {REVIEW_ACTIONS.map((a) => (
                            <option key={a.value} value={a.value}>{a.label}</option>
                          ))}
                        </select>
                      </td>
                    </tr>
                    {expanded === f.id && (
                      <tr key={`${f.id}-detail`}>
                        <td colSpan={9} style={{ background: 'var(--surface-2)' }}>
                          <p style={{ marginTop: 0 }}>{f.description}</p>
                          <table className="data" style={{ maxWidth: 720 }}>
                            <tbody>
                              <tr><td>Asset interessato</td>
                                  <td className="tabular">{f.asset_display ?? '—'}</td></tr>
                              <tr><td>Proprieta’ dell’asset</td>
                                  <td>{OWNERSHIP_LABEL[f.ownership_status] ?? f.ownership_status}</td></tr>
                              <tr><td>Dettaglio</td><td>{f.detail ?? '—'}</td></tr>
                              {f.evidence_summary && (
                                <tr><td>Evidenze</td><td>{f.evidence_summary}</td></tr>
                              )}
                              {f.attributes_json && Object.keys(f.attributes_json).length > 0 && (
                                <tr>
                                  <td>Dati osservati</td>
                                  <td>
                                    {/* Servono a riprodurre la verifica: porta, header,
                                        versione rilevata, codice di risposta. */}
                                    <ul style={{ margin: 0, paddingLeft: 16 }}>
                                      {Object.entries(f.attributes_json).map(([chiave, valore]) => (
                                        <li key={chiave} className="small">
                                          <span className="muted">{chiave}:</span>{' '}
                                          <span className="tabular">
                                            {typeof valore === 'object'
                                              ? JSON.stringify(valore)
                                              : String(valore)}
                                          </span>
                                        </li>
                                      ))}
                                    </ul>
                                  </td>
                                </tr>
                              )}
                              <tr><td>Prima rilevazione</td><td>{formatDate(f.first_seen_at)}</td></tr>
                              <tr><td>Ultima rilevazione</td><td>{formatDate(f.last_seen_at)}</td></tr>
                              {f.cve_id && (
                                <tr><td>Vulnerabilita’</td>
                                    <td>{f.cve_id} · CVSS {f.cvss_score ?? 'n/d'} ·{' '}
                                      EPSS {f.epss_score !== null ? `${(f.epss_score * 100).toFixed(1)}%` : 'n/d'} ·{' '}
                                      CISA KEV: {f.cisa_kev ? 'si' : 'no'}</td></tr>
                              )}
                              <tr><td>Rilevato da</td><td>{(f.sources_json ?? []).join(', ') || '—'}</td></tr>
                              <tr><td>Stato nel workflow</td><td>{f.workflow_state}</td></tr>
                              {f.remediation_catalog_id && (
                                <tr><td>Come si risolve</td>
                                    <td>
                                      <Link to={`/scansioni/${scanId}/remediation#${f.remediation_catalog_id}`}>
                                        {f.remediation_title_it ?? f.remediation_catalog_id}
                                      </Link>{' '}
                                      <span className="muted small">
                                        ({f.remediation_catalog_id})
                                      </span>
                                    </td></tr>
                              )}
                            </tbody>
                          </table>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
