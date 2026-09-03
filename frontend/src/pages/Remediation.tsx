import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api/client';
import type { RemediationItem } from '../api/types';
import { Banner, Empty, SeverityChip, Spinner } from '../components/ui';

const PRIORITY_LABEL: Record<string, string> = {
  p1: 'Immediata', p2: 'Alta', p3: 'Media', p4: 'Pianificabile',
};
const EFFORT_LABEL: Record<string, string> = {
  xs: 'Molto basso', s: 'Basso', m: 'Medio', l: 'Alto', xl: 'Molto alto',
};

export default function Remediation() {
  const { scanId = '' } = useParams();
  const [items, setItems] = useState<RemediationItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [quickOnly, setQuickOnly] = useState(false);

  useEffect(() => {
    setItems(null);
    api.remediationPlan(scanId, quickOnly).then(setItems)
      .catch((e) => setError(String(e.message ?? e)));
  }, [scanId, quickOnly]);

  if (error) return <Banner kind="danger">{error}</Banner>;
  if (!items) return <Spinner />;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Piano di remediation</h1>
          <p className="sub">Interventi ordinati per rischio, priorita’ e diffusione</p>
        </div>
      </div>

      <div className="toolbar">
        <label className="small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={quickOnly} onChange={(e) => setQuickOnly(e.target.checked)} />
          Solo interventi rapidi ad alto beneficio
        </label>
        <span className="muted small" style={{ marginLeft: 'auto' }}>{items.length} interventi</span>
      </div>

      {items.length === 0 ? (
        <div className="card"><Empty>Nessun intervento identificato per questa scansione.</Empty></div>
      ) : items.map((item, index) => (
        <div className="card" key={item.catalog_id} style={{ marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
            <strong style={{ fontSize: 15 }}>{index + 1}. {item.title_it}</strong>
            <SeverityChip severity={item.max_severity} />
            <span className="chip">Priorita’: {PRIORITY_LABEL[item.priority] ?? item.priority}</span>
            <span className="chip">Impegno: {EFFORT_LABEL[item.effort] ?? item.effort}</span>
            {item.is_quick_win && <span className="chip chip--low">
              <span className="chip__dot" aria-hidden="true" />Intervento rapido</span>}
          </div>

          <p className="small muted" style={{ marginTop: 8 }}>
            <strong>Rischio mitigato:</strong> {item.risk_mitigated_it}
          </p>
          <p style={{ margin: '6px 0' }}><strong>Azione immediata.</strong> {item.immediate_action_it}</p>
          <p style={{ margin: '6px 0' }}><strong>Soluzione strutturale.</strong> {item.structural_solution_it}</p>
          <p style={{ margin: '6px 0' }}><strong>Verifica della risoluzione.</strong> {item.verification_it}</p>

          <p className="small muted" style={{ marginBottom: 0 }}>
            Competenze: {item.skills.join(', ') || '—'} ·{' '}
            Asset interessati: {item.affected_asset_count} ·{' '}
            Rilievi: {item.finding_codes.join(', ') || '—'}
            {item.references.length > 0 && <> · Riferimenti: {item.references.join(' · ')}</>}
          </p>

          {item.commercial_services.length > 0 && (
            <p className="small muted" style={{
              marginTop: 10, marginBottom: 0, paddingTop: 8, borderTop: '1px solid var(--grid)' }}>
              <em>Proposta commerciale (distinta dalla raccomandazione tecnica):</em>{' '}
              {item.commercial_services.join(', ')}
            </p>
          )}
        </div>
      ))}
    </>
  );
}
