/** Componenti UI di base: chip, tile, banner, tabelle. */
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import type { RatingClass, Severity } from '../api/types';

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critica', high: 'Alta', medium: 'Media', low: 'Bassa', info: 'Informativa',
};

export const CONFIDENCE_LABEL: Record<string, string> = {
  confirmed: 'Confermata', probable: 'Probabile', inferred: 'Dedotta',
  informational: 'Informativa', false_positive: 'Falso positivo',
  accepted_risk: 'Rischio accettato', resolved: 'Risolta',
};

export const OWNERSHIP_LABEL: Record<string, string> = {
  verified_owned: 'Proprieta’ verificata', likely_owned: 'Probabile proprieta’',
  unverified: 'Non verificato', third_party: 'Terza parte', excluded: 'Escluso',
};

export const CATEGORY_LABEL: Record<string, string> = {
  attack_surface: 'Attack surface',
  technical_vulnerabilities: 'Vulnerabilita’ tecniche',
  web_security: 'Sicurezza web',
  email_dns_security: 'E-mail e DNS',
  darkweb_breach: 'Dark web e breach',
};

/** La classe di rating e' un'ordinale: il colore accompagna SEMPRE la lettera. */
export const RATING_TINT: Record<RatingClass, string> = {
  A: 'var(--status-good)', B: 'var(--status-good)', C: 'var(--status-warning)',
  D: 'var(--status-serious)', E: 'var(--status-critical)',
};

export function SeverityChip({ severity }: { severity: Severity }) {
  return (
    <span className={`chip chip--${severity}`}>
      <span className="chip__dot" aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function Chip({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return <span className={`chip chip--${tone}`}>{children}</span>;
}

export function StatTile({ label, value, hint, tone }:
  { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className="card">
      <div className="stat__label">{label}</div>
      <div className="stat__value" style={tone ? { color: tone } : undefined}>{value}</div>
      {hint ? <div className="stat__hint">{hint}</div> : null}
    </div>
  );
}

export function Banner({ kind = 'info', children }:
  { kind?: 'info' | 'warning' | 'danger'; children: ReactNode }) {
  const suffix = kind === 'info' ? '' : ` banner--${kind}`;
  return <div className={`banner${suffix}`} role={kind === 'info' ? undefined : 'alert'}>{children}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="muted small" style={{ margin: '8px 0' }}>{children}</p>;
}

export function Spinner({ label = 'Caricamento…' }: { label?: string }) {
  return <p className="muted small" role="status">{label}</p>;
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleDateString('it-IT');
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? '—'
    : date.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
}

export function formatDelta(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return `${value > 0 ? '+' : ''}${value.toFixed(1)}`;
}

/* -------------------------------- form ---------------------------------- */

/** Campo etichettato. L'errore e' testuale, non solo un bordo colorato: deve
 *  restare percepibile anche senza distinzione dei colori. */
export function Field({ label, hint, error, children }: {
  label: string; hint?: string; error?: string | null; children: ReactNode;
}) {
  return (
    <div className={`field${error ? ' field--invalid' : ''}`}>
      <label>{label}</label>
      {children}
      {hint && !error && <span className="hint">{hint}</span>}
      {error && <span className="error" role="alert">{error}</span>}
    </div>
  );
}

/** Pulsante per azioni distruttive: richiede una seconda conferma esplicita,
 *  cosi' un click involontario non cancella nulla. */
export function ConfirmButton({ label, confirmLabel, onConfirm, disabled, tone = 'danger' }: {
  label: string; confirmLabel?: string; onConfirm: () => void;
  disabled?: boolean; tone?: 'danger' | 'ghost';
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const timer = window.setTimeout(() => setArmed(false), 5000);
    return () => window.clearTimeout(timer);
  }, [armed]);

  if (!armed) {
    return (
      <button type="button" className={`btn btn--sm btn--${tone === 'danger' ? 'ghost' : 'ghost'}`}
              disabled={disabled} onClick={() => setArmed(true)}>
        {label}
      </button>
    );
  }
  return (
    <button type="button" className="btn btn--sm btn--danger" disabled={disabled}
            onClick={() => { setArmed(false); onConfirm(); }}>
      {confirmLabel ?? 'Confermi?'}
    </button>
  );
}
