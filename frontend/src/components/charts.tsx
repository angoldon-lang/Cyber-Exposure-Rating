/**
 * Grafici della dashboard.
 *
 * Regole applicate:
 *  - una sola serie dati per grafico -> un solo colore, nessuna legenda
 *    (il titolo del riquadro nomina la serie);
 *  - nessun doppio asse;
 *  - griglia e assi recessivi, marcature sottili;
 *  - tooltip sempre presente (hover layer);
 *  - la classe di rating usa la palette di stato ed e' SEMPRE accompagnata
 *    dalla lettera e dall'etichetta: il colore non porta mai da solo il
 *    significato;
 *  - animazioni disattivate: i grafici si ridisegnano al cambio di filtro e
 *    l'animazione di ingresso renderebbe la lettura instabile (oltre a non
 *    rispettare `prefers-reduced-motion`).
 */
import {
  Bar, BarChart, CartesianGrid, Cell, Line, LineChart, PolarAngleAxis, PolarGrid,
  PolarRadiusAxis, Radar, RadarChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import type { CategoryScore, RatingClass, TrendPoint } from '../api/types';
import { CATEGORY_LABEL, RATING_TINT, formatDate } from './ui';

const AXIS_STYLE = { fill: 'var(--text-muted)', fontSize: 11 };

function TooltipBox({ label, value, suffix = '' }:
  { label: string; value: number | string; suffix?: string }) {
  return (
    <div className="viz-tooltip">
      <div className="viz-tooltip__label">{label}</div>
      <div className="viz-tooltip__value">{value}{suffix}</div>
    </div>
  );
}

/** Indicatore del rating complessivo: arco + numero + lettera + etichetta. */
export function RatingGauge({ score, ratingClass, label, provisional }:
  { score: number | null; ratingClass: RatingClass | null; label: string | null; provisional: boolean }) {
  const size = 168;
  const stroke = 13;
  const radius = (size - stroke) / 2;
  // Arco di 270 gradi: lascia spazio all'etichetta sotto.
  const circumference = 2 * Math.PI * radius;
  const arc = circumference * 0.75;
  const value = score ?? 0;
  const filled = provisional ? 0 : (value / 100) * arc;
  const tone = ratingClass ? RATING_TINT[ratingClass] : 'var(--status-neutral)';

  return (
    <div style={{ display: 'grid', placeItems: 'center', gap: 6 }}>
      <svg width={size} height={size} role="img"
           aria-label={provisional
             ? 'Valutazione provvisoria: rating non pubblicabile'
             : `Rating ${value.toFixed(0)} su 100, classe ${ratingClass}`}>
        <g transform={`rotate(135 ${size / 2} ${size / 2})`}>
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none"
                  stroke="var(--grid)" strokeWidth={stroke} strokeLinecap="round"
                  strokeDasharray={`${arc} ${circumference}`} />
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none"
                  stroke={tone} strokeWidth={stroke} strokeLinecap="round"
                  strokeDasharray={`${filled} ${circumference}`} />
        </g>
        <text x="50%" y="46%" textAnchor="middle" dominantBaseline="middle"
              style={{ fontSize: 34, fontWeight: 700, fill: 'var(--text-primary)' }}>
          {provisional ? '—' : value.toFixed(0)}
        </text>
        <text x="50%" y="60%" textAnchor="middle"
              style={{ fontSize: 12, fill: 'var(--text-muted)' }}>
          {provisional ? 'provvisorio' : 'su 100'}
        </text>
      </svg>
      {provisional ? (
        <div className="small muted" style={{ textAlign: 'center' }}>
          Evidenze insufficienti per un rating attendibile
        </div>
      ) : (
        <div style={{ textAlign: 'center' }}>
          <strong style={{ fontSize: 16 }}>Classe {ratingClass}</strong>
          <div className="small muted">{label}</div>
        </div>
      )}
    </div>
  );
}

/** Punteggio per area: una sola misura su cinque categorie -> un colore. */
export function CategoryBars({ categories }: { categories: CategoryScore[] }) {
  const data = categories.map((c) => ({
    name: CATEGORY_LABEL[c.key] ?? c.label_it,
    score: Number(c.score.toFixed(1)),
    weight: c.weight,
    findings: c.finding_count,
  }));
  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 42)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 44, bottom: 4, left: 4 }}>
        <CartesianGrid horizontal={false} stroke="var(--grid)" />
        <XAxis type="number" domain={[0, 100]} tick={AXIS_STYLE} axisLine={{ stroke: 'var(--axis)' }}
               tickLine={false} />
        <YAxis type="category" dataKey="name" width={132} tick={AXIS_STYLE}
               axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: 'color-mix(in srgb, var(--series-1) 8%, transparent)' }}
                 content={({ active, payload }) => {
                   if (!active || !payload?.length) return null;
                   const row = payload[0].payload as typeof data[number];
                   return (
                     <div className="viz-tooltip">
                       <div className="viz-tooltip__label">{row.name}</div>
                       <div className="viz-tooltip__value">{row.score}/100</div>
                       <div className="small muted">
                         peso {(row.weight * 100).toFixed(0)}% · {row.findings} rilievi
                       </div>
                     </div>
                   );
                 }} />
        <Bar dataKey="score" fill="var(--series-1)" radius={[0, 4, 4, 0]} barSize={14}
             isAnimationActive={false}
             label={{ position: 'right', fill: 'var(--text-secondary)', fontSize: 11 }} />
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Profilo di esposizione: una sola serie, quindi nessuna legenda. */
export function CategoryRadar({ categories }: { categories: CategoryScore[] }) {
  const short: Record<string, string> = {
    attack_surface: 'Attack surface', technical_vulnerabilities: 'Vulnerabilita’',
    web_security: 'Web', email_dns_security: 'E-mail e DNS', darkweb_breach: 'Dark web',
  };
  const data = categories.map((c) => ({
    area: short[c.key] ?? c.label_it,
    full: CATEGORY_LABEL[c.key] ?? c.label_it,
    score: Number(c.score.toFixed(1)),
  }));
  return (
    <ResponsiveContainer width="100%" height={260}>
      <RadarChart data={data} outerRadius="68%" margin={{ top: 10, right: 40, bottom: 10, left: 40 }}>
        <PolarGrid stroke="var(--grid)" />
        <PolarAngleAxis dataKey="area" tick={AXIS_STYLE} />
        <PolarRadiusAxis domain={[0, 100]} tick={false} axisLine={false} tickCount={5} />
        <Tooltip content={({ active, payload }) => {
          if (!active || !payload?.length) return null;
          const row = payload[0].payload as typeof data[number];
          return <TooltipBox label={row.full} value={row.score} suffix="/100" />;
        }} />
        <Radar dataKey="score" stroke="var(--series-1)" strokeWidth={2}
               fill="var(--series-1)" fillOpacity={0.18} dot={{ r: 3 }}
               isAnimationActive={false} />
      </RadarChart>
    </ResponsiveContainer>
  );
}

/** Andamento del rating: serie unica nel tempo. */
export function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length < 2) {
    return (
      <p className="muted small" style={{ margin: 0 }}>
        Servono almeno due scansioni per mostrare un andamento.
      </p>
    );
  }
  const data = points.map((p) => ({
    date: formatDate(p.computed_at),
    score: Number(p.score.toFixed(1)),
    ratingClass: p.rating_class,
    confidence: p.confidence,
  }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -12 }}>
        <CartesianGrid vertical={false} stroke="var(--grid)" />
        <XAxis dataKey="date" tick={AXIS_STYLE} axisLine={{ stroke: 'var(--axis)' }} tickLine={false} />
        <YAxis domain={[0, 100]} tick={AXIS_STYLE} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ stroke: 'var(--axis)', strokeWidth: 1 }}
                 content={({ active, payload, label }) => {
                   if (!active || !payload?.length) return null;
                   const row = payload[0].payload as typeof data[number];
                   return (
                     <div className="viz-tooltip">
                       <div className="viz-tooltip__label">{label}</div>
                       <div className="viz-tooltip__value">{row.score}/100 · classe {row.ratingClass}</div>
                       {row.confidence !== null && (
                         <div className="small muted">affidabilita’ {row.confidence?.toFixed(0)}%</div>
                       )}
                     </div>
                   );
                 }} />
        <Line type="monotone" dataKey="score" stroke="var(--series-1)" strokeWidth={2}
              dot={{ r: 4, strokeWidth: 2, stroke: 'var(--surface-1)' }} activeDot={{ r: 6 }}
              isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

/**
 * Rilievi per severita'. La severita' e' una scala di STATO, non una serie
 * categoriale: usa la palette di stato ed e' sempre etichettata in asse.
 */
export function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const order: Array<[string, string, string]> = [
    ['critical', 'Critica', 'var(--status-critical)'],
    ['high', 'Alta', 'var(--status-serious)'],
    ['medium', 'Media', 'var(--status-warning)'],
    ['low', 'Bassa', 'var(--status-good)'],
    ['info', 'Informativa', 'var(--status-neutral)'],
  ];
  const data = order.map(([key, label, color]) => ({ key, label, color, value: counts[key] ?? 0 }));
  if (data.every((d) => d.value === 0)) {
    return <p className="muted small">Nessun rilievo registrato per questa scansione.</p>;
  }
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ top: 12, right: 8, bottom: 4, left: -18 }}>
        <CartesianGrid vertical={false} stroke="var(--grid)" />
        <XAxis dataKey="label" tick={AXIS_STYLE} axisLine={{ stroke: 'var(--axis)' }} tickLine={false} />
        <YAxis allowDecimals={false} tick={AXIS_STYLE} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: 'color-mix(in srgb, var(--series-1) 8%, transparent)' }}
                 content={({ active, payload }) => {
                   if (!active || !payload?.length) return null;
                   const row = payload[0].payload as typeof data[number];
                   return <TooltipBox label={`Severita’ ${row.label.toLowerCase()}`} value={row.value}
                                      suffix={row.value === 1 ? ' rilievo' : ' rilievi'} />;
                 }} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]} maxBarSize={54} isAnimationActive={false}
             label={{ position: 'top', fill: 'var(--text-secondary)', fontSize: 11 }}>
          {data.map((row) => <Cell key={row.key} fill={row.color} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
