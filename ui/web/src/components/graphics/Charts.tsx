// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';

/* Hand-written SVG charts. No chart library. Every chart is role="img" with an
 * aria-label that carries the same information as the picture. */

export type Tone = 'ok' | 'warn' | 'err' | 'blue' | 'violet' | 'teal' | 'muted';

const toneVar: Record<Tone, string> = {
  ok: 'var(--zy-chart-2)',
  warn: 'var(--zy-chart-3)',
  err: 'var(--zy-chart-4)',
  blue: 'var(--zy-chart-1)',
  violet: 'var(--zy-chart-5)',
  teal: 'var(--zy-chart-6)',
  muted: 'var(--zy-muted)',
};

export function toneColor(t: Tone) {
  return toneVar[t];
}

function reducedMotion() {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** Counts up from 0 to target on mount / change. Jumps straight there under reduced motion. */
export function useCountUp(target: number, ms = 900) {
  const [v, setV] = useState(() => (reducedMotion() ? target : 0));
  useEffect(() => {
    if (reducedMotion()) {
      setV(target);
      return;
    }
    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - t0) / ms);
      const eased = 1 - Math.pow(1 - p, 3);
      setV(Math.round(target * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

/** Flips to true one frame after mount so CSS transitions play from the initial state. */
function useMounted() {
  const [m, setM] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setM(true));
    return () => cancelAnimationFrame(id);
  }, []);
  return m;
}

function polar(cx: number, cy: number, r: number, deg: number) {
  const a = ((deg - 90) * Math.PI) / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)] as const;
}

function arcPath(cx: number, cy: number, r: number, from: number, to: number) {
  const [x0, y0] = polar(cx, cy, r, from);
  const [x1, y1] = polar(cx, cy, r, to);
  const large = to - from > 180 ? 1 : 0;
  return `M${x0.toFixed(2)} ${y0.toFixed(2)}A${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

/* ------------------------------------------------------------------ */

type RingProps = {
  value: number;
  max: number;
  size?: number;
  tone?: Tone;
  label: string; // accessible description
  center?: string;
  caption?: string;
  pulse?: boolean;
};

/** Clean ring gauge with a gentle pulse. */
export function RingGauge({ value, max, size = 168, tone = 'ok', label, center, caption, pulse }: RingProps) {
  const mounted = useMounted();
  const r = 52;
  const c = 2 * Math.PI * r;
  const frac = max > 0 ? Math.max(0, Math.min(1, value / max)) : 0;
  return (
    <div className="gauge" style={{ width: size, height: size }}>
      <svg viewBox="0 0 128 128" width={size} height={size} role="img" aria-label={label}>
        <defs>
          <linearGradient id="hv-ring-grad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor={toneVar[tone]} stopOpacity="0.75" />
            <stop offset="1" stopColor={toneVar[tone]} />
          </linearGradient>
        </defs>
        {pulse && <circle className="gauge-pulse" cx="64" cy="64" r={r + 6} fill="none" stroke={toneVar[tone]} strokeWidth="2" />}
        <circle cx="64" cy="64" r={r} fill="none" stroke="var(--zy-chart-track)" strokeWidth="10" />
        <circle
          className="gauge-arc"
          cx="64"
          cy="64"
          r={r}
          fill="none"
          stroke="url(#hv-ring-grad)"
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={c}
          style={{ strokeDashoffset: mounted ? c * (1 - frac) : c }}
          transform="rotate(-90 64 64)"
        />
      </svg>
      <div className="gauge-center" aria-hidden>
        <strong>{center ?? `${value}/${max}`}</strong>
        {caption && <span>{caption}</span>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

const BANDS = [
  { from: 0, to: 50, color: 'var(--zy-chart-4)', name: 'at risk' },
  { from: 50, to: 70, color: 'var(--zy-chart-3)', name: 'fair' },
  { from: 70, to: 85, color: 'var(--zy-chart-6)', name: 'good' },
  { from: 85, to: 100, color: 'var(--zy-chart-2)', name: 'strong' },
];

export function scoreBand(score: number) {
  return BANDS.find((b) => score < b.to) ?? BANDS[BANDS.length - 1];
}

const SWEEP = 270;
const START = 225; // degrees, clockwise from 12 o'clock => bottom-left

/** Radial score dial with colour bands, an animated needle dot and a count-up number. */
export function ScoreDial({ score, grade, size = 220 }: { score: number; grade: string; size?: number }) {
  const mounted = useMounted();
  const shown = useCountUp(Math.round(score));
  const clamped = Math.max(0, Math.min(100, score));
  const band = scoreBand(clamped);
  const angle = START + (SWEEP * (mounted ? clamped : 0)) / 100;
  const cx = 100;
  const cy = 100;
  const r = 78;
  const toDeg = (v: number) => START + (SWEEP * v) / 100;
  const [kx, ky] = polar(cx, cy, r, START);
  return (
    <div className="dial" style={{ width: size, height: size }}>
      <svg
        viewBox="0 0 200 200"
        width={size}
        height={size}
        role="img"
        aria-label={`Security score ${Math.round(score)} out of 100, grade ${grade}, ${band.name}`}
      >
        {BANDS.map((b) => (
          <path
            key={b.name}
            d={arcPath(cx, cy, r + 13, toDeg(b.from) + 1.2, toDeg(b.to) - 1.2)}
            fill="none"
            stroke={b.color}
            strokeOpacity="0.9"
            strokeWidth="4"
            strokeLinecap="round"
          />
        ))}
        <path d={arcPath(cx, cy, r, START, START + SWEEP)} fill="none" stroke="var(--zy-chart-track)" strokeWidth="14" strokeLinecap="round" />
        <path
          className="dial-arc"
          d={arcPath(cx, cy, r, START, START + SWEEP - 0.01)}
          pathLength={100}
          fill="none"
          stroke={band.color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray="100"
          style={{ strokeDashoffset: mounted ? 100 - clamped : 100 }}
        />
        <g className="dial-knob" style={{ transform: `rotate(${angle - START}deg)`, transformOrigin: `${cx}px ${cy}px` }}>
          <circle cx={kx} cy={ky} r="9" fill="var(--zy-surface)" stroke={band.color} strokeWidth="4" />
        </g>
      </svg>
      <div className="dial-center" aria-hidden>
        <strong>{shown}</strong>
        <span>/ 100</span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

type SparkProps = {
  values: number[];
  width?: number;
  height?: number;
  tone?: Tone;
  label: string;
  /** Optional x labels (first and last are shown). */
  from?: string;
  to?: string;
};

/** Sparkline with area fill and an end dot. */
export function Sparkline({ values, width = 160, height = 44, tone = 'blue', label, from, to }: SparkProps) {
  const mounted = useMounted();
  if (values.length === 0) return null;
  const pad = 4;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const step = values.length > 1 ? (width - pad * 2) / (values.length - 1) : 0;
  const pts = values.map((v, i) => [pad + i * step, height - pad - ((v - min) / span) * (height - pad * 2)] as const);
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join('');
  const last = pts[pts.length - 1];
  const area = `${line}L${last[0].toFixed(1)} ${height}L${pts[0][0].toFixed(1)} ${height}Z`;
  const gid = `hv-spark-${tone}`;
  return (
    <figure className="spark">
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="none" role="img" aria-label={label}>
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor={toneVar[tone]} stopOpacity="0.28" />
            <stop offset="1" stopColor={toneVar[tone]} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={area} fill={`url(#${gid})`} className={`spark-area${mounted ? ' is-on' : ''}`} />
        <path d={line} fill="none" stroke={toneVar[tone]} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" pathLength={1} className={`spark-line${mounted ? ' is-on' : ''}`} />
      </svg>
      {(from || to) && (
        <figcaption>
          <span>{from}</span>
          <span>{to}</span>
        </figcaption>
      )}
    </figure>
  );
}

/* ------------------------------------------------------------------ */

export type BarDatum = { label: string; value: number; tone?: Tone; note?: string };

/** Horizontal bars, one row per category. `max` defaults to the largest value. */
export function BarList({ data, max, unit = '', label, marker }: { data: BarDatum[]; max?: number; unit?: string; label: string; marker?: { at: number; text: string } }) {
  const mounted = useMounted();
  const top = max ?? Math.max(1, ...data.map((d) => d.value));
  const rowH = 34;
  const labelW = 112;
  const w = 520;
  const barW = w - labelW - 64;
  const h = data.length * rowH + (marker ? 22 : 4);
  const summary = `${label}: ${data.map((d) => `${d.label} ${d.value}${unit}`).join(', ')}`;
  return (
    <svg className="barlist" viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label={summary}>
      {marker && (
        <g>
          <line x1={labelW + (marker.at / top) * barW} x2={labelW + (marker.at / top) * barW} y1="0" y2={data.length * rowH} stroke="var(--zy-chart-3)" strokeWidth="1.5" strokeDasharray="4 3" />
          <text x={labelW + (marker.at / top) * barW} y={data.length * rowH + 16} textAnchor="middle" className="chart-text" fill="var(--zy-slate)">{marker.text}</text>
        </g>
      )}
      {data.map((d, i) => {
        const y = i * rowH + 6;
        const len = Math.max(d.value > 0 ? 4 : 0, (d.value / top) * barW);
        return (
          <g key={d.label}>
            <text x="0" y={y + 12} className="chart-text" fill="var(--zy-ink)">{d.label.length > 16 ? `${d.label.slice(0, 15)}…` : d.label}</text>
            <rect x={labelW} y={y} width={barW} height="16" rx="8" fill="var(--zy-chart-track)" />
            <rect className="bar-fill" x={labelW} y={y} style={{ width: mounted ? len : 0 }} height="16" rx="8" fill={toneVar[d.tone ?? 'blue']} />
            <text x={labelW + barW + 10} y={y + 12} className="chart-text chart-num" fill="var(--zy-ink)">{d.value}{unit}</text>
          </g>
        );
      })}
    </svg>
  );
}

/** One stacked horizontal bar with a legend rendered by the caller. */
export function StackBar({ parts, label }: { parts: { label: string; value: number; tone: Tone }[]; label: string }) {
  const mounted = useMounted();
  const total = parts.reduce((n, p) => n + p.value, 0);
  let x = 0;
  const w = 400;
  return (
    <svg className="stackbar" viewBox={`0 0 ${w} 14`} width="100%" height="14" preserveAspectRatio="none" role="img" aria-label={`${label}: ${parts.map((p) => `${p.label} ${p.value}`).join(', ')}`}>
      <rect width={w} height="14" rx="7" fill="var(--zy-chart-track)" />
      <clipPath id="hv-stack-clip"><rect width={w} height="14" rx="7" /></clipPath>
      <g clipPath="url(#hv-stack-clip)">
        {total > 0 &&
          parts.map((p) => {
            const pw = (p.value / total) * w;
            const rect = <rect key={p.label} className="stack-seg" x={x} style={{ width: mounted ? Math.max(0, pw - (pw > 3 ? 2 : 0)) : 0 }} height="14" fill={toneVar[p.tone]} />;
            x += pw;
            return rect;
          })}
      </g>
    </svg>
  );
}

/** Small donut with a centre label. */
export function Donut({ parts, size = 120, center, label }: { parts: { label: string; value: number; tone: Tone }[]; size?: number; center?: string; label: string }) {
  const mounted = useMounted();
  const total = parts.reduce((n, p) => n + p.value, 0);
  const r = 40;
  const c = 2 * Math.PI * r;
  let acc = 0;
  return (
    <div className="gauge" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" width={size} height={size} role="img" aria-label={`${label}: ${parts.map((p) => `${p.label} ${p.value}`).join(', ')}`}>
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--zy-chart-track)" strokeWidth="12" />
        {total > 0 &&
          parts.map((p) => {
            const len = (p.value / total) * c;
            const off = acc;
            acc += len;
            if (p.value === 0) return null;
            return (
              <circle
                key={p.label}
                className="donut-seg"
                cx="50"
                cy="50"
                r={r}
                fill="none"
                stroke={toneVar[p.tone]}
                strokeWidth="12"
                style={{ strokeDasharray: `${mounted ? Math.max(0, len - 2) : 0} ${c}`, strokeDashoffset: -off }}
                transform="rotate(-90 50 50)"
              />
            );
          })}
      </svg>
      {center && (
        <div className="gauge-center" aria-hidden>
          <strong>{center}</strong>
        </div>
      )}
    </div>
  );
}
