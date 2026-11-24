// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { SnapshotSummary } from '../../api/client';

const fmt = (iso: string) => new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

/** Timeline rail of recovery points, spaced by real time. Oldest on the left. */
export function SnapshotRail({ items, selectedId }: { items: SnapshotSummary[]; selectedId?: string }) {
  if (items.length === 0) return null;
  const w = 560;
  const pad = 22;
  const t0 = +new Date(items[0].createdAt);
  const t1 = +new Date(items[items.length - 1].createdAt);
  const span = t1 - t0 || 1;
  const x = (iso: string) => (items.length === 1 ? w / 2 : pad + ((+new Date(iso) - t0) / span) * (w - pad * 2));
  const summary = `Recovery point timeline: ${items.length} point${items.length === 1 ? '' : 's'}, from ${fmt(items[0].createdAt)} to ${fmt(items[items.length - 1].createdAt)}`;
  return (
    <svg className="rail" viewBox={`0 0 ${w} 74`} width="100%" role="img" aria-label={summary}>
      <line x1={pad} x2={w - pad} y1="30" y2="30" stroke="var(--zy-hairline)" strokeWidth="3" strokeLinecap="round" />
      <rect className="rail-now" x={x(items[0].createdAt)} y="28.5" width={Math.max(0, x(items[items.length - 1].createdAt) - x(items[0].createdAt))} height="3" rx="1.5" fill="url(#hv-accent)" />
      {items.map((it, i) => {
        const active = it.id === selectedId;
        const cx = x(it.createdAt);
        return (
          <g key={it.id} className="rail-dot" style={{ animationDelay: `${i * 70}ms` }}>
            {active && <circle cx={cx} cy="30" r="13" fill="var(--zy-tint)" />}
            <circle cx={cx} cy="30" r={active ? 7 : 6} fill="var(--zy-surface)" stroke={active ? 'var(--zy-500)' : 'var(--zy-chart-5)'} strokeWidth="3" />
            <text x={cx} y="58" textAnchor="middle" className="chart-text" fill="var(--zy-slate)">{fmt(it.createdAt)}</text>
          </g>
        );
      })}
    </svg>
  );
}
