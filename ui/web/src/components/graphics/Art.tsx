// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { ReactNode } from 'react';

/** Shared SVG gradients. Rendered once at the app root; icons and art reference them by id. */
export function GraphicDefs() {
  return (
    <svg width="0" height="0" focusable="false" aria-hidden="true" style={{ position: 'absolute' }}>
      <defs>
        <linearGradient id="hv-accent" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" style={{ stopColor: 'var(--zy-grad-1)' }} />
          <stop offset="0.55" style={{ stopColor: 'var(--zy-grad-2)' }} />
          <stop offset="1" style={{ stopColor: 'var(--zy-grad-3)' }} />
        </linearGradient>
      </defs>
    </svg>
  );
}

/** Animated gradient-mesh backdrop. Transform and opacity only; decorative. */
export function Mesh({ subtle }: { subtle?: boolean }) {
  return (
    <div className={`mesh${subtle ? ' mesh--subtle' : ''}`} aria-hidden>
      <span className="mesh-blob mesh-a" />
      <span className="mesh-blob mesh-b" />
      <span className="mesh-blob mesh-c" />
      <span className="mesh-blob mesh-d" />
    </div>
  );
}

export type ArtName = 'plane' | 'key' | 'hub' | 'shield' | 'clock' | 'people' | 'offline' | 'apps' | 'realm';

function Frame({ children, size }: { children: ReactNode; size: number }) {
  return (
    <svg className="art" viewBox="0 0 160 120" width={size} height={(size * 120) / 160} aria-hidden focusable="false" fill="none" strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="80" cy="62" rx="62" ry="46" fill="url(#hv-accent)" opacity="0.14" />
      <ellipse cx="80" cy="108" rx="42" ry="5" fill="var(--zy-ink)" opacity="0.06" />
      {children}
    </svg>
  );
}

const card = { fill: 'var(--zy-surface)', stroke: 'var(--zy-hairline)', strokeWidth: 1.5 } as const;
const line = { stroke: 'var(--zy-slate)', strokeWidth: 2 } as const;
const acc = { stroke: 'url(#hv-accent)', strokeWidth: 2.5 } as const;

/** Friendly illustrations for empty and error states, drawn inline so they theme. */
export function Art({ name, size = 160 }: { name: ArtName; size?: number }) {
  switch (name) {
    case 'plane':
      return (
        <Frame size={size}>
          <rect x="38" y="68" width="84" height="22" rx="8" {...card} />
          <rect x="30" y="48" width="100" height="22" rx="8" {...card} />
          <rect x="44" y="28" width="72" height="22" rx="8" fill="var(--zy-surface)" stroke="url(#hv-accent)" strokeWidth="2" strokeDasharray="5 5" />
          <circle cx="44" cy="59" r="3" fill="var(--zy-chart-2)" />
          <circle cx="54" cy="59" r="3" fill="var(--zy-chart-track)" />
          <circle cx="48" cy="79" r="3" fill="var(--zy-chart-1)" />
          <path d="M80 34v10M75 39h10" {...acc} />
        </Frame>
      );
    case 'key':
      return (
        <Frame size={size}>
          <circle cx="62" cy="58" r="26" {...card} />
          <circle cx="62" cy="58" r="10" {...acc} />
          <path d="M88 58h34M110 58v12M120 58v8" {...line} />
          <path className="art-orbit" d="M40 30a38 38 0 0 1 44 -4" {...acc} opacity="0.7" />
          <circle cx="62" cy="58" r="3" fill="var(--zy-chart-1)" />
        </Frame>
      );
    case 'hub':
      return (
        <Frame size={size}>
          <path d="M80 60 36 34M80 60l46-26M80 60 30 84M80 60l52 22M80 60v38" stroke="var(--zy-hairline)" strokeWidth="2" strokeDasharray="3 5" />
          <circle cx="80" cy="60" r="17" fill="var(--zy-surface)" stroke="url(#hv-accent)" strokeWidth="2.5" />
          <path d="M80 52l7 3v6c0 4-3 7-7 8-4-1-7-4-7-8v-6l7-3Z" stroke="url(#hv-accent)" strokeWidth="2" />
          <circle cx="36" cy="34" r="9" {...card} />
          <circle cx="126" cy="34" r="9" {...card} />
          <circle cx="30" cy="84" r="9" {...card} />
          <circle cx="132" cy="82" r="9" {...card} />
          <circle cx="80" cy="98" r="9" {...card} />
          <circle cx="36" cy="34" r="3.5" fill="var(--zy-chart-1)" />
          <circle cx="126" cy="34" r="3.5" fill="var(--zy-chart-5)" />
          <circle cx="30" cy="84" r="3.5" fill="var(--zy-chart-6)" />
          <circle cx="132" cy="82" r="3.5" fill="var(--zy-chart-3)" />
          <circle cx="80" cy="98" r="3.5" fill="var(--zy-chart-2)" />
        </Frame>
      );
    case 'shield':
      return (
        <Frame size={size}>
          <path d="M80 18 116 32v28c0 22-14 38-36 46-22-8-36-24-36-46V32l36-14Z" {...card} />
          <path d="M80 28l26 10v22c0 15-10 27-26 33-16-6-26-18-26-33V38l26-10Z" fill="url(#hv-accent)" opacity="0.14" />
          <path d="m66 62 10 10 20-22" {...acc} strokeWidth="4" />
        </Frame>
      );
    case 'clock':
      return (
        <Frame size={size}>
          <circle cx="80" cy="58" r="34" {...card} />
          <circle cx="80" cy="58" r="34" stroke="url(#hv-accent)" strokeWidth="2.5" strokeDasharray="150 64" transform="rotate(-90 80 58)" />
          <path d="M80 40v18l12 8" {...line} />
          <path d="M26 100h108" stroke="var(--zy-hairline)" strokeWidth="2" />
          <circle cx="42" cy="100" r="4" fill="var(--zy-chart-track)" stroke="var(--zy-hairline)" />
          <circle cx="80" cy="100" r="4" fill="var(--zy-chart-5)" />
          <circle cx="118" cy="100" r="4" fill="var(--zy-chart-1)" />
        </Frame>
      );
    case 'people':
      return (
        <Frame size={size}>
          <circle cx="56" cy="50" r="14" {...card} />
          <path d="M34 90c2-14 12-20 22-20s20 6 22 20" {...card} />
          <circle cx="104" cy="50" r="14" {...card} />
          <path d="M82 90c2-14 12-20 22-20s20 6 22 20" {...card} />
          <circle cx="80" cy="36" r="9" fill="var(--zy-surface)" stroke="url(#hv-accent)" strokeWidth="2.5" />
          <path d="m75.5 36 3 3 6-6.5" {...acc} />
        </Frame>
      );
    case 'offline':
      return (
        <Frame size={size}>
          <path d="M52 78a18 18 0 0 1 2-35 24 24 0 0 1 46 6 15 15 0 0 1 2 29Z" {...card} />
          <path d="M80 52v14" stroke="var(--zy-chart-4)" strokeWidth="3.5" />
          <circle cx="80" cy="74" r="2.5" fill="var(--zy-chart-4)" />
          <path d="M60 94l10-8M100 94l-10-8" stroke="var(--zy-hairline)" strokeWidth="2.5" />
        </Frame>
      );
    case 'apps':
      return (
        <Frame size={size}>
          <rect x="32" y="26" width="96" height="66" rx="12" {...card} />
          <path d="M32 44h96" stroke="var(--zy-hairline)" strokeWidth="1.5" />
          <circle cx="44" cy="35" r="2.5" fill="var(--zy-chart-4)" />
          <circle cx="53" cy="35" r="2.5" fill="var(--zy-chart-3)" />
          <circle cx="62" cy="35" r="2.5" fill="var(--zy-chart-2)" />
          <rect x="44" y="54" width="32" height="28" rx="8" fill="url(#hv-accent)" opacity="0.2" />
          <path d="M84 60h30M84 70h22" stroke="var(--zy-hairline)" strokeWidth="3" />
          <circle cx="60" cy="68" r="6" {...acc} />
        </Frame>
      );
    default:
      return (
        <Frame size={size}>
          <path d="M80 20 118 40v40L80 100 42 80V40l38-20Z" {...card} />
          <path d="M80 36 104 48v24L80 84 56 72V48l24-12Z" fill="url(#hv-accent)" opacity="0.18" />
          <circle cx="80" cy="60" r="9" {...acc} />
        </Frame>
      );
  }
}

type EmptyProps = {
  art: ArtName;
  title: string;
  body?: ReactNode;
  actions?: ReactNode;
  tone?: 'default' | 'error';
  compact?: boolean;
  role?: 'status' | 'alert';
};

/** Illustrated empty or error state. */
export function EmptyState({ art, title, body, actions, tone = 'default', compact, role }: EmptyProps) {
  return (
    <div className={`empty-state${tone === 'error' ? ' empty-state--error' : ''}${compact ? ' empty-state--compact' : ''}`} role={role}>
      <Mesh subtle />
      <Art name={art} size={compact ? 120 : 168} />
      <h3 className="empty-state-title">{title}</h3>
      {body && <p className="empty-state-body">{body}</p>}
      {actions && <div className="empty-state-actions">{actions}</div>}
    </div>
  );
}

/** Skeleton placeholder. Includes a visually hidden label for assistive tech. */
export function Skeleton({ w, h = 14, r, className = '' }: { w?: number | string; h?: number | string; r?: number | string; className?: string }) {
  return <span className={`skeleton ${className}`} style={{ width: w, height: h, borderRadius: r }} aria-hidden />;
}

export function SkeletonBlock({ label, rows = 3, card }: { label: string; rows?: number; card?: boolean }) {
  return (
    <div className={`skeleton-block${card ? ' skeleton-card' : ''}`} role="status" aria-busy="true">
      <span className="sr-only">{label}</span>
      <Skeleton w="38%" h={12} />
      <Skeleton w="62%" h={26} r={8} />
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} w={`${92 - i * 14}%`} h={12} />
      ))}
    </div>
  );
}
