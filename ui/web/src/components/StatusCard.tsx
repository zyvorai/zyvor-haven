// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

type Props = {
  label: string;
  value: string;
  meta: string;
  ok?: boolean;
  icon?: string;
  variant?: 'live' | 'mock' | 'default';
};

export function StatusCard({ label, value, meta, ok, icon, variant = 'default' }: Props) {
  const cardClass = [
    'status-card',
    variant === 'live' ? 'status-card--live' : '',
    variant === 'mock' ? 'status-card--mock' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div className={cardClass}>
      <div className="status-card-header">
        <div className="status-card-label">{label}</div>
        {icon && <span className="status-card-icon" aria-hidden>{icon}</span>}
      </div>
      {variant === 'live' && (
        <span className="status-card-badge status-card-badge--live">Live</span>
      )}
      {variant === 'mock' && (
        <span className="status-card-badge">Preview</span>
      )}
      <div className={`status-card-value ${ok ? 'ok' : ''}`}>{value}</div>
      <div className="status-card-meta">{meta}</div>
    </div>
  );
}
