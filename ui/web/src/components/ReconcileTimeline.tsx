// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { PlaneCondition } from '../api/client';

function StepGlyph({ kind }: { kind: 'ok' | 'pending' | 'warn' }) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {kind === 'ok' && <path d="m6 12.5 4 4 8-9" />}
      {kind === 'pending' && <circle cx="12" cy="12" r="5" strokeDasharray="2.5 3.5" />}
      {kind === 'warn' && <path d="M12 6.5v7M12 17.4v.1" />}
    </svg>
  );
}

const defaultSteps = [
  { id: 'database', label: 'PostgreSQL', sub: 'cluster health', type: 'DatabaseReady' },
  { id: 'identity', label: 'Identity server', sub: 'instances ready', type: 'IdentityProviderReady' },
  { id: 'certs', label: 'Certificates', sub: 'TLS valid', type: 'CertificateReady' },
  { id: 'backup', label: 'Backups', sub: 'schedule configured', type: 'BackupConfigured' },
];

type Props = {
  conditions?: PlaneCondition[];
  phase?: string;
};

function condMap(conditions?: PlaneCondition[]) {
  const m = new Map<string, PlaneCondition>();
  conditions?.forEach((c) => m.set(c.type, c));
  return m;
}

export function ReconcileTimeline({ conditions, phase }: Props) {
  const map = condMap(conditions);
  const allDone = phase === 'Ready';
  const live = (conditions?.length ?? 0) > 0;

  return (
    <div className="timeline-panel">
      <div className="timeline-header">
        <div className="timeline-title">Reconcile Timeline</div>
        <div className="timeline-live">
          <span className={`timeline-live-dot ${live ? '' : 'timeline-live-dot--idle'}`} />
          {live
            ? allDone
              ? `Live · ${phase}`
              : `Reconciling · ${phase ?? 'Pending'}`
            : 'Awaiting controller status'}
        </div>
      </div>
      <div className="timeline-steps">
        {defaultSteps.map((step, i) => {
          const c = map.get(step.type);
          const ok = c?.status === 'True';
          const pending = !c;
          return (
            <div key={step.id} style={{ display: 'contents' }}>
              <div className={`timeline-step ${pending ? 'timeline-step--pending' : ''}`}>
                <div className={`timeline-step-icon ${ok ? 'ok' : pending ? 'pending' : 'warn'}`}>
                  <StepGlyph kind={ok ? 'ok' : pending ? 'pending' : 'warn'} />
                  <span className="sr-only">{ok ? 'Ready' : pending ? 'Pending' : 'Needs attention'}</span>
                </div>
                <div className="timeline-step-label">
                  <strong>{step.label}</strong>
                  <br />
                  {c?.message || step.sub}
                </div>
              </div>
              {i < defaultSteps.length - 1 && (
                <div className="timeline-connector" aria-hidden />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
