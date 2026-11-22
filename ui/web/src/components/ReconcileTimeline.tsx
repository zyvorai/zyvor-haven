// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { PlaneCondition } from '../api/client';

const defaultSteps = [
  { id: 'database', label: 'PostgreSQL', sub: 'cluster health', type: 'DatabaseReady' },
  { id: 'keycloak', label: 'Keycloak', sub: 'instances ready', type: 'KeycloakReady' },
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
                  {ok ? '✓' : pending ? '○' : '!'}
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
