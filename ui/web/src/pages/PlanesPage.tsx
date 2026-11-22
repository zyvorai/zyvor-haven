// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { api, type PlaneStatus } from '../api/client';

type PlaneRow = {
  name: string;
  namespace: string;
  phase: string;
  profile: string;
  hostname: string;
  ok: boolean;
  meta: string;
};

export function PlanesPage() {
  const [plane, setPlane] = useState<PlaneStatus | null>(null);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api
      .planeStatus()
      .then(setPlane)
      .catch((e) => setErr(e.message))
      .finally(() => setLoading(false));
  }, []);

  const rows: PlaneRow[] = plane
    ? [
        {
          name: plane.plane || 'platform',
          namespace: plane.namespace || 'identity',
          phase: plane.phase || plane.phaseCard?.value || 'Unknown',
          profile: 'dev',
          hostname: plane.message?.includes('not') ? '—' : 'auth (external)',
          ok: !!plane.phaseCard?.ok || plane.phase === 'Ready',
          meta: plane.phaseCard?.meta || plane.postgres?.meta || '',
        },
      ]
    : [];

  return (
    <ConsoleLayout>
      <div className="console-content">
        <div className="console-content-inner">
          <ConsolePageHeader
            eyebrow="Fleet"
            title="Planes"
            subtitle="IdentityPlane instances — health, profile, and endpoints."
            actions={
              <Link to="/deploy" className="btn btn-primary">
                + Deploy plane
              </Link>
            }
          />

          {err && <p style={{ color: 'var(--zy-danger)' }}>{err}</p>}
          {loading ? (
            <p style={{ color: 'var(--zy-muted)' }}>Loading planes…</p>
          ) : rows.length === 0 ? (
            <div className="card empty-card">
              <h3>No IdentityPlane yet</h3>
              <p>Deploy a plane or connect Keycloak in Settings to start operating.</p>
              <div className="btn-row" style={{ marginTop: 16 }}>
                <Link to="/deploy" className="btn btn-primary">
                  Deploy wizard
                </Link>
                <Link to="/settings?focus=keycloak" className="btn btn-ghost">
                  Settings
                </Link>
              </div>
            </div>
          ) : (
            <div className="planes-grid">
              {rows.map((p) => (
                <article key={`${p.namespace}/${p.name}`} className="plane-card">
                  <div className="plane-card-top">
                    <div>
                      <div className="plane-card-name">{p.name}</div>
                      <div className="plane-card-ns">{p.namespace}</div>
                    </div>
                    <span className={`plane-phase ${p.ok ? 'ok' : 'warn'}`}>{p.phase}</span>
                  </div>
                  <dl className="plane-meta">
                    <div>
                      <dt>Profile</dt>
                      <dd>{p.profile}</dd>
                    </div>
                    <div>
                      <dt>Postgres</dt>
                      <dd>{plane?.postgres?.value ?? '—'}</dd>
                    </div>
                    <div>
                      <dt>Certificate</dt>
                      <dd>{plane?.certificate?.value ?? '—'}</dd>
                    </div>
                  </dl>
                  <p className="plane-card-desc">{p.meta}</p>
                  <div className="plane-card-actions">
                    <Link to="/deck" className="btn btn-primary" style={{ padding: '8px 14px', fontSize: 13 }}>
                      Open Command Deck
                    </Link>
                    <Link to="/atlas" className="btn btn-ghost" style={{ padding: '8px 14px', fontSize: 13 }}>
                      View Atlas
                    </Link>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>
      </div>
    </ConsoleLayout>
  );
}
